import sys
from scapy.all import *

class ipv6Pkt:
    EthHdr = {'LLSrcAddr': None, 'LLDstAddr': None, 'Interface': None}
    IPHdr = {'SrcIPAddr': None, 'DstIPAddr': None}
    ExtHdr = [['','','','']]
    indize = 0
    RAconf = {'Prefix':'fd00:141:64:1::','Prefixlen':'64','RA_LLSrcAddr':'', 'M': False, 'O': False, 'RouterLifeTime':'1800', 'CHLim': '255'}
    NSconf = {'NS_LLSrcAddr': ':::::'}
    NAconf = {'NA_tgtAddr': '::', 'R' : True, 'S' : False, 'O' : True}
    ICMP = {'indize': 0, 'Code': '1', 'Type': '0', 'Message': ''}
    PTB = {'MTU': '1280'}
    TCP_UDP = {'SrcPort': '20', 'DstPort': '80', 'Flags': 2}
    Payload = {'indizeP': 0, 'Payloadlen': '1', 'PayloadString': 'X', 'Capture File': '', 'Packet No.': '1'}
 
class GetIPv6Addr:
    def __init__(self):
        query = Ether()/IPv6(dst='ff02::1',hlim=1)/IPv6ExtHdrHopByHop(autopad=0,nh=58)/ICMPv6MLQuery()
        query[2].options='\x05\x02\x00\x00\x00\x00'
        sendp(query)
        ans=sniff(filter='ip6[48]=131', timeout=10)
        addresses={}
        request = Ether()/IPv6(dst='ff02::1')/ICMPv6EchoRequest()
        ans2 = srp(request, multi = 1, timeout = 10)
        if ans != None:
            for packet in ans:
                macSrc = packet[Ether].src
                addresses[macSrc] = packet[IPv6].src
        if ans2 != None:
            for packet in ans2[0]:
                macSrc = packet[1][Ether].src
                addresses[macSrc] = packet[1][IPv6].src
        self.uniqueAddr = addresses

        
    def getAddr(self):
        print self.uniqueAddr


class createPkt:
  
    def __init__(self,ipv6Pkt):

        self.IPv6 = ipv6Pkt
        self.IPv6packet = {'EthHeader':None,'IPHeader':None,
                           'ExtHeader':None,'NextHeader':None}
        self.IPv6Scapy = None

        ##################
        ## Ethernet Header

        self.IPv6packet['EthHeader'] = Ether(dst=self.IPv6.EthHdr['LLDstAddr'],
                                             src=self.IPv6.EthHdr['LLSrcAddr'])

        ##############
        ## IPv6 Header

        self.IPv6packet['IPHeader'] = IPv6(dst=self.IPv6.IPHdr['DstIPAddr'],
                                           src=self.IPv6.IPHdr['SrcIPAddr'])

        ############################
        ## add extension header if set

        self.NumExtHdr = len(self.IPv6.ExtHdr)
    
        
        if self.NumExtHdr > 1:
            self.IPv6packet['ExtHeader'] = self.BuildExtHdr(self.NumExtHdr - 1)
        else:
            self.IPv6packet['ExtHeader'] = None

        ########################
        ## add next header

        self.IPv6packet['NextHeader'] = self.BuildNextHeader()

        ############
        ## get iface

        if self.IPv6.EthHdr['Interface'] != '':
            Interface = str(self.IPv6.EthHdr['Interface'])
        else:
            Interface = None

        if self.IPv6packet['ExtHeader'] == None and self.IPv6packet['NextHeader'] != None:
            self.IPv6Scapy=(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['NextHeader'])
        elif self.IPv6packet['ExtHeader'] == (None or '') and self.IPv6packet['NextHeader'] == None:
            self.IPv6Scapy=(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader'])
        elif self.IPv6packet['ExtHeader'] != (None or '') and self.IPv6packet['NextHeader'] != None:
            self.IPv6Scapy=(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['ExtHeader']/self.IPv6packet['NextHeader'])
        elif self.IPv6packet['ExtHeader'] != (None or '') and self.IPv6packet['NextHeader'] == None:
            self.IPv6Scapy=(self.IPv6packet['EthHeader']/self.IPv6packet['IPHeader']/self.IPv6packet['ExtHeader'])
        sendp(self.IPv6Scapy, iface = Interface)



    ###############
    ## Build Extension Header

    def  BuildExtHdr(self, Num):
        ExtensionHeader = ''
        for d in range(Num):
            if self.IPv6.ExtHdr[d][0] == 'Hop By Hop Options':
                if d == 0:
                    ExtensionHeader = IPv6ExtHdrHopByHop()
                else:
                    ExtensionHeader = ExtensionHeader/IPv6ExtHdrHopByHop()
            elif self.IPv6.ExtHdr[d][0] == 'Destination Options':
                if d == 0:
                    ExtensionHeader = IPv6ExtHdrDestOpt()
                else:
                    ExtensionHeader = ExtensionHeader/IPv6ExtHdrDestOpt()
            elif self.IPv6.ExtHdr[d][0] == 'Routing':
                i = len(self.IPv6.ExtHdr[d][1])
                if d == 0:
                    ExtensionHeader = IPv6ExtHdrRouting(addresses = self.IPv6.ExtHdr[d][1])
                else:
                    ExtensionHeader = ExtensionHeader/IPv6ExtHdrRouting(addresses = self.IPv6.ExtHdr[d][1])
            elif self.IPv6.ExtHdr[d][0] == 'Fragmentation':
                if self.IPv6.ExtHdr[d][3] == 0:
                    self.M_Flag = '0'
                    if d == 0:
                        ExtensionHeader = IPv6ExtHdrFragment(m = self.IPv6.ExtHdr[d][3], offset = int(self.IPv6.ExtHdr[d][1]), id = int(self.IPv6.ExtHdr[d][2]))
                    else:
                        ExtensionHeader = ExtensionHeader/IPv6ExtHdrFragment(m = 0, offset = int(self.IPv6.ExtHdr[d][1]), id = int(self.IPv6.ExtHdr[d][2]))
                else:
                    self.M_Flag = '1'
                    if d == 0:
                        ExtensionHeader = IPv6ExtHdrFragment(m = self.IPv6.ExtHdr[d][3], offset = int(self.IPv6.ExtHdr[d][1]), id = int(self.IPv6.ExtHdr[d][2]))
                    else:
                        ExtensionHeader = ExtensionHeader/IPv6ExtHdrFragment(m = 1, offset = int(self.IPv6.ExtHdr[d][1]), id = int(self.IPv6.ExtHdr[d][2]))
        return(ExtensionHeader)

    ###############
    ## Build Next Header

    def BuildNextHeader(self):
        NextHeader = self.BuildICMPv6_Ping()
        if self.IPv6.indize == 0:               # ICMP
            if self.IPv6.ICMP['indize'] == 0:        # Ping
                NextHeader = self.BuildICMPv6_Ping()
            elif self.IPv6.ICMP['indize'] == 1:      # Router Advetisement
                NextHeader = self.BuildICMPv6_RA()
            elif self.IPv6.ICMP['indize'] == 2:      # Router Solicitation
                NextHeader = self.BuildICMPv6_RS()
            elif self.IPv6.ICMP['indize'] == 3:      # Neighbor Advetisement
                NextHeader = self.BuildICMPv6_NA()
            elif self.IPv6.ICMP['indize'] == 4:      # Neighbor Solicitation
                NextHeader = self.BuildICMPv6_NS()
            elif self.IPv6.ICMP['indize'] == 5:      # Packet Too Big
                NextHeader = self.BuildICMPv6_PacketTooBig()
            elif self.IPv6.ICMP['indize'] == 6:      # ICMP Unknown
                NextHeader = self.BuildICMPv6_Unknown()
        elif self.IPv6.indize == 1:             # TCP
            NextHeader = self.BuildTCP()
        elif self.IPv6.indize == 2:             # UDP
            NextHeader = self.BuildUDP()
        elif self.IPv6.indize == 3:             # No Next Header
            NextHeader = self.BuildNoNextHeader()
        else:
            print "Not yet implemented"
        return(NextHeader)

    ## Echo Request

    def BuildICMPv6_Ping(self):
        return(ICMPv6EchoRequest())

    ## Router Solicitation

    def BuildICMPv6_RS(self):
        rs = ICMPv6ND_RS()
        return(rs)

    ## Router Advertisement

    def BuildICMPv6_RA(self):

        if self.IPv6.RAconf['M'] == True: MFlag = 1
        else: MFlag = 0
        if self.IPv6.RAconf['O'] == True: OFlag = 1
        else: OFlag = 0
        ra=ICMPv6ND_RA(chlim=int(self.IPv6.RAconf['CHLim']), H=0L, M=MFlag, O=OFlag,
                       routerlifetime=int(self.IPv6.RAconf['RouterLifeTime']), P=0L, retranstimer=0, prf=0L,
                       res=0L)

        prefix_info=ICMPv6NDOptPrefixInfo(A=1L, res2=0, res1=0L, L=1L,
                                          len=4,
                                          prefix=str(self.IPv6.RAconf['Prefix']),
                                          R=0L, validlifetime=1814400,
                                          prefixlen=int(self.IPv6.RAconf['Prefixlen']),
                                          preferredlifetime=604800, type=3)

        ## if source link-layer-addr set

        if (self.IPv6.RAconf['RA_LLSrcAddr'] != (None or '')):
            llad=ICMPv6NDOptSrcLLAddr(type=1, len=1,
                                      lladdr=str(self.IPv6.RAconf['RA_LLSrcAddr']))
            return(ra/prefix_info/llad)
        else:
            return(ra/prefix_info)

    ## Neighbor Solicitation

    def BuildICMPv6_NS(self):

        ns = ICMPv6ND_NS(tgt=str(self.IPv6.NSconf['NS_LLSrcAddr']))
        return(ns)

    ## Neighbor Advertisment

    def BuildICMPv6_NA(self):

        if self.IPv6.NAconf['R'] == True: RFlag = 1
        else: RFlag = 0
        if self.IPv6.NAconf['S'] == True: SFlag = 1
        else: SFlag = 0
        if self.IPv6.NAconf['O'] == True: OFlag = 1
        else: OFlag = 0
        na = ICMPv6ND_NA(tgt=str(self.IPv6.NAconf['NA_tgtAddr']), R = RFlag, S = SFlag, O = OFlag)
        return(na)

    ## Packet Too Big

    def BuildICMPv6_PacketTooBig(self):

        if self.IPv6.PTB['MTU'] != '':
            MTU = self.IPv6.PTB['MTU']
        else:
            MTU = None
        q = ICMPv6PacketTooBig(mtu=int(MTU))

        if self.IPv6.Payload['Capture File'] != '':
            path = self.IPv6.Payload['Capture File']
            capture = rdpcap(str(path))
            enPCAPno = self.PayloadFile['Packet No.']
            if self.IPv6.Payload['Packet No.'] != '':
                no = int(self.IPv6.Payload['Packet No.'])-1
            else:
                no = 0
            q = q/capture[no][IPv6]
        return(q)

    ## ICMP Unknown

    def BuildICMPv6_Unknown(self):

        q = ICMPv6Unknown(type=int(self.IPv6.ICMP['Type']), code=int(self.IPv6.ICMP['Code']), msgbody=self.IPv6.ICMP['Message'])
        return(q)

    ## TCP

    def BuildTCP(self):
        SPort=int(self.IPv6.TCP_UDP['SrcPort'])
        DPort=int(self.IPv6.TCP_UDP['DstPort'])
        tcp= TCP(sport=SPort, dport=DPort, flags=self.IPv6.TCP_UDP['Flags'])
        tcp = self.BuildPayload(tcp)
        return(tcp)

    ## UDP

    def BuildUDP(self):
        SPort=int(self.IPv6.TCP_UDP['SrcPort'])
        DPort=int(self.IPv6.TCP_UDP['DstPort'])
        udp= UDP(sport=SPort, dport=DPort)
        udp = self.BuildPayload(udp)
        return(udp)

    ## No Next Header

    def BuildNoNextHeader(self):
        return(None)

    ## Payload

    def BuildPayload(self, x):
        if self.IPv6.Payload['indizeP'] == 3:
            return(x)
        elif self.IPv6.Payload['indizeP'] == 0:
            load = 'X'*int(self.IPv6.Payload['Payloadlen'])
            return(x/load)
        elif self.IPv6.Payload['indizeP'] == 1:
            load = str(self.IPv6.Payload['PayloadString'])
            return(x/load)
        elif self.IPv6.Payload['indizeP'] == 2:
            path = self.IPv6.Payload['Capture File']
            capture = rdpcap(str(path))
            PCAPno = self.IPv6.Payload['Packet No.']
            if PCAPno != '':
                no = int(PCAPno)-1
            else:
                no = 0
            load = capture[no][Raw]
            return(x/load)

