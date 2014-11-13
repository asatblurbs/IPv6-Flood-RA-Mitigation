from scapy.all import *
from ipv6Pkt import *
from Logger import *

import os


conf.verb=0
class trustInfo:
    def __init__(self,iface,macManuf):
        self.iface = iface
        self.routerAddr = ''
        
        self.banIp = {}
        self.macManuf = macManuf
        #Counter for a packet from an ip
        self.pktPIp = {'ip' :['ra','ns','na','icmp']}

        self.trustIp = {}

        self.globalPkt = [0,0,0,0] #RA/NS/NA/ICMP
            
    def getRouter(self):
        #Another config file define some info from our network
        return self.routerAddr
        
    def getMac(self,ip):
        if ip in self.trustIp.keys():
            return self.trustIp[ip]
        return False



    #Gather all neighbor at current time, we assume it a genuine IP/MAC on our LAN
    def gatherNeighbor(self):
        #Local address
        ifaddr = in6_getifaddr()
        for ifa in ifaddr:
            if ifa[2] == self.iface and ifa[1] != 0: 
                ip = ifa[0]
                mac = in6_addrtomac(ip)
                self.trustIp[ip] = mac

        #Send multicast network to get Neighbor Advertisement
        query = Ether()/IPv6(dst='ff02::1',hlim=1)/IPv6ExtHdrHopByHop(autopad=0,nh=58)/ICMPv6MLQuery()
        query[2].options='\x05\x02\x00\x00\x00\x00'
        sendp(query,iface=self.iface)
        
        ipv6_lfilter = lambda (r): IPv6 in r
        ans=sniff(filter='ip6[48]=131', lfilter=ipv6_lfilter,timeout=10)
        self.readInfo()
        request = Ether()/IPv6(dst='ff02::1')/ICMPv6EchoRequest()
        ans2 = srp(request, multi = 1, timeout = 10)
        if ans != None:
            for packet in ans:
                macSrc = packet[Ether].src
                ipSrc = packet[IPv6].src
                if self.trustIp.has_key(ipSrc):
                    if macSrc != self.trustIp[ipSrc]:
                        print "Exist an IP with Mac address "+macSrc
                        if self.query_yes_no("Delete old mac address and replace it with new one  ","yes"):
                            self.trustIp[ipSrc] = macSrc
                else:
                    print "Got "+ipSrc +" / "+macSrc
                    if macSrc[:8] in self.macManuf.macDict.keys():
                        manuf = self.macManuf.macDict[macSrc[:8]]
                        print "Mac Manufacture : "+manuf
                    else:
                        print "Warning : Unknow manufacturer use this mac address "
                    if self.query_yes_no("Trusted ?","yes"):
                        self.trustIp[ipSrc] = macSrc

        if ans2 != None:
            for packet in ans2[0]:
                macSrc = packet[1][Ether].src
                ipSrc = packet[1][IPv6].src
                if self.trustIp.has_key(ipSrc):
                    if macSrc != self.trustIp[ipSrc]:
                        print "Exist an IP with Mac address "+macSrc
                        if self.query_yes_no("Delete old mac address and replace it with new one ","yes"):
                            self.trustIp[ipSrc] = macSrc


                else:
                    print "Got "+ipSrc +" / "+macSrc
                    if macSrc[:8] in self.macManuf.macDict.keys():
                        manuf = self.macManuf.macDict[macSrc[:8]]
                        print "Manufacture "+manuf
                    else:
                        print "Warning : Unknow manufacturer use this mac address "
                    if self.query_yes_no("Trusted ?","yes"):
                        self.trustIp[ipSrc] = macSrc

        print self.trustIp
        self.writeInfo()
        for m in self.trustIp.values():
            self.pktPIp[m] = [0,0,0,0]

    #Gather genuine ipv6 router on our network
    def gatherRouter(self):
        pkt = ipv6Pkt
        pkt.indize = 0
        pkt.IPHdr['DstIPAddr'] = 'ff02::2'
        pkt.EthHdr['Interface'] = self.iface
        pkt.ICMP['indize'] = 2
        ra_lfilter = lambda (r): IPv6 in r and ICMPv6ND_RA in r
        rsPkt = createPkt(pkt)
        ras = sniff(iface=self.iface, filter="ip6", lfilter = ra_lfilter, timeout = 10)
        if ras != None:
            for packet in ras:
                macSrc = packet[Ether].src
                ipSrc = packet[IPv6].src
                if self.query_yes_no("Received Router Advertisement from "+macSrc+" Accept it?","yes"):
                    self.routerAddr = macSrc
            

        print "No IPv6 Router on the Wire. "

    def writeInfo(self):
        ftemp = open("data/genuine.info","w")
        for ip in self.trustIp.keys():
            ftemp.write(ip+"\t"+str(self.trustIp[ip])+"\n")

        ftemp.close()

    def readInfo(self):
        if os.path.isfile("data/genuine.info"):
            ftemp = open("data/genuine.info","r")
            fcontent = ftemp.readlines()
            for line in fcontent:
                line = line.strip()
                line_ = line.split("\t")
                self.trustIp[line_[0]] = line_[1]

            
    def query_yes_no(self,question, default="yes"):
        valid = {"yes":True,   "y":True,  "ye":True, "no":False,     "n":False}
        if default == None:
            prompt = " [y/n] "
        elif default == "yes":
            prompt = " [Y/n] "
        elif default == "no":
            prompt = " [y/N] "
        else:
            raise ValueError("invalid default answer: '%s'" % default)

        while True:
            sys.stdout.write(question + prompt)
            choice = raw_input().lower()
            if default is not None and choice == '':
                return valid[default]
            elif choice in valid:
                return valid[choice]
            else:
                sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

