import sys
import math
from scapy.all import *
from trustInfo import *
from reAct import *
from Logger import *
from time import *
conf.verb=0
class processPkt:
    def __init__(self,iface,stime,sig,trustInfo,macManuf):
        self.iface = iface
        self.Log = Logger("guard.log",iface)
        self.trustInfo = trustInfo
        #Time start sniffing on the wire
        self.sTime = stime
        self.Sig = sig
        self.Rea = reAct(iface)
        self.macManuf = macManuf
        self.react = 0
        #Count number of packet per second to check if we got DOS attack
        self.pktRate  = 0
        self.globalRate = 0
        self.violate = 0
        self.ignore_new_ns = 1
        self.manuf = ""
        self.dmanuf = ""



    def writeFault(self,packet,atkType):
        if atkType == "fakeRA":
            self.Log.writeDetails("FAKE ROUTER ADVERTISMENT",packet.src,self.manuf,packet.dst,self.dmanuf,"fake_router6 | flood_router6")
            return
        if atkType == "fakeNA":
            self.Log.writeDetails("FAKE NEIGHBOR ADVERTISMENT",packet.src,self.manuf,packet.dst,self.dmanuf,"fake_advertise6")
            return
        if atkType == "floodNS":
            self.Log.writeDetails("FAKE NEIGHBOR SOLICITATION",packet.src,self.manuf,packet.dst,self.dmanuf,"parasite6")
            return

    def process(self,packet,atkType):
        self.manuf = self.macManuf.getManuf(packet.src)
        self.dmanuf =self.macManuf.getManuf(packet.dst)
        if packet[IPv6].src not in self.trustInfo.trustIp.keys() :
            if packet.src not in self.trustInfo.trustIp.values():
                if self.manuf == "Unknow":
                    print "Warning : No manufacturer use this mac address "+packet.src
                if self.ignore_new_ns:
                    self.writeFault(packet,atkType)
                    if packet.src not in self.trustInfo.pktPIp.keys():
                        self.trustInfo.pktPIp[packet.src] =[0,0,0,0]
            else:
                self.writeFault(packet,atkType)
        elif packet[IPv6].src not in self.trustInfo.trustIp.keys():
            self.writeFault(packet,atkType)

        elif packet.src != self.trustInfo.trustIp[packet[IPv6].src]:
            self.writeFault(packet,atkType)
            
        cTime = time()  
        

        if atkType == "fakeRA":
            self.trustInfo.pktPIp[packet.src][0] += 1            
            self.trustInfo.globalPkt[0] += 1
            self.pktRate = int(math.ceil(self.trustInfo.pktPIp[packet.src][0]/(cTime - self.sTime)))
            self.globalRate = int(math.ceil(self.trustInfo.globalPkt[0]/(cTime - self.sTime)))
            self.processFakeRA(packet)
            
        
        elif atkType == "floodNS":
            self.trustInfo.globalPkt[1] += 1
            self.globalRate = int(math.ceil(self.trustInfo.globalPkt[1]/(cTime - self.sTime)))
            self.trustInfo.pktPIp[packet.src][1] += 1
            self.pktRate = int(math.ceil(self.trustInfo.pktPIp[packet.src][1]/(cTime - self.sTime)))
            self.processFloodNS(packet)
          

        elif atkType == "mitmNA":
            self.trustInfo.globalPkt[2] += 1
            self.globalRate = int(math.ceil(self.trustInfo.globalPkt[2]/(cTime - self.sTime)))
            self.trustInfo.pktPIp[packet.src][2] += 1
            self.pktRate = int(math.ceil(self.trustInfo.pktPIp[packet.src][2]/(cTime - self.sTime)))
            self.processMitmNA(packet)
         

        elif atkType == "routerReset":
            self.processRouterReset(packet)
        
        elif atkType == "floodDHCP":
            self.processFloodDhcp(packet)


        elif atkType == "newAttack":
            self.handleNewAttack(packet)
       

        if atkType == "floodPing":
            self.trustInfo.globalPkt[3] += 1
            self.globalRate = int(math.ceil(self.trustInfo.globalPkt[3]/(cTime - self.sTime)))
            self.trustInfo.pktPIp[packet.src][3] += 1
            self.pktRate = int(math.ceil(self.trustInfo.pktPIp[packet.src][3]/(cTime - self.sTime)))
            self.processFloodPing(packet)
        
        if int(self.globalRate) > int(self.Sig.limitRate) :
            self.Log.writeLog(packet.src,"Warning : Packet Per Second is very high, possible an flood attack with rate:","current rate: "+str(self.globalRate), )
            self.violate += 1
            if self.violate < 10:
                self.Log.writeDetails("FLOOD PACKET",packet.src,self.manuf,packet.dst,self.dmanuf,"flood_advertise6")
            
            


    def processFakeRA(self,packet):
        cTime = time()
        #Check if this RA packet come from trusted Router we got at first start
        if packet.src != self.trustInfo.routerAddr:
            self.Log.writeLog(packet.src,"Detect fake Router Advertisement ","")
            self.Log.writeDetails("FAKE ROUTER ADVERTISMENT",packet.src,self.manuf,packet.dst,self.dmanuf,"fake_router6")
            self.react = 1
        
        
        if self.pktRate > self.Sig.raLimit:
            self.Log.writeLog(packet.src,"Detect Flood Packet with Rate",str(self.pktRate))
            self.Log.writeDetails("FLOOD ROUTER ADVERTISEMENT",packet.src,self.manuf,packet.dst,self.dmanuf,"flood_router6")
            self.react = 1

        
        elif packet[ICMPv6ND_RA].routerlifetime > self.Sig.routerLifetime:
            
            self.Log.writeLog(packet.src,"Router lifetime suspecious",str(self.pktRate))
            self.Log.writeDetails("ROUTER LIFETIME SUSPECIOUS",packet.src,self.manuf,packet.dst,self.dmanuf,"fake_router6")
            self.react = 1

        elif packet[ICMPv6ND_RA].routerlifetime == 0:
            self.Log.writeLog(packet.src,"Reset default router Attack",str(self.pktRate))
            self.Log.writeDetails("RESET ROUTER DEFAULT ATTACK",packet.src,self.manuf,packet.dst,self.dmanuf,"fake_router6 | kill_router6")
            self.react = 1

        
        if self.react:
            self.Rea.reAction(packet,"resetRA")
            #clean invalid inet6 address from system since it received fake router advertisement
            inet6Addr = in6_getifaddr()
            for item in inet6Addr:
                if item[2] ==  self.iface:
                    trustIp = self.trustInfo.trustIp.keys()[0]
                    #Check if it diffenrent from local address we gather in very first start
                    if item[1] == 0:
                        self.Rea.cleanInet6(item[0],self.iface)
            return

    def processFloodNS(self,packet):
        if self.pktRate > self.Sig.naLimit:
            self.Log.writeDetails("FLOOD NEIGHBOR SOLICITATION",packet.src,self.manuf,packet.dst,self.dmanuf,"flood_solicitate6")
            self.react =1

        if ICMPv6NDOptSrcLLAddr  in packet:
            if packet[ICMPv6NDOptSrcLLAddr].lladdr != packet.src:
                self.Log.writeDetails("FLOOD NEIGHBOR SOLICITATION",packet.src,self.manuf,packet.dst,self.dmanuf," rsmurf6 |  sendpees6")
                self.react = 1
        else:
            ip = packet[IPv6].src
            mac = packet[Ether].src
            #Get  mac address of this source ip and check with trusted Info we have
            candMac = self.trustInfo.getMac(ip)
            if candMac==0:
                #Doesn't have this entry in trust INFO, add it 
                if self.ignore_new_ns == 0:
                    self.Log.writeLog(mac,"Received net Address ","")
                    if self.trustInfo.query_yes_no("It a trusted IP/MAC ? ","yes"):
                        self.Log.writeLog(mac,"Added to trust Source","")
                        self.trustInfo.trustIp[ip] = mac                    
                    else:
                        if self.trustInfo.query_yes_no("Ignore all new IP ? ","yes"):
                            self.ignore_new_ns = 1
                        self.Log.writeLog(mac,"A sign of attack....","")
                else:
                    self.Log.writeLog(mac,"Attack Detection ...","")
                return
            else:
                if candMac == mac:
                    #A valid packet in trustInfo
                    self.react = 0
                else:
                    #Look like we have a suspecious packet with sample IP , need another method to validate who is trust....
                    self.Log.writeLog(packet.src," Man in the middle Attack  ","")
                    self.Log.writeDetails("IPV6 MITM ATTACK",packet.src,self.manuf,packet.dst,self.dmanuf,"fake_advertise6") 

        if self.react:
            self.Rea.reAction(packet,"floodNS")
            return

    #Same as flood NS, attacker cause fake entry in mac/ip table, it do via flood packet 
    
    def processMitmNA(self,packet):
        if self.pktRate > self.Sig.naLimit:
            self.Log.writeDetails("FLOOD NEIGHBOR ADVERTISEMENT",packet.src,self.manuf,packet.dst,self.dmanuf,"flood_advertise6")
            self.react = 1



    #Just warning about the attack when it occur
    def processFloodPing(self,packet):
        if self.pktRate > self.Sig.icmpLimit:
            self.Log.writeLog(packet.src,"Detect Flood ICMP Echo Packet ",str(self.pktRate))
            self.Log.writeDetails("FLOOD ICMP ECHO",packet.src,self.manuf,packet.dst,self.dmanuf,"smurf6")
            #Maybe ban this IP from Network but this give another attack vector ..
            return
    def processFloodDhcp(self,packet):
        if self.pktRate > self.Sig.naLimit:
            self.Log.writeDetails("FLOOD DHCP",packet.src,self.manuf,packet.dst,self.dmanuf,"flood_dhcp6")
