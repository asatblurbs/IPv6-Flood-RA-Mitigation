

import sys
from scapy import *

import os

from Logger import *
from ipv6Pkt import *

class reAct:
    def __init__(self,iface):
        self.iface = iface
        self.Log = Logger("guard.log",iface)
        self.ipv6 = ipv6Pkt

    def generalReaction(self,packet):
        #Just log source ip address 
        content = "General reaction "
        self.Log.writeLog(packet.src,content,"")


    def reAction(self,packet,defen):
        if defen == "resetRA":
            self.resetRA(packet)

        elif defen == "blockIP":
            self.blockIP(packet)

        elif defen == "resetRouter":
            self.setRouter(packet)
        else:
            self.Log.writeLog(packet.src,"Doesn't have any defense mechanism  with "+defen,"")

    def resetRA(self,packet):
        content = "Send another packet with routerlifetime = 0 to delete cache entry of this attacker's packet"
        comment = ""
        send(IPv6(src=packet[IPv6].src)/ICMPv6ND_RA(routerlifetime=0) )
        self.Log.writeLog(packet.src,content,comment)
        self.Log.writeRea("Reaction : Reset routerlifetime = 0")

    def setRouter(self,packet):
        content = "Send a packet reset routerlifetime of trusted router "
        comment= ""
        sendp((IPv6(src=packet[IPv6].src)/ICMPv6ND_RA(routerlifetime=1800) ))
        self.Log.writeLog(packet.src,contnet,comment)
        self.Log.writeRea("Reaction : Reset Genuine Router ")



    def blockIP(self,packet):
        content = "Maybe* using IPtables to block source address from sending invalid packet"
        comment = "Need to check"
#        os.system("ip6tables -A icmpv6-filter --source"+ address + "-p icmp    v6   -j DROP")
        self.Log.writeLog(packet.src,content,comment)      



    def unBlockIP(self,packet):
        content = "Maybe* using IPtables to block source address from sending invalid packet"
        comment = "Need to check"
#       os.system("ip6tables -D icmpv6-filter --source"+ address + "-p icmp    v6   -j DROP")
        self.Log.writeLog(packet.src,content,comment)

    def cleanInet6(self,addr,iface):
        os.system("/sbin/ifconfig "+iface+" inet6 del "+addr+"/64")
        self.Log.writeLog(addr,"Delete from ipv6 address of interface "+iface,"")
        self.Log.writeRea("Reaction : Delete invalid "+addr)
