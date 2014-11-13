import os
import sys
import ConfigParser
from optparse import OptionParser
import io
from threading import *

from scapy.all import *
sys.path.append("./lib/")
sys.path.append("./log/")
sys.path.append("./factory/")
from v6Sig import *
from processPkt import *
from ipv6Pkt import *
from trustInfo import *
from Logger import *
from macManuf import *
from time import *


usage = "./%prog -i <interface> -c <config file>"
usage += "\nExample: ./%prog -i eth0 -c guard.cfg"

parser = OptionParser(usage=usage)

parser.add_option("-i", type="string",action="store", dest="iface",
                  help="Interface to activate Shield")

parser.add_option("-c", type="string", action="store", dest="cfgfile",
                    help="Configuration file")

parser.set_defaults(cfgfile="guard.cfg")

(options, args) = parser.parse_args()


class v6Shield:
    def __init__(self, iface, sigfile):
        self.iface = iface
        self.Sig = v6Sig(sigfile)
        macFile = self.Sig.macFile
        print "[+] Initialize mac and manufacturer database"
        self.macManuf = macManuf(macFile)
        self.finished=True
        self.trustInfo = trustInfo(iface,self.macManuf)
        print "[+] Gathering genuine network information..."
        print "[+] Gather Neighbor..."
        self.trustInfo.gatherNeighbor()
        print "[+] Gather Router..."
        self.trustInfo.gatherRouter()

        self.stime = time()
        
        self.processPkt = processPkt(self.iface,self.stime,self.Sig,self.trustInfo,self.macManuf)   



  
    def start(self):
        print "[====================]Shield activated at %s"%timer()
        print "[====================]Press Ctr-C to terminate"        
        self.run()
    def run(self):
        print "Sniff packet at "+self.iface+"\n"
        sniff(iface=self.iface, prn=self.process)

    def process(self, packet):
        #Neighbor Spoofing via Neighbor Discovery (ND) protocol
        #Flood RA packet to create fake router 
        if ICMPv6ND_RA  in packet:
	    #Router Advertisement packet comes, handle it
            #Handle packet with router life time = 0 to DOS
	    self.processPkt.process(packet,"fakeRA")
        
        #Process Neighbor Solicitation Packet 
        if ICMPv6ND_NS in packet:
            self.processPkt.process(packet,"floodNS")


        #Detect MITM attack via spoofed ICMPv6 Neighbor Advertisement
        if ICMPv6ND_NA in packet:
            self.processPkt.process(packet,"mitmNA")

        if DHCP6_Solicit in packet:
            self.processPkt.process(packet,"floodDHCP")

        #Detect a ping flood
        if ICMPv6EchoRequest in packet:
            self.processPkt.process(packet,"floodPing")
                

    


  
def banner():
    print "      ________ _________.__    .__       .__       .___"
    print "      /  _____//   _____/|  |__ |__| ____ |  |    __| _/"
    print "     /   __  \ \_____  \ |  |  \|  |/ __ \|  |   / __ | "
    print "     \  |__\  \/        \|   Y  \  \  ___/|  |__/ /_/ | "
    print "      \_____  /_______  /|___|  /__|\___  >____/\____ | "
    print "            \/        \/      \/        \/           \/ "

if len(sys.argv) < 2:
    banner()
    parser.print_help()
    sys.exit(1)

def timer():
    now = localtime(time())
    return asctime(now)  
  
def main():
    banner()
    shield = v6Shield(options.iface,options.cfgfile)
    shield.start()
    while os.path.exists('CAPTURE_RUNNING'):
        time.sleep(10)
    
if __name__=='__main__':
    main()
