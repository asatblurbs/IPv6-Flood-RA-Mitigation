import ipv6Pkt

ii = ipv6Pkt.ipv6Pkt


ii.indize = 0
ii.IPHdr['DstIPAddr'] = 'ff02::2'

ii.EthHdr['Interface'] = "eth0"

ii.ICMP['indize'] = 2
pkt = ipv6Pkt.createPkt(ii)

a = ipv6Pkt.GetIPv6Addr()

a.getAddr()




