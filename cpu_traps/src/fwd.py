from scapy.all import *
import os

PCAP='/tmp/debug.pcap'

def p_action(p):

	ether=(Ether(dst='00:07:43:de:ad:be', src='00:1c:73:7b:f7:5c'))
	ip=IP(src='192.168.0.111', dst='192.168.0.18') 
	udp=UDP(sport=9999,dport=9999)

	p_encap = (ether/ip/udp)
	
	#save packet to a PCAP before encapsulation
	
	wrpcap(PCAP, p, append=True)

	#encapsulate and send
	p = (p_encap/p)
	#(p).display()
	sendp(p, iface='Ethernet20')


try:
	os.remove(PCAP)
except OSError:
	print 'Removing of %s file failed' % PCAP
sniff(count=0, prn = lambda x: p_action(x), iface='Ethernet20', filter='! (proto UDP and src port 9999 and dst port 9999)')
