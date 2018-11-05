from scapy.all import *
import os

def get_mac(interface):
	try:
		mac = open('/sys/class/net/'+interface+'/address').readline()
	except:
		mac = "00:00:00:00:00:00"

	return mac[0:17]

PCAP='/tmp/debug.pcap'

DUT_IFACE='Ethernet20'
HOST_MAC='00:07:43:39:8c:58'


#take MAC from mgmt iface
DUT_MAC=get_mac('eth0')

def p_action(p):

	ether=Ether(dst=HOST_MAC, src=DUT_MAC)
	ip=IP(src='192.168.0.111', dst='192.168.0.18') 
	udp=UDP(sport=9999,dport=9999)

	p_encap = (ether/ip/udp)
	
	#save packet to a PCAP before encapsulation
	
	wrpcap(PCAP, p, append=True)

	#encapsulate and send
	p = (p_encap/p)
	#(p).display()
	sendp(p, iface=DUT_IFACE)


try:
	os.remove(PCAP)
except OSError:
	print 'Removing of %s file failed' % PCAP
sniff(count=0, prn = lambda x: p_action(x), iface=DUT_IFACE, filter='! (proto UDP and src port 9999 and dst port 9999)')
