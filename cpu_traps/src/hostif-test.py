import sys,time
from scapy.all import *
from scapy.utils import rdpcap
import threading
import pcap_diff

DUT_MAC='00:1c:73:7b:f7:5c'
#HOST_MAC='00:07:43:39:8c:58'
HOST_MAC='EC:0D:9A:8D:F1:E4'
VERBOSE=False

HOST_IFACE='enp5s0f4d1'

def printe(msg):
	sys.stderr.write(msg + '\n')
	sys.stderr.flush()

def craft_stop_packet():

	ether=(Ether(dst=DUT_MAC, src=HOST_MAC))
	ip=IP(dst='192.168.0.111', src='192.168.0.18', proto=254) 
	udp=fuzz(UDP())

	p = (ether/ip/udp)

	return p


def is_stop_packet(p):

	if p.haslayer(IP):
		if p[1].proto == 254:
			return True	

	return False

def rmfile(f):
	try:
		os.remove(f)
	except OSError:
		printe('Removing of %s file failed' % f)


def save_pcap(p, pcapfile):

	sys.stderr.write('.')
	sys.stderr.flush()

	try:
		wrpcap(pcapfile, Ether(str(p[3])), append=True)
	except IndexError:
		if VERBOSE:
			printe('Layer missing, stop packet(?)')
		pass

def mysniff():

	PCAP='/tmp/debug_sniff.pcap'
	rmfile(PCAP)

	sniff(count=0, store=1, prn = lambda x: save_pcap(x, PCAP), stop_filter = is_stop_packet, iface=HOST_IFACE,filter='ip[9] == 254 || (ip proto UDP and src port 9999 and dst port 9999)')

def mysend(filename):

	PCAP='/tmp/debug_send.pcap'
	global ETHER_CNT
	ETHER_CNT=0

	rmfile(PCAP)

	pkts=rdpcap(filename)

	for p in pkts:
		#Ether(str(p)).display()


		# Check whether packet has a Ethernet layer, if not skip it
		if not (p.haslayer(Ether) or p.haslayer(Dot3)):
			printe("No ether layer found in packet (%s), skipping" % p.summary())
			continue
		# Some packets should not get their DST MAC changed, i.e.
		# multicast, broadcast

		if not ( p.dst.startswith('01:') or p.dst.startswith('11:') ):
			p.dst = DUT_MAC

		wrpcap(PCAP, p, append=True)
		sendp(p, iface=HOST_IFACE, verbose=VERBOSE)

		ETHER_CNT+=1

		time.sleep(1)

	#sendp(pkts[0], iface='vlan333', loop=1, inter=2)

	#send a stop packet
	p = craft_stop_packet()
	sendp(p, iface=HOST_IFACE)


### MAIN
pcap_to_send=sys.argv[1]
result=''

t1 = threading.Thread(target=mysniff, args = ())
t1.daemon = True
t1.start()

#t2 = threading.Thread(target=mysend, args = (pcap_to_send))
time.sleep(5)
mysend(pcap_to_send)

t1.join()

if ETHER_CNT > 0:
	ret = pcap_diff.cmp_left_to_right('/tmp/debug_send.pcap','/tmp/debug_sniff.pcap')

	if ret:
		result='OK'
	else:
		result='FAIL'
else:
	result='SKIPPED'

#SUMMARY
print "%s,%s" % (pcap_to_send,result)

#try:
#	work_mode = sys.argv[1]
#except IndexError:
#	work_mode=None
#
#if work_mode == 'send':
#	mysend()
#elif work_mode == 'sniff':
#	mysniff()
#else:
#	print "Usage %s [send|sniff]" % sys.argv[0]
#
