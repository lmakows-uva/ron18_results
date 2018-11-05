import sys,time
from scapy.all import *
from scapy.utils import rdpcap
import threading
import pcap_diff



def get_mac(interface):
	#Taken from https://stackoverflow.com/a/32080877/869012
	try:
		mac = open('/sys/class/net/'+interface+'/address').readline()
	except:
		mac = "00:00:00:00:00:00"

	return mac[0:17]

VERBOSE=False
ARISTA_MAC='00:1c:73:7b:f7:5c'
#MELLANOX_MAC='ec:0d:9a:8d:f1:e4'
#it seems for Mellanox using the mac of eth0 does not work, here mac for Eth52
MELLANOX_MAC='ec:0d:9a:5a:25:40'

try:
	work_mode = sys.argv[1]
except IndexError:
	work_mode=''

if work_mode == 'arista':

	DUT_MAC=ARISTA_MAC
	HOST_IFACE='enp5s0f4d1'
	SRC_IP='10.0.0.10'
	DST_IP='10.0.0.11'

elif work_mode == 'mlnx' or work_mode == 'mellanox':

	DUT_MAC=MELLANOX_MAC
	HOST_IFACE='enp5s0f4'

	SRC_IP='10.10.0.10'
	DST_IP='10.10.0.1'
	#DST_IP='192.168.251.4'

else:
	print "Usage %s [arista|mlnx] <pcap file>" % sys.argv[0]
	sys.exit(1)

HOST_MAC=get_mac(HOST_IFACE)


def printe(msg):
	sys.stderr.write(msg + '\n')
	sys.stderr.flush()

def craft_stop_packet():

	ether=(Ether(dst=DUT_MAC, src=HOST_MAC))
	ip=IP(dst=DST_IP, src=SRC_IP, proto=254) 
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

		# Check whether packet has an Ethernet layer, if not skip it
		if not (p.haslayer(Ether) or p.haslayer(Dot3)):
			printe("No ether layer found in packet (%s), skipping" % p.summary())
			continue



		# Some packets should not get their DST MAC changed, i.e.
		# multicast, broadcast

		if not ( p.dst.startswith('01:') or p.dst.startswith('11:') ):
			p.dst = DUT_MAC

			# for Packets with unicast dst MAC, rewrite dst IP
			# address
			if p.haslayer(IP):
				p.getlayer(IP).dst = DST_IP
				del p.getlayer(IP).chksum

				if p.haslayer(TCP):
					del p.getlayer(TCP).chksum

		#p.display()
		wrpcap(PCAP, p, append=True)
		sendp(p, iface=HOST_IFACE, verbose=VERBOSE)

		ETHER_CNT+=1

		time.sleep(1)

	#sendp(pkts[0], iface='vlan333', loop=1, inter=2)

	#send a stop packet
	p = craft_stop_packet()
	sendp(p, iface=HOST_IFACE)


### MAIN
pcap_to_send=sys.argv[2]
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

