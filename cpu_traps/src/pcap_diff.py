from scapy.all import *
from scapy.utils import rdpcap
import sys

VERBOSE=False

def pkt_cmp(p1, p2):
	if p1 == p2:
		if VERBOSE:
			sys.stdout.write('+')
		return True
	else:
		if VERBOSE:
			sys.stdout.write('.')
		return False
		

def cmp_left_to_right(file1, file2):

	pkt_match_cnt=0
	pkts1=rdpcap(file1)
	pkts2=rdpcap(file2)

	pkts1 = map(lambda x: str(x), pkts1)
	pkts2 = map(lambda x: str(x), pkts2)

	for p1 in pkts1:
		for i in range(len(pkts2)):
			
			try:
				p2 = pkts2[i]
			except IndexError:
				#print 
				#print 'Packet with index %s has been already matched' % i
				continue

			if pkt_cmp(p1, p2):
				pkt_match_cnt+=1


				"""
				Once the packet is matched remove it from the list of
				received packets. This helps to avoid double matching
				a packet if there are more than one identical packets contained in a given
				PCAP
				"""

				del pkts2[i]

	if VERBOSE:
		print
		print "%s packets matched out of %s sent" % (pkt_match_cnt, len(pkts1))	
	print "[%s/%s]" % (pkt_match_cnt, len(pkts1))	

	if pkt_match_cnt == len(pkts1):
		return True
	else:
		return False


if __name__ == "__main__":
	file1 = sys.argv[1]
	file2 = sys.argv[2]
	VERBOSE=True
	pkt_match_cnt=0
	ret = cmp_left_to_right(file1, file2)

	if not ret:
		sys.exit(1)	
