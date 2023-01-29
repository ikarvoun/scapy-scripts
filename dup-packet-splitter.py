#!/Applications/anaconda3/lib/python3.9/site-packages python3
import os
import scapy
from scapy.all import *


###########################################################################################################################################################################################
#####  ABOUT: This script is for use on PCAP files  in enironments where network analysis tools and active tap technology such as Gigamon, IXIA, Nozomi and Netscout
#####  
#####  In firewall-on-a-stick implementations, there may be instances where probes in the network collect traffic both in the ingress and egress directions on a tapped link.
#####  
#####  The script will delete all the duplicate packets in the PCAP file by only monitoring one copy of each TCP stream. 
#####  This is achieved by using the src/dst MAC of the first packet as a reference point and only collecting packets with those fields.
#####  It can be verified that no duplicate packets exist in the output, by confirming ip.id field of the packets in the output PCAP file.
#####  
#####  PRE-REQUISITES
#####  1. Have python installed (obviously)
#####  2. Install Scapy library through anaconda
#####  3. Run this script, with the following syntax:
#####
#####        cli> python3 svdc-strip.py <FILENAME>
#####             python3 svdc-strip.py samplecapture.pcap  
#####
#####  NOTE: This version of script will only work with following criteria:
#####        1. Run the script in the same directory as the target file, otherwise the absolute file path needs to be specified. 
#####        2. an output file '<filename>-out.pcap' will be created with the desired filter being performed in the current working directory
#####
##########################################################################################################################################

#### Arguements and Variable setup + optimize ####
if len(sys.argv) > 2:
	print('You have specified too many arguements \n')
	sys.exit()
if len(sys.argv) < 2:
	print('You need to specify the path to be listed \n')
	sys.exit()
inputFile = str(sys.argv[1])
pcap = rdpcap(inputFile)
conf.layers.filter([Ether])
firstSrcMAC = pcap[0][Ether].src
firstDstMAC = pcap[0][Ether].dst


#### Define function to write packet ####
def write(packet):
	wrpcap(input+'-out.pcap', packet, append=True)


#### Loop through packets ####
for packet in pcap:
	if (packet.src == firstSrcMAC or packet.src == firstDstMAC) or (packet.dst == firstDstMAC  or packet.dst == firstSrcMAC):
		write(packet)
	else:
		pass


