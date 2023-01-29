#!/Applications/anaconda3/lib/python3.9/site-packages python3
import os
import scapy
import sys
import argparse
from scapy.all import *
from argparse import *


#### arguement parsers ####
#parser = argparse.ArguementParser(prog='DNS request matcher',description='iterates through each packet in PCAP to find matching DNS response for DNS queries',epilog='Written by Rick K.')
#parser.add_arguement("-f","--filename", dest="inputFile" , type=str)
#args = parser.parse_args()


if len(sys.argv) > 2:
	print('You have specified too many arguements \n')
	sys.exit()

if len(sys.argv) < 2:
	print('You need to specify the path to be listed \n')
	sys.exit()

inputFile = str(sys.argv[1])



#### input pcap file ####
#input = input("Please enter the filename of the PCAP file in this folder to be parsed:\n")
pcap = rdpcap(inputFile)



#### define write functions - write to pcap file feature still in progress:  ####
#outputfilename2 = str(input+'Req-no-Resp-out.pcap')
#def writeReqSeen(packet):
#	PcapWriter(outputfilename1, packet, append=True)
#
#def writeRespSeen(packet2):
#	PcapWriter(outputfilename1, packet2, append=True)
#
#def writeReqNoResp(packet):
#	PcapWriter(outputfilename2, packet, append=True)
#
#



#### logic ####
for packet in range(0,len(pcap)-1):
	if pcap[packet][DNS].qr == 0:
		for packet2 in range(packet+1,len(pcap)-1):
			matchingResp=False
			if pcap[packet][DNS].id == pcap[packet2][DNS].id:
				if pcap[packet2][DNS].qr == 1:
					#writeReqSeen(packet)
					#writeRespSeen(packet2)
					matchingResp = True
					print('Packet 1 Req DNS ID + IP ID ',pcap[packet][DNS].id,' ',pcap[packet][IP].id ,' ' ,pcap[packet][DNS].qr,' Packet 2 Resp DNS ID + IP ID: ',pcap[packet2][DNS].id ,' ' , pcap[packet2][IP].id ,' ' , pcap[packet2][DNS].qr)
					break
			else:
				pass
		if matchingResp == False:
			#writeReqNoResp(packet)
			print('For the following DNS ID: ', pcap[packet][DNS].id , 'Requesting ',pcap[packet][DNSQR].qname ,' We do not see a matching response in: ' ,inputFile )
			print(pcap[packet][DNS].qr)
		print(pcap[packet][IP].id)
	else:
		pass

