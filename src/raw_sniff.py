#!/usr/bin/env python
import sys, os, time, json
import scapy.all as scapy

def processPkt(inpPacket):
	inpPacket.show()

def main():
	## sniffer on interface
	scapy.sniff(iface="wlp3s0", prn=processPkt)#, filter="tcp", store=0)

if __name__ == "__main__":
	main()