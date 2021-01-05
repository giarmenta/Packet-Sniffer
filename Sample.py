#!/usr/bin/python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(filter='tcp and dst port 23 and src host 000.00.000.000', prn=print_pkt)  # filter='icmp'
