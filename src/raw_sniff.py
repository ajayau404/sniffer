#!/usr/bin/env python
import sys, os, time, json
import scapy.all as s
import random
from scapy.all import ICMP, IP, sr1, TCP, sr
host = "192.168.0.1"
port_range = [22, 23, 80, 443, 3389]

# print(dir(s))
def map():
    for dst_port in port_range:
        src_port = random.randint(1025,65534)
        resp = sr1(
            IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,
            verbose=0,
        )

        if resp is None:
            print("{%s}:{%s} is filtered (silently dropped)."%(host, dst_port))

        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags == 0x12):
                # Send a gratuitous RST to close the connection
                send_rst = sr(
                    IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),
                    timeout=1,
                    verbose=0,
                )
                print("{%s}:{%s} is open."%(host, dst_port))

            elif (resp.getlayer(TCP).flags == 0x14):
                print("{%s}:{%s} is closed."%(host, dst_port))

        elif(resp.haslayer(ICMP)):
            if(
                int(resp.getlayer(ICMP).type) == 3 and
                int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
            ):
                print("{host}:{dst_port} is filtered (silently dropped).".format(host, dst_port))

def handle_packet(pkt):
    # print(pkt.show())
    # print(pkt.summary())
    # print(dir(pkt))
    # print("dissect:", pkt.dissect)
    # print("get_field:",pkt.get_field)
    ip_src, ip_dst = None, None
    tcp_sport, tcp_dport = None, None
    if s.IP in pkt:
        ip_src=pkt[s.IP].src
        ip_dst=pkt[s.IP].dst
    if s.TCP in pkt:
        tcp_sport=pkt[s.TCP].sport
        tcp_dport=pkt[s.TCP].dport
    print("ip_src:%s-> ip_dst:%s, tcp_sport:%s->tcp_dport:%s"%(ip_src, ip_dst, tcp_sport, tcp_dport))

def sniff():
    s.sniff(iface="wlo1", prn=handle_packet)#, filter="type Data")

def main():
    # sniff()
    map()

if __name__ == "__main__":
    main()