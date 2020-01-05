#!/usr/bin/env python
import sys, os, time, json
import scapy.all as s
# print(dir(s))
def handle_packet(pkt):
    # print(pkt.show())
    print(pkt.summary())
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
def main():
    s.sniff(iface="wlp3s0", prn=handle_packet)#, filter="type Data")

if __name__ == "__main__":
    main()