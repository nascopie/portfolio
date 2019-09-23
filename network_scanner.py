#!/usr/bin/env python

# network scanner using ARP request
# paired with a list of known MAC from companies

import optparse
import socket
from scapy.all import *


def opt_parse():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--ipaddr", dest="ipaddr", help="Address IP of the network")
    return parser.parse_args()
    
    
def find_device_company(MAC):
    a,b,c,d,e,f = MAC.split(":")
    mac = a+b+c
    try:
        file = open("test_files/mac-vendor.txt", "r")
        for line in file:
            if mac.upper() in line:
                company = line[7:].strip("\n")
                return company
    except:
        pass
    

def scan(ip):
    arp_request = scapy.all.ARP(pdst=ip)
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broad = broadcast / arp_request
    answered_list = scapy.all.srp(arp_req_broad, timeout=1, verbose=False)[0]

    print("IP\t\t\tMAC Address\t\tHostname\t\tCompany\n----------------------------------------------------------------------------------")

    for element in answered_list:
        mac_addr = str(element[1].hwsrc)
        ip_addr = str(element[1].psrc)
        try:
            dns = socket.gethostbyaddr(ip_addr)
            hostname = dns[0]
        except:
            pass
        print element[1].psrc + "\t\t" + element[1].hwsrc +"\t",
        try:
            print str(hostname)[0:16] + "\t\t",
        except:
            print "NOT FOUND" + "\t\t",
        print str(find_device_company(mac_addr))[0:20]


(options, arguments) = opt_parse()
scan(options.ipaddr)
