#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help="IP range to scan")
    options = parser.parse_args()

    if not options.ip:
        parser.error("[-] Please specify a network range.")

    return options

def scan():

    #creation d'une requete ARP vers le broadcast 
    arp_request = scapy.ARP(pdst=options.ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    #recuperation des adresses IP dans un dictionnaire
    clients_list = []
    for element in answered_list:
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list

#afficher les adresses IP avec leur adresse MAC correspondant
def print_scan(results_list):
    print("IP\t\t\tMAC Address\n---------------------------------------------")
    for client in results_list:
        print("{}\t\t{}".format(client["ip"], client["mac"]))

options = get_arguments()
result = scan()
print_scan(result)
