#!/usr/bin/env python

import subprocess
import optparse
import re

#fonction qui permet aux utilisateur de rentrer les arguments
def get_arguments():

    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")
    (options, arguments) = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please specify interface, use --help for  more informations.")
    elif not options.new_mac:
        parser.error("[-] Please specify MAC address, use --help for more informations.")
    return options

#appel de ligne de commande dans la console afin de modifier l'adresse MAC
def change_mac(interface, new_mac):

    print("[+] Changing the MAC address for {} to {}".format(interface, new_mac))
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

#recupere les adresses mac et les associe avec les adresses IP
def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))

    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("[-] Could not get MAC address")


options = get_arguments()

current_mac = get_current_mac(options.interface)
print("Current mac is {}".format(current_mac))

change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)

if current_mac == options.new_mac:
    print("[+] Current MAC was successfully changed to {}".format(current_mac))
else:
    print("[-] Current MAC did not change.")
