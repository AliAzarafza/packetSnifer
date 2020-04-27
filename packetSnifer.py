#################
#   liberary    #
#################
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=processSniffedPacket, filter="udp")



def processSniffedPacket(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet)



sniff('eth0')   