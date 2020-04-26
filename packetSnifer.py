#################
#   liberary    #
#################
import scapy.all as acapy


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=processSniffedPacket)



def processSniffedPacket(packet):
    print(packet)


sniff('eth0')