#!/usr/bin/python

from scapy.all import *


def proto(pkt):
    if pkt.proto == 6:
        return "TCP"
    elif pkt.proto == 1:
        return "ICMP"
    elif pkt.proto == 2:
        return "IGMP"
    elif pkt.proto == 17:
        return "UDP"
    else:
        return "UNKNOWN"


class PacketAnalysis:
    def __init__(self, packet: Packet):
        self.sport = packet.sport
        self.dport = packet.dport
        self.proto = proto(packet)
        self.count = 1
        self.min = len(packet)
        self.max = len(packet)
        self.avg = len(packet)

    def add_packet(self, packet: Packet):
        self.min = min(self.min, len(packet))
        self.max = max(self.max, len(packet))
        self.avg = (self.count * self.avg + len(packet)) / self.count + 1
        self.count += 1

    def __str__(self):
        return "{}\t{}\t{}\t{}\t{}\t{}\t{}\n\n\n".format(self.proto,
                                                         self.sport, self.dport,
                                                         self.count, self.avg,
                                                         self.min, self.max)

    def __repr__(self):
        return self.__str__()

    def proxy(self, packet: Packet):
        if self.sport == packet.sport and \
                self.dport == packet.dport and \
                self.proto == proto(packet):
            return True
        else:
            return False


packetAnalysis_list = []


def customAction1(packet: Packet):
    print(packet.fields)
    for existed_pAnalysis in packetAnalysis_list:
        if existed_pAnalysis.proxy(packet):
            existed_pAnalysis.add_packet(packet)
            # print(packetAnalysis_list)
            return
    packetAnalysis_list.append(PacketAnalysis(packet))
    # print(packetAnalysis_list)


def main():
    for arg in sys.argv:
        print("arg")
        if arg == '-rm_udp_tcp':
            os.system('rmmod LKM.o')
        elif arg == '-rm_icmp_igmp':
            os.system('cd icmp_igmp')
            os.system('rmmod LKM.o')
            os.system('cd ..')
        elif arg == '-b_udp_tcp':
            os.system('make')
            os.system('insmod LKM.o')
        elif arg == '-b_icmp_igmp':
            os.system('cd icmp_igmp')
            os.system('make')
            os.system('insmod LKM.o')
            os.system('cd ..')
    sniff(iface='eno1', filter="tcp or udp", prn=customAction1)


if __name__ == '__main__':
    main()
