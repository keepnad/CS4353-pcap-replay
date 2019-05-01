#!/usr/bin/env python3

# Daniel Peek qer419
# CS 4353.001
# Assignment 06
# April 29th, 2019

import argparse
import sys
import random
from time import sleep

from kamene.config import conf
conf.ipv6_enabled = False
from kamene.all import *

def main():
    # parse 2 arguments: -s flag and the path/filename of config file
    parser = argparse.ArgumentParser(description='Python 3 script to read and replay a network logfile')
    parser.add_argument('-s', '--send_packets', action='store_true',
                        help='Replay packets using data from cfg file')
    parser.add_argument('cfg_file', type=str, help='Path and filename of configuration file')
    args = parser.parse_args()

    # read in data from config file
    with open(args.cfg_file) as cfg:
        log_file = cfg.readline().rstrip()

        victim_ip = cfg.readline().rstrip()
        victim_mac = cfg.readline().rstrip()
        victim_port = int(cfg.readline().rstrip())

        attacker_ip = cfg.readline().rstrip()
        attacker_mac = cfg.readline().rstrip()
        attacker_port = int(cfg.readline().rstrip())

        replay_victim_ip = cfg.readline().rstrip()
        replay_victim_mac = cfg.readline().rstrip()
        replay_victim_port = int(cfg.readline().rstrip())

        replay_attacker_ip = cfg.readline().rstrip()
        replay_attacker_mac = cfg.readline().rstrip()
        replay_attacker_port = int(cfg.readline().rstrip())
        #replay_attacker_port = random.randint(40000, 50000)

        interface = cfg.readline().rstrip()
        timing = cfg.readline().rstrip()
        print(interface)


    # read in pcap header, then unpack into separate variables
    with open(log_file, "rb") as log:
        header = log.read(24)
    (magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, linktype) = struct.unpack("IHHiIII", header)

    # print pcap header info
    print(get_magic_type(magic))
    print('Version major number =', ver_major)
    print('Version minor number =', ver_minor)
    print('GMT to local correction =', thiszone)
    print('Timestamp accuracy =', sigfigs)
    print('Snaplen =', snaplen)
    print('Linktype =', linktype)
    print()

    # read packets into list and loop through them
    packets = rdpcap(log_file)
    start_seq = 5280
    current_seq = 0
    current_ack = 0
    my_packet = [None] * len(packets)

    # Determine which packets should be from us
    for i, packet in enumerate(packets):
        my_packet[i] = False
        if packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP):
            if packet[Ether].src == attacker_mac and packet[Ether].dst == victim_mac:
                if packet[IP].src == attacker_ip and packet[IP].dst == victim_ip:
                    my_packet[i] = True

    recvd_packet = None
    backup = None
    for i, packet in enumerate(packets):

        # determine if the current packet should be sent
        if args.send_packets and my_packet[i]:
            send_packet = True
        else:
            send_packet = False

        # get packet time and length
        if i == 0:
            start_time = packet.time

        caplen = len(packet)
        if caplen != packet.wirelen:
           print('Captured vs actual length mismatch in packet', i, file=sys.stderr)

        # print basic information available for every packet
        print('Packet', i)
        print('%.6f' % (packet.time - start_time))
        print('Captured length:', caplen)
        print('Actual length:', packet.wirelen)

        # print specific information based on packet type
        if packet.haslayer(Ether):
            print('Ethernet Header')
            print('    eth_src =', packet[Ether].src)
            if my_packet[i]: print('    rep_src =', replay_attacker_mac)
            print('    eth_dst =', packet[Ether].dst)
            if my_packet[i]: print('    rep_dst =', replay_victim_mac)

            if packet.haslayer(IP):
                print('    IP')
                print('        ip len =', packet[IP].len)
                print('        ip src =', packet[IP].src)
                if my_packet[i]: print('        rep src =', replay_attacker_ip)
                print('        ip dst =', packet[IP].dst)
                if my_packet[i]: print('        rep dst =', replay_victim_ip)

                if packet.haslayer(TCP):
                    print('        TCP')
                    print('            Src port =', packet[TCP].sport)
                    if my_packet[i]: print('            Rep src port =', replay_attacker_port)
                    print('            Dst port =', packet[TCP].dport)
                    if my_packet[i]: print('            Rep dst port =', replay_victim_port)
                    print('            Seq =', packet[TCP].seq)
                    print('            Ack =', packet[TCP].ack)

                elif packet.haslayer(UDP):
                    print('        UDP')
                    print('            Src port =', packet[UDP].sport)
                    print('            Dst port =', packet[UDP].dport)

                elif packet.haslayer(ICMP):
                    print('        ICMP')
                    print('            %s' % get_ICMP_type(packet[ICMP].type))

                elif packet.proto == 2:
                    print('        IGMP')

                else:
                    print('        Other')

            elif packet.haslayer(ARP):
                print('    ARP')
                print('        %s' % get_ARP_op(packet[ARP].op))

            else:
                print('    Other')

        elif packet.haslayer(Dot3):
            print('Ethernet Header')
            print('    src =', packet[Dot3].src)
            print('    dst =', packet[Dot3].dst)
            print('    len =', packet[Dot3].len)
            print('      Other')

        else:
            print('Other')

        print()

        # set new mac/ip for packet and send it
        if send_packet:
            if recvd_packet is None and backup is not None:
                recvd_packet = backup

            rep_packet = packet

            rep_packet[Ether].src = replay_attacker_mac
            rep_packet[Ether].dst = replay_victim_mac

            rep_packet[IP].src = replay_attacker_ip
            rep_packet[IP].dst = replay_victim_ip

            rep_packet[TCP].sport = replay_attacker_port
            rep_packet[TCP].dport = replay_victim_port

            del(rep_packet[IP].chksum)
            del(rep_packet[TCP].chksum)

            if i == 0:
                rep_packet[TCP].seq = start_seq

            elif recvd_packet is not None:
                flags = recvd_packet.sprintf('%TCP.flags%')
                payload = len(recvd_packet[TCP].payload)
                if 'S' in flags:
                    rep_packet[TCP].ack = recvd_packet[TCP].seq + 1
                    rep_packet[TCP].seq = recvd_packet[TCP].ack
                elif 'F' in flags:
                    rep_packet[TCP].ack = recvd_packet[TCP].seq + 1
                    rep_packet[TCP].seq = recvd_packet[TCP].ack
                else:
                    rep_packet[TCP].ack = recvd_packet[TCP].seq + payload
                    rep_packet[TCP].seq = recvd_packet[TCP].ack

            try:
                if i + 1 == len(packets) or my_packet[i + 1]:
                    sendp(rep_packet, iface=interface, verbose=0)
                    print('Packet %d sent' %(i))
                else:
                    backup = recvd_packet
                    recvd_packet = srp1(rep_packet, iface=interface, timeout=.5, verbose=0)
                    print('Packet %d sent' %(i))

            except PermissionError:
                print('Tried to send packet, but could not: Run as root to send packets')
        else:
            print('Packet %d not sent' %(i))

        print()

# return pcap magic type based on magic number
def get_magic_type(magic):
    if magic == 0xa1b2c3d4:
        return 'PCAP_MAGIC'
    elif magic == 0xd4c3b2a1:
        return 'PCAP_SWAPPED_MAGIC'
    elif magic == 0xa1b2cd34:
        return 'PCAP_MODIFIED_MAGIC'
    elif magic == 0x34cdb2a1:
        return 'PCAP_SWAPPED_MODIFIED_MAGIC'
    else:
        print('Bad PCAP_MAGIC value: 0x%x, ipnut file does not appear to be in PCAP format' % magic)
        print('Quitting...')
        quit()

# return ARP operation based on opcode
def get_ARP_op(op_num):
    if op_num == 1:
        return 'Arp Request'
    elif op_num == 2:
        return 'Arp Reply'
    elif op_num == 3:
        return 'Arp Reverse Request'
    elif op_num == 4:
        return 'Arp Reverse Reply'
    else:
        return 'Other'

# return ICMP type based on type number
def get_ICMP_type(type_num):
    if type_num == 0:
        return 'Echo Reply'
    elif type_num == 3:
        return 'Destination Unreachable'
    elif type_num == 4:
        return 'Stable Quench'
    elif type_num == 5:
        return 'Route Redirection'
    elif type_num == 6:
        return 'Alternate Host Address'
    elif type_num == 8:
        return 'Echo'
    elif type_num == 9:
        return 'Route Advertisment'
    elif type_num == 10:
        return 'Route Selection'
    elif type_num == 11:
        return 'Time Exceeded'
    elif type_num == 12:
        return 'Bad IP Header'
    elif type_num == 13:
        return 'Time Stamp Request'
    elif type_num == 14:
        return 'Time Stamp Reply'
    elif type_num == 15:
        return 'Information Request'
    elif type_num == 16:
        return 'Information Reply'
    elif type_num == 17:
        return 'Address Mask Request'
    elif type_num == 18:
        return 'Address Mask Reply'
    elif type_num == 30:
        return 'Traceroute'
    elif type_num == 31:
        return 'Data Conversion Error'
    elif type_num == 32:
        return 'Mobile Host Redirection'
    elif type_num == 33:
        return 'IPV6 Where are you?'
    elif type_num == 34:
        return 'IPV6 I am here.'
    elif type_num == 35:
        return 'Mobile Registration Request'
    elif type_num == 36:
        return 'Mobile Registration Reply'
    elif type_num == 37:
        return 'Domain Name Request'
    elif type_num == 38:
        return 'Domain Name Reply'
    elif type_num == 39:
        return 'Skip'
    elif type_num == 40:
        return 'Photuris'
    else:
        return 'Unknown'

if __name__ == '__main__':
    main()
