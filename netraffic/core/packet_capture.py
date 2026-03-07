from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

from netraffic.stats.packet_counter import PacketCounter


counter = PacketCounter()


def process_packet(packet):

    counter.record_packet()
    pps = counter.packets_per_second()

    timestamp = datetime.now().strftime("%H:%M:%S")

    if IP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = "OTHER"
        src_port = "-"
        dst_port = "-"

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        print(
            f"[{timestamp}] {protocol} "
            f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
            f"| PPS: {pps}"
        )


def start_capture(interface=None):

    print("\nStarting Packet Capture...\n")

    sniff(
        iface=interface,
        prn=process_packet,
        store=False
    )