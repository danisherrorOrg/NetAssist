from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import traceback

from netraffic.stats.packet_counter import PacketCounter
from netraffic.parser.protocol_detector import get_protocol_name

counter = PacketCounter()


def process_packet(packet):
    try:
        if not packet.haslayer(IP):
            return

        counter.record_packet()
        pps = counter.packets_per_second()

        timestamp = datetime.now().strftime("%H:%M:%S")

        protocol = get_protocol_name(packet)

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        src_port = "-"
        dst_port = "-"

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        print(
            f"[{timestamp}] {protocol} "
            f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
            f"| PPS: {pps}"
        )

    except Exception:
        traceback.print_exc()

def start_capture(interface=None):

    print("\nStarting Packet Capture...\n")

    sniff(
        iface=interface,
        prn=process_packet,
        store=False,
        promisc=True
    )