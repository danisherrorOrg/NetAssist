from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import traceback
from netraffic.dns.dns_parser import parse_dns
from netraffic.stats.packet_counter import PacketCounter
from netraffic.parser.protocol_detector import get_protocol_name
from netraffic.dns.reverse_dns import reverse_lookup

counter = PacketCounter()


def process_packet(packet):

    try:

        # DNS detection first
        dns_data = parse_dns(packet)

        if dns_data:

            if dns_data[0] == "QUERY":
                domain = dns_data[1]
                print(f"[DNS QUERY] {domain}")

            elif dns_data[0] == "RESPONSE":
                domain = dns_data[1]
                ips = dns_data[2]

                for ip in ips:
                    print(f"[DNS RESPONSE] {domain} -> {ip}")

            return

        # Normal packet parsing
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

        src_port = "-"
        dst_port = "-"

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        src_domain = reverse_lookup(src_ip)
        dst_domain = reverse_lookup(dst_ip)

        src_display = src_domain if src_domain else src_ip
        dst_display = dst_domain if dst_domain else dst_ip

        print(
            f"[{timestamp}] {protocol} "
            f"{src_display}:{src_port} -> {dst_display}:{dst_port} "
            f"| PPS: {pps}"
        )

    except Exception as e:
        print("Packet error:", e)

def start_capture(interface=None):

    print("\nStarting Packet Capture...\n")

    sniff(
        iface=interface,
        prn=process_packet,
        store=False,
        promisc=True
    )