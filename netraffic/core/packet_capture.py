from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import traceback

from netraffic.dns.dns_parser import parse_dns
from netraffic.stats.packet_counter import PacketCounter
from netraffic.parser.protocol_detector import get_protocol_name
from netraffic.dns.reverse_dns import reverse_lookup
from netraffic.dns.dns_cache import resolve_ip, store_mapping
from netraffic.tls.tls_sni_parser import parse_tls_sni
from netraffic.http.http_parser import parse_http_host
from netraffic.flow.flow_tracker import FlowTracker

seen_http = set()
seen_tls = set()
flow_tracker = FlowTracker()

counter = PacketCounter()


def process_packet(packet):

    try:

        # TLS / HTTP detection
        tls_domain = None
        if packet.haslayer(TCP):

            sport = packet[TCP].sport
            dport = packet[TCP].dport

            if sport == 443 or dport == 443:
                tls_domain = parse_tls_sni(packet)
        http_host = parse_http_host(packet)

        if http_host and http_host not in seen_http:
            seen_http.add(http_host)
            print(f"[HTTP HOST] {http_host}")

        if tls_domain and tls_domain.strip() and tls_domain not in seen_tls:
            seen_tls.add(tls_domain)
            print(f"[TLS SNI] {tls_domain}")

        # DNS detection
        dns_data = parse_dns(packet)

        if dns_data:

            if dns_data[0] == "QUERY":
                print(f"[DNS QUERY] {dns_data[1]}")

            elif dns_data[0] == "RESPONSE":
                domain = dns_data[1]
                ips = dns_data[2]

                for ip in ips:
                    print(f"[DNS RESPONSE] {domain} -> {ip}")

            return

        if not packet.haslayer(IP):
            return

        counter.record_packet()
        if counter.total_packets % 10 == 0:
            print("\n--- Active Flows ---")
            flow_tracker.print_active_flows()
            print("--------------------\n")
        pps = counter.packets_per_second()

        timestamp = datetime.now().strftime("%H:%M:%S")

        protocol = get_protocol_name(packet)

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        pkt_len = len(packet)

        src_port = "-"
        dst_port = "-"

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        src_domain = resolve_ip(src_ip)
        dst_domain = resolve_ip(dst_ip)

        if not src_domain:
            src_domain = reverse_lookup(src_ip)
            if src_domain:
                store_mapping(src_domain, [src_ip])

        if not dst_domain:
            dst_domain = reverse_lookup(dst_ip)
            if dst_domain:
                store_mapping(dst_domain, [dst_ip])

        src_display = src_domain if src_domain else src_ip
        dst_display = dst_domain if dst_domain else dst_ip
        flow_tracker.update(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            pkt_len
        )

        print(
            f"[{timestamp}] {protocol} "
            f"{src_display}:{src_port} -> {dst_display}:{dst_port} "
            f"| PPS: {pps} | LEN: {pkt_len}"
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