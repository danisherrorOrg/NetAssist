from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import sys
from collections import Counter
import geoip2.database

from netraffic.dns.dns_parser import parse_dns
from netraffic.stats.top_talkers import TopTalkers
from netraffic.stats.packet_counter import PacketCounter
from netraffic.parser.protocol_detector import get_protocol_name
from netraffic.dns.reverse_dns import reverse_lookup
from netraffic.dns.dns_cache import resolve_ip, store_mapping
from netraffic.stats.trafficStats import TrafficStats
from netraffic.tls.tls_sni_parser import parse_tls_sni
from netraffic.http.http_parser import parse_http_host
from netraffic.flow.flow_tracker import FlowTracker

# ----------------------
# Global State
# ----------------------
domain_counter = Counter()
geoip_reader = geoip2.database.Reader("./GeoLite2-City.mmdb")
traffic_stats = TrafficStats()
top_talkers = TopTalkers(top_n=10)
seen_http = set()
seen_tls = set()
flow_tracker = FlowTracker()
counter = PacketCounter()

# ----------------------
# Filter & Blacklist Config
# ----------------------
ENABLE_FILTERS = False
FILTER_IPS = set()         # No IP filter by default
FILTER_PORTS = set()       # No port filter by default
FILTER_PROTOCOLS = set()   # No protocol filter by default
FILTER_DOMAINS = set()     # No domain filter by default

BLACKLIST_DOMAINS = set()  # Blacklisted domains


# ----------------------
# Helper Functions
# ----------------------
def print_top_domains(top_n=10):
    print("\n--- Top Requested Domains ---")
    for domain, count in domain_counter.most_common(top_n):
        print(f"{domain}: {count}")
    print("----------------------------\n")


def get_geo_info(ip):
    try:
        response = geoip_reader.city(ip)
        country = response.country.name
        region = response.subdivisions.most_specific.name
        city = response.city.name
        return f"{city}, {region}, {country}"
    except:
        return None


def is_blacklisted(packet):
    """Return True if packet matches any blacklisted domain."""
    # DNS
    dns_data = parse_dns(packet)
    if dns_data:
        domain = dns_data[1] if dns_data[0] in {"QUERY", "RESPONSE"} else None
        if domain and any(bd in domain for bd in BLACKLIST_DOMAINS):
            return True

    # TLS SNI
    tls_domain = parse_tls_sni(packet)
    if tls_domain and any(bd in tls_domain for bd in BLACKLIST_DOMAINS):
        return True

    # HTTP Host
    http_host = parse_http_host(packet)
    if http_host and any(bd in http_host for bd in BLACKLIST_DOMAINS):
        return True

    return False


def packet_matches_domain(packet):
    """Return True if packet matches any domain filter."""
    dns_data = parse_dns(packet)
    if dns_data:
        domain = dns_data[1] if dns_data[0] in {"QUERY", "RESPONSE"} else None
        if domain and any(domain.endswith(d) for d in FILTER_DOMAINS):
            return True

    tls_domain = parse_tls_sni(packet)
    if tls_domain and any(tls_domain.endswith(d) for d in FILTER_DOMAINS):
        return True

    http_host = parse_http_host(packet)
    if http_host and any(http_host.endswith(d) for d in FILTER_DOMAINS):
        return True

    return False


def packet_passes_filter(packet):
    """Return True if packet passes IP/Port/Protocol filters."""
    if not packet.haslayer(IP):
        return False

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if FILTER_IPS and src_ip not in FILTER_IPS and dst_ip not in FILTER_IPS:
        return False

    protocol = ""
    src_port = dst_port = None

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer("ICMP"):
        protocol = "ICMP"

    if FILTER_PROTOCOLS and protocol not in FILTER_PROTOCOLS:
        return False

    if FILTER_PORTS and protocol in {"TCP", "UDP"}:
        if src_port not in FILTER_PORTS and dst_port not in FILTER_PORTS:
            return False

    return True


# ----------------------
# Packet Processing
# ----------------------
def process_packet(packet):
    try:
        # Check blacklist first
        if is_blacklisted(packet):
            print("[BLACKLISTED DOMAIN] Malicious packet detected!")
            sys.exit(1)  # or log only

        # Apply filters if enabled
        if ENABLE_FILTERS:
            if not packet_passes_filter(packet):
                return
            if FILTER_DOMAINS and not packet_matches_domain(packet):
                return

        # TLS SNI / HTTP Host
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
            domain_counter[http_host] += 1

        tls_domain = parse_tls_sni(packet)
        if tls_domain:
            tls_domain = tls_domain.strip()
            # Only print valid domain-like strings
            if '.' in tls_domain and tls_domain not in seen_tls:
                seen_tls.add(tls_domain)
                print(f"[TLS SNI] {tls_domain}")
                domain_counter[tls_domain] += 1

        # DNS
        dns_data = parse_dns(packet)
        if dns_data:
            if dns_data[0] == "QUERY":
                domain = dns_data[1]
                print(f"[DNS QUERY] {domain}")
                domain_counter[domain] += 1
            elif dns_data[0] == "RESPONSE":
                domain = dns_data[1]
                ips = dns_data[2]
                domain_counter[domain] += 1
                for ip in ips:
                    print(f"[DNS RESPONSE] {domain} -> {ip}")
            return

        if not packet.haslayer(IP):
            return

        # Record packet
        counter.record_packet()
        pps = counter.packets_per_second()
        timestamp = datetime.now().strftime("%H:%M:%S")
        protocol = get_protocol_name(packet)
        pkt_len = len(packet)

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = dst_port = "-"
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Resolve domain names
        src_domain = resolve_ip(src_ip) or reverse_lookup(src_ip)
        dst_domain = resolve_ip(dst_ip) or reverse_lookup(dst_ip)
        if src_domain: store_mapping(src_domain, [src_ip])
        if dst_domain: store_mapping(dst_domain, [dst_ip])

        # GeoIP
        src_geo = get_geo_info(src_ip)
        dst_geo = get_geo_info(dst_ip)
        src_display = f"{src_ip} ({src_geo})" if src_geo else src_ip
        dst_display = f"{dst_ip} ({dst_geo})" if dst_geo else dst_ip

        # Update flow tracker
        flow_tracker.update(src_ip, dst_ip, src_port, dst_port, protocol, pkt_len)

        # Update traffic stats
        traffic_stats.record_packet(protocol, pkt_len)

        # Update top talkers
        top_talkers.record_packet(src_ip, dst_ip, pkt_len)

        # Print stats periodically
        if counter.total_packets % 100 == 0:
            flow_tracker.print_active_flows()
            traffic_stats.print_protocol_distribution()
            top_talkers.print_top_talkers()
            print_top_domains(top_n=10)

        # Print main packet info
        print(f"[{timestamp}] {protocol} {src_display}:{src_port} -> {dst_display}:{dst_port} | PPS: {pps} | LEN: {pkt_len}")

    except Exception as e:
        print("Packet error:", e)


# ----------------------
# Start Capture
# ----------------------
def start_capture(interface=None):
    print("\nStarting Packet Capture...\n")
    sniff(
        iface=interface,
        prn=process_packet,
        store=False,
        promisc=True
    )