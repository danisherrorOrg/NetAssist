import time
from collections import defaultdict, deque

class TrafficStats:
    def __init__(self, interval=1):
        self.interval = interval  # seconds
        self.start_time = time.time()
        self.protocol_bytes = defaultdict(int)   # Bytes per protocol
        self.ip_bytes = defaultdict(int)         # Bytes per IP
        self.domain_bytes = defaultdict(int)     # Bytes per domain
        self.packet_times = deque()              # For PPS calculation

    def record_packet(self, packet, protocol, src_ip, dst_ip, pkt_len, src_domain=None, dst_domain=None):
        now = time.time()
        self.packet_times.append(now)

        # Clean old packet times to calculate PPS
        while self.packet_times and now - self.packet_times[0] > self.interval:
            self.packet_times.popleft()

        # Update statistics
        self.protocol_bytes[protocol] += pkt_len
        self.ip_bytes[src_ip] += pkt_len
        self.ip_bytes[dst_ip] += pkt_len

        if src_domain:
            self.domain_bytes[src_domain] += pkt_len
        if dst_domain:
            self.domain_bytes[dst_domain] += pkt_len

    def packets_per_second(self):
        return len(self.packet_times)

    def print_stats(self):
        print(f"\n--- Traffic Stats (last {self.interval}s) ---")
        print(f"PPS: {self.packets_per_second()}")
        print("Top Protocols:")
        for proto, b in self.protocol_bytes.items():
            print(f"  {proto}: {b} bytes")
        print("Top IPs:")
        for ip, b in self.ip_bytes.items():
            print(f"  {ip}: {b} bytes")
        print("Top Domains:")
        for domain, b in self.domain_bytes.items():
            print(f"  {domain}: {b} bytes")
        print("-----------------------------------------\n")