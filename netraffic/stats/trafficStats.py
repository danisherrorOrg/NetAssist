import time
from collections import defaultdict

class TrafficStats:
    def __init__(self):
        # Cumulative stats
        self.total_packets = 0
        self.total_bytes = 0
        self.cum_protocol_packets = defaultdict(int)
        self.cum_protocol_bytes = defaultdict(int)

        # Interval stats (reset after each print)
        self.int_protocol_packets = defaultdict(int)
        self.int_protocol_bytes = defaultdict(int)

    def record_packet(self, protocol, pkt_len):
        # Update cumulative
        self.total_packets += 1
        self.total_bytes += pkt_len
        self.cum_protocol_packets[protocol] += 1
        self.cum_protocol_bytes[protocol] += pkt_len

        # Update interval
        self.int_protocol_packets[protocol] += 1
        self.int_protocol_bytes[protocol] += pkt_len

    def protocol_distribution(self):
        dist = {}
        for proto in self.cum_protocol_packets:
            pct_packets = (self.cum_protocol_packets[proto] / self.total_packets) * 100
            pct_bytes = (self.cum_protocol_bytes[proto] / self.total_bytes) * 100
            dist[proto] = {"packets": pct_packets, "bytes": pct_bytes}
        return dist

    def print_protocol_distribution(self, logger):
        dist = self.protocol_distribution()
        logger.info("\n--- Protocol Distribution (Cumulative) ---")
        for proto, stats in dist.items():
            interval_pkt = self.int_protocol_packets[proto]
            interval_bytes = self.int_protocol_bytes[proto]
            logger.info(
                f"{proto}: {stats['packets']:.2f}% packets, "
                f"{stats['bytes']:.2f}% bytes | "
                f"Interval: {interval_pkt} pkt, {interval_bytes} bytes"
            )
        logger.info("-----------------------------------------\n")
        # Reset interval stats
        self.int_protocol_packets.clear()
        self.int_protocol_bytes.clear()