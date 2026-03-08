from collections import defaultdict

class TopTalkers:
    def __init__(self, top_n=10):
        self.top_n = top_n
        self.ip_packets = defaultdict(int)
        self.ip_bytes = defaultdict(int)

    def record_packet(self, src_ip, dst_ip, pkt_len):
        # Increment stats for both source and destination
        self.ip_packets[src_ip] += 1
        self.ip_bytes[src_ip] += pkt_len

        self.ip_packets[dst_ip] += 1
        self.ip_bytes[dst_ip] += pkt_len

    def get_top_talkers(self):
        # Sort by packets
        top_by_packets = sorted(self.ip_packets.items(), key=lambda x: x[1], reverse=True)[:self.top_n]
        # Sort by bytes
        top_by_bytes = sorted(self.ip_bytes.items(), key=lambda x: x[1], reverse=True)[:self.top_n]
        return top_by_packets, top_by_bytes

    def print_top_talkers(self,logger):
        top_by_packets, top_by_bytes = self.get_top_talkers()
        logger.info("\n--- Top Talkers (Packets) ---")
        for ip, pkt_count in top_by_packets:
            logger.info(f"{ip}: {pkt_count} packets")
        logger.info("\n--- Top Talkers (Bytes) ---")
        for ip, byte_count in top_by_bytes:
            logger.info(f"{ip}: {byte_count} bytes")
        print("-----------------------------\n")