from collections import defaultdict
from tabulate import tabulate

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

    def print_top_talkers(self, logger=None):
        top_by_packets, top_by_bytes = self.get_top_talkers()

        if logger:
            logger.info("\n--- Top Talkers (Packets) ---")
            for ip, pkt_count in top_by_packets:
                logger.info(f"{ip}: {pkt_count} packets")
            logger.info("\n--- Top Talkers (Bytes) ---")
            for ip, byte_count in top_by_bytes:
                logger.info(f"{ip}: {byte_count} bytes")
            logger.info("-----------------------------\n")
        else:
            print("\n--- Top Talkers (Packets) ---")
            for ip, pkt_count in top_by_packets:
                print(f"{ip}: {pkt_count} packets")
            print("\n--- Top Talkers (Bytes) ---")
            for ip, byte_count in top_by_bytes:
                print(f"{ip}: {byte_count} bytes")
            print("-----------------------------\n")

    def print_top_talkers_table(self, by="bytes", logger=None):
        """
        Print top talkers in table format.
        by: "bytes" or "packets"
        """
        if by == "bytes":
            sorted_list = sorted(self.ip_bytes.items(), key=lambda x: x[1], reverse=True)[:self.top_n]
            headers = ["Rank", "IP Address", "Bytes"]
        else:
            sorted_list = sorted(self.ip_packets.items(), key=lambda x: x[1], reverse=True)[:self.top_n]
            headers = ["Rank", "IP Address", "Packets"]

        if not sorted_list:
            msg = "No top talkers available."
            if logger:
                logger.info(msg)
            else:
                print(msg)
            return

        table = [[i+1, ip, val] for i, (ip, val) in enumerate(sorted_list)]

        table_str = tabulate(table, headers=headers, tablefmt="fancy_grid")
        if logger:
            logger.info("\n" + table_str)
        else:
            print("\n" + table_str)