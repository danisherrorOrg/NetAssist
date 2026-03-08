import time
from tabulate import tabulate

class FlowTracker:
    def __init__(self):
        self.flows = {}

    def update(self, src_ip, dst_ip, src_port, dst_port, protocol, pkt_len):
        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        now = time.time()

        if key not in self.flows:
            self.flows[key] = {
                "packets": 1,
                "bytes": pkt_len,
                "start": now,
                "last": now
            }
        else:
            flow = self.flows[key]
            flow["packets"] += 1
            flow["bytes"] += pkt_len
            flow["last"] = now

    def print_active_flows(self, logger=None):
        """Print flows one by one (legacy style)."""
        now = time.time()
        for key, flow in self.flows.items():
            src_ip, dst_ip, src_port, dst_port, protocol = key
            duration = int(flow["last"] - flow["start"])
            bytes_kb = flow["bytes"] / 1024
            msg = (
                f"FLOW {src_ip}:{src_port} → {dst_ip}:{dst_port} {protocol} "
                f"| Packets: {flow['packets']} "
                f"| Bytes: {bytes_kb:.2f} KB "
                f"| Duration: {duration}s"
            )
            if logger:
                logger.info(msg)
            else:
                print(msg)

    def print_flows_table(self, logger=None):
        """Print active flows in a table format."""
        if not self.flows:
            msg = "No active flows."
            if logger:
                logger.warning(msg)
            else:
                print(msg)
            return

        headers = ["Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Packets", "Bytes (KB)", "Duration (s)"]
        table = []

        for key, flow in self.flows.items():
            src_ip, dst_ip, src_port, dst_port, protocol = key
            duration = int(flow["last"] - flow["start"])
            bytes_kb = flow["bytes"] / 1024
            table.append([
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                protocol,
                flow["packets"],
                f"{bytes_kb:.2f}",
                duration
            ])

        table_str = tabulate(table, headers=headers, tablefmt="fancy_grid")
        if logger:
            logger.info("\n" + table_str)
        else:
            print(table_str)