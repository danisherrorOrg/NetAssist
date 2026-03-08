import time

flows = {}


class FlowTracker:

    def update(self, src_ip, dst_ip, src_port, dst_port, protocol, pkt_len):

        key = (src_ip, dst_ip, src_port, dst_port, protocol)

        now = time.time()

        if key not in flows:

            flows[key] = {
                "packets": 1,
                "bytes": pkt_len,
                "start": now,
                "last": now
            }

        else:

            flow = flows[key]

            flow["packets"] += 1
            flow["bytes"] += pkt_len
            flow["last"] = now

    def print_active_flows(self, logger):

        now = time.time()

        for key, flow in flows.items():

            src_ip, dst_ip, src_port, dst_port, protocol = key

            duration = int(flow["last"] - flow["start"])

            bytes_kb = flow["bytes"] / 1024

            logger.info(
                f"FLOW {src_ip}:{src_port} → {dst_ip}:{dst_port} {protocol} "
                f"| Packets: {flow['packets']} "
                f"| Bytes: {bytes_kb:.2f} KB "
                f"| Duration: {duration}s"
            )