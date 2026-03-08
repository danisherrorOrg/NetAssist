from scapy.all import TCP, Raw


def parse_http_host(packet):

    if not packet.haslayer(TCP):
        return None

    if not packet.haslayer(Raw):
        return None

    payload = packet[Raw].load

    try:
        payload = payload.decode(errors="ignore")

        if "Host:" in payload:

            for line in payload.split("\r\n"):
                if line.startswith("Host:"):
                    return line.split("Host:")[1].strip()

    except:
        pass

    return None