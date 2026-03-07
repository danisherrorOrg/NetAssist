from scapy.layers.inet import IP_PROTOS


def get_protocol_name(packet):

    if packet.haslayer("IP"):

        proto_number = packet["IP"].proto

        try:
            protocol = IP_PROTOS[proto_number]
        except KeyError:
            protocol = f"PROTO_{proto_number}"

        return protocol.upper()

    elif packet.haslayer("ARP"):
        return "ARP"

    return "UNKNOWN"