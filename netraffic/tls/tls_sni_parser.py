from scapy.all import TCP, Raw


def parse_tls_sni(packet):

    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return None

    payload = bytes(packet[Raw].load)

    try:

        # TLS record type must be handshake (22)
        if payload[0] != 22:
            return None

        # TLS handshake type must be ClientHello (1)
        if payload[5] != 1:
            return None

        data = payload

        # Look for SNI extension
        sni_marker = b"\x00\x00"
        idx = data.find(sni_marker)

        if idx == -1:
            return None

        name_len = int.from_bytes(data[idx+7:idx+9], "big")
        hostname = data[idx+9:idx+9+name_len].decode(errors="ignore")

        # Validate hostname
        if "." not in hostname:
            return None

        if len(hostname) > 255:
            return None

        return hostname

    except:
        return None