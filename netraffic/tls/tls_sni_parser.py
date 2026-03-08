from scapy.all import Raw, TCP

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
        # SNI extension type = 0x00 0x00
        sni_idx = data.find(b'\x00\x00')
        if sni_idx == -1:
            return None

        # Extract length of hostname
        if sni_idx + 9 >= len(data):
            return None
        name_len = int.from_bytes(data[sni_idx+7:sni_idx+9], "big")
        if sni_idx + 9 + name_len > len(data):
            return None

        hostname_bytes = data[sni_idx+9:sni_idx+9+name_len]
        # decode safely, ignore errors
        hostname = hostname_bytes.decode('ascii', errors='ignore').strip()

        # Only return if it looks like a domain
        if '.' not in hostname or len(hostname) > 255:
            return None

        return hostname.lower()

    except Exception:
        return None