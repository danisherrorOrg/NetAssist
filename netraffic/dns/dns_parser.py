from scapy.layers.dns import DNS


def clean(value):
    if isinstance(value, bytes):
        return value.decode(errors="ignore").rstrip(".")
    return str(value)


def parse_dns(packet):

    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]

    # DNS Query
    if dns.qr == 0 and dns.qd:
        domain = clean(dns.qd.qname)
        return ("QUERY", domain)

    # DNS Response
    if dns.qr == 1 and dns.an:

        domain = clean(dns.qd.qname)

        answers = set()

        for i in range(dns.ancount):

            rr = dns.an[i]

            try:
                answers.add(clean(rr.rdata))
            except Exception:
                pass

        return ("RESPONSE", domain, list(answers))

    return None