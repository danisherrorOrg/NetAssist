from scapy.layers.dns import DNS, DNSQR, DNSRR


def parse_dns(packet):
    """
    Detect DNS query or response
    """

    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]

    # DNS Query
    if dns.qr == 0:
        if dns.qd:
            domain = dns.qd.qname.decode(errors="ignore").rstrip(".")
            return ("QUERY", domain)

    # DNS Response
    if dns.qr == 1:
        if dns.an:
            domain = dns.qd.qname.decode(errors="ignore").rstrip(".")

            answers = []

            for i in range(dns.ancount):
                rr = dns.an[i]
                if isinstance(rr, DNSRR):
                    answers.append(rr.rdata)

            return ("RESPONSE", domain, answers)

    return None