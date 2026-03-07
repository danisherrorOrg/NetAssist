from scapy.all import DNS

# Store already seen queries
seen_queries = set()


def parse_dns(packet):

    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]

    # DNS QUERY
    if dns.qr == 0 and dns.qd:

        domain = dns.qd.qname.decode(errors="ignore").rstrip(".")

        if domain in seen_queries:
            return None

        seen_queries.add(domain)

        return ("QUERY", domain)

    # DNS RESPONSE
    elif dns.qr == 1:

        ips = []

        for i in range(dns.ancount):

            ans = dns.an[i]

            if ans.type == 1:  # A record
                ips.append(ans.rdata)

            elif ans.type == 28:  # AAAA record
                ips.append(ans.rdata)

        if dns.qd:
            domain = dns.qd.qname.decode(errors="ignore").rstrip(".")
        else:
            domain = "unknown"

        if ips:
            return ("RESPONSE", domain, ips)

    return None