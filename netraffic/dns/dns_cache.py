ip_to_domain = {}

def store_mapping(domain, ips):
    for ip in ips:
        ip_to_domain[ip] = domain


def resolve_ip(ip):
    return ip_to_domain.get(ip)