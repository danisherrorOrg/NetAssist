import socket
import ipaddress

dns_cache = {}

def reverse_lookup(ip):

    # Skip private, loopback, multicast
    try:
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
            return None

    except Exception:
        return None

    if ip in dns_cache:
        return dns_cache[ip]

    try:
        domain = socket.gethostbyaddr(ip)[0]
        if domain.endswith("in-addr.arpa"):
            return None
        dns_cache[ip] = domain
        return domain

    except Exception:
        dns_cache[ip] = None
        return None