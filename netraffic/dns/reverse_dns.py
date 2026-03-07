import socket

cache = {}

def reverse_lookup(ip):

    if ip in cache:
        return cache[ip]

    try:
        domain = socket.gethostbyaddr(ip)[0]
        cache[ip] = domain
        return domain

    except Exception:
        cache[ip] = None
        return None