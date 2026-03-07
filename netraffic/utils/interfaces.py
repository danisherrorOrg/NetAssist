import psutil


def list_interfaces():
    """
    Returns available network interfaces
    """
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())


def print_interfaces():
    """
    Print interfaces in numbered format
    """
    interfaces = list_interfaces()

    print("\nAvailable Network Interfaces:\n")

    for i, iface in enumerate(interfaces, start=1):
        print(f"{i}. {iface}")

    return interfaces


def select_interface():
    """
    Let user select interface from CLI
    """
    interfaces = print_interfaces()

    choice = int(input("\nSelect interface number: "))

    return interfaces[choice - 1]