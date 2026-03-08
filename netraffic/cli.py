import argparse
from netraffic.core.packet_capture import start_capture, analyze_pcap
from netraffic.utils.interfaces import select_interface


def main():
    parser = argparse.ArgumentParser(
        description="Netraffic CLI - Network Traffic Monitoring"
    )

    parser.add_argument(
        "-i", "--interface",
        help="Interface to capture packets from (for live capture)"
    )

    parser.add_argument(
        "-p", "--pcap-file",
        help="Path to a PCAP file for offline analysis"
    )

    args = parser.parse_args()

    if args.pcap_file:
        # Offline PCAP analysis mode
        analyze_pcap(args.pcap_file)
    else:
        # Live capture mode
        if args.interface:
            interface = args.interface
        else:
            interface = select_interface()
        start_capture(interface)


if __name__ == "__main__":
    main()