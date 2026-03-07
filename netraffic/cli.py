import argparse

from netraffic.core.packet_capture import start_capture
from netraffic.utils.interfaces import select_interface


def main():

    parser = argparse.ArgumentParser(
        description="Netraffic CLI - Network Traffic Monitoring"
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Interface to capture packets from"
    )

    args = parser.parse_args()

    if args.interface:
        interface = args.interface
    else:
        interface = select_interface()

    start_capture(interface)


if __name__ == "__main__":
    main()