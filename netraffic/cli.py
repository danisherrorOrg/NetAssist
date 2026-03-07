import argparse


def main():
    parser = argparse.ArgumentParser(
        description="Netraffic CLI - Network Traffic Monitoring Tool"
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to monitor",
        default=None
    )

    args = parser.parse_args()

    print("Netraffic CLI started")
    print("Selected Interface:", args.interface)


if __name__ == "__main__":
    main()