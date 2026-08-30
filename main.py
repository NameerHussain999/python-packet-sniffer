
import argparse

from config import LOG_FILE, ALERT_LOG_FILE
from logger import setup_log_file
from sniffer import start_sniffing



def get_arguments():
    parser = argparse.ArgumentParser(
        description = "Live Network Packet Sniffer and Analyzer"
    )

    parser.add_argument(
        "--protocol",
        choices = ["ALL", "TCP", "UDP", "ICMP"],
        default = "ALL",
        help = "Filter packets by protocol"
    )

    return parser.parse_args()


def main():
    setup_log_file()

    args = get_arguments()
    selected_protocol = args.protocol


    print("=" * 80)
    print("PACKET SNIFFER")
    print("=" * 80)
    print(f"\nProtocol filter: {selected_protocol}")
    print(f"Packet log: {LOG_FILE}")
    print(f"Alert log: {ALERT_LOG_FILE}")
    print("Port scan detection: Enabled")
    print("SYN activity detection: Enabled")
    print("Capture started")
    print("Press Ctrl+C to stop")
    print("=" * 80) 

    start_sniffing(selected_protocol)


if __name__ == "__main__":
    main()










