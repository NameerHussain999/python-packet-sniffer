from datetime import datetime
import csv
import os

from config import LOG_FILE, ALERT_LOG_FILE

alert_count = 0

def log_alert(alert_type, details):

    global alert_count
    alert_count += 1


    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(ALERT_LOG_FILE, "a") as file:
        file.write("=" * 60 + "\n")
        file.write(f"Timestamp: {timestamp}\n")
        file.write(f"Alert:     {alert_type}\n")

        for key, value in details.items():
            file.write(f"{key}: {value}\n")

        file.write("=" * 60 + "\n\n")


def setup_log_file():
    os.makedirs("logs", exist_ok = True)

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline = "") as file:
            writer = csv.writer(file)

            writer.writerow([
                "Timestamp",
                "Protocol",
                "Source IP",
                "Source Port",
                "Destination IP",
                "Destination Port",
                "Packet Size",
                "TCP Flags"
            ])

    if not os.path.exists(ALERT_LOG_FILE):
        with open(ALERT_LOG_FILE, "w") as file:
            file.write("PACKET SNIFFER SECURITY ALERT LOG\n")
            file.write("=" * 60 + "\n\n")

def log_packet(
        timestamp,
        protocol,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        packet_size,
        flags
):
    with open(LOG_FILE, "a", newline = "") as file:
        writer = csv.writer(file)

        writer.writerow([
            timestamp,
            protocol,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            packet_size,
            flags
        ])

def get_alert_count():
    return alert_count