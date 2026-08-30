from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

from detector import detect_port_scan, detect_syn_activity
from logger import log_packet, get_alert_count

packet_counts = {
    "TOTAL": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "OTHER": 0
}

def packet_callback(packet, selected_protocol):

    if IP not in packet:
        return
    

    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_size = len(packet)


    protocol = "OTHER"
    src_port = "-"
    dst_port = "-"
    flags = "-"


    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = str(packet[TCP].flags)

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport


    elif ICMP in packet:
        protocol = "ICMP"

    if selected_protocol != "ALL" and protocol != selected_protocol:
        return

    packet_counts["TOTAL"] += 1
    packet_counts[protocol] += 1



    print(
        f"[{timestamp}]"
        f"{protocol:<5}"
        f"{src_ip}:{src_port} ->"
        f"{dst_ip}:{dst_port} |"
        f"Size: {packet_size} bytes |"
        f"Flags: {flags}"
    )

    log_packet(
        timestamp,
        protocol,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        packet_size,
        flags
    )

    if protocol in ["TCP", "UDP"]:
        detect_port_scan(
            src_ip,
            dst_ip,
            dst_port
        )

    if protocol == "TCP":
        detect_syn_activity(
            src_ip,
            flags
        )





def show_statistics():
    print("\n" + "=" * 80)
    print("CAPTURE STATISTICS")
    print("=" * 80)
    print(f"Total packets:   {packet_counts['TOTAL']}")
    print(f"TCP packets:     {packet_counts['TCP']}")
    print(f"UDP packets:     {packet_counts['UDP']}")
    print(f"ICMP packets:    {packet_counts['ICMP']}")
    print(f"Other packets:   {packet_counts['OTHER']}")
    print(f"Alerts:          {get_alert_count()}")
    print("=" * 80)

def start_sniffing(selected_protocol):
    try:
        sniff(
                prn = lambda packet: packet_callback(
                    packet,
                    selected_protocol
                ),
                store = False
            )
    

    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    

    finally:
        show_statistics()
    
