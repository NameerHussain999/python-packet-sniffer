import time

from config import(
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW,
    SYN_THRESHOLD,
    SYN_WINDOW

)

from logger import log_alert

syn_activity = {}

port_activity = {}

def detect_port_scan(src_ip, dst_ip, dst_port):
    if dst_port == "-":
        return

    current_time = time.time()

    key = (src_ip, dst_ip)

    if key not in port_activity:
        port_activity[key] = []

    port_activity[key].append(
        (current_time, dst_port)
    )

    port_activity[key] = [
        (timestamp, port)
        for timestamp, port in port_activity[key]
        if current_time - timestamp <= PORT_SCAN_WINDOW
    ]

    unique_ports = {
        port
        for timestamp, port in port_activity[key]
    }

    if len(unique_ports) >= PORT_SCAN_THRESHOLD:
        print("\n" + "!" * 80)
        print("WARNING: POSSIBLE PORT SCAN")
        print(f"Source IP:      {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Unique ports:   {len(unique_ports)}")
        print(f"Time Window:    {PORT_SCAN_WINDOW} seconds")
        print("!" * 80 + "\n")

        log_alert(
            "POSSIBLE POrT SCAN",
            {
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Unique Ports": len(unique_ports),
                "Time Window": f"{PORT_SCAN_WINDOW} seconds"
            }
        )

        port_activity[key] = []

def detect_syn_activity(src_ip, flags):
    if "S" not in flags or "A" in flags:
        return

    current_time = time.time()

    if src_ip not in syn_activity:
        syn_activity[src_ip] = []

    syn_activity[src_ip].append(current_time)


    syn_activity[src_ip] = [
        timestamp
        for timestamp in syn_activity[src_ip]
        if current_time - timestamp <= SYN_WINDOW
    ]

    syn_count = len(syn_activity[src_ip])

    if syn_count >= SYN_THRESHOLD:
        print("\n" + "!" * 80)
        print("WARNING HIGH SYN ACTIVITY")
        print(f"Source IP:  {src_ip}")
        print(f"SYN packets:{syn_count}")
        print(f"Time window:{SYN_WINDOW} seconds")
        print("!" * 80 + "\n")

        log_alert(
            "HIGH SYN ACTIVITY",
            {
                "Source IP": src_ip,
                "SYN Packets": syn_count,
                "Time Window": f"{SYN_WINDOW} seconds"
            }
        )

        syn_activity[src_ip] = []