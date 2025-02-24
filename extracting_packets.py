import pyshark
import time
import math
from prettytable import PrettyTable

INTERFACE = "en0"  # Change this to your network interface (e.g., "wlan0" for Wi-Fi, "en0" for macOS)

# Create table for displaying network flows
table = PrettyTable()
table.field_names = [
    "Src IP", "Src Port", "Dest IP", "Dest Port", "Protocol",
    "Bytes In", "Bytes Out", "Pkts In", "Pkts Out", "Entropy",
    "Total Entropy", "Mean IPT", "Start Time", "End Time", "Duration", "Label"
]

# Dictionary to store active flows
flows = {}

def calculate_entropy(data):
    """Calculate Shannon entropy of given data"""
    if not data:
        return 0
    entropy = 0
    length = len(data)
    freq = {byte: data.count(byte) / length for byte in set(data)}
    for f in freq.values():
        entropy -= f * math.log2(f)
    return entropy

def packet_handler(packet):
    """Processes each captured packet and updates flow statistics."""
    try:
        time_now = time.time()

        # Extract essential packet details
        src_ip = packet.ip.src if hasattr(packet, "ip") else "N/A"
        dest_ip = packet.ip.dst if hasattr(packet, "ip") else "N/A"
        src_port = packet[packet.transport_layer].srcport if hasattr(packet, "transport_layer") else "N/A"
        dest_port = packet[packet.transport_layer].dstport if hasattr(packet, "transport_layer") else "N/A"
        protocol = packet.transport_layer if hasattr(packet, "transport_layer") else "N/A"
        length = int(packet.length)
        payload = packet.get_raw_packet() if hasattr(packet, "get_raw_packet") else b''

        # Generate flow key (unique per session)
        flow_key = f"{src_ip}:{src_port} -> {dest_ip}:{dest_port} ({protocol})"

        if flow_key not in flows:
            # New flow detected
            flows[flow_key] = {
                "src_ip": src_ip,
                "src_port": src_port,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": protocol,
                "bytes_in": length,
                "bytes_out": 0,
                "num_pkts_in": 1,
                "num_pkts_out": 0,
                "entropy": calculate_entropy(payload),
                "total_entropy": calculate_entropy(payload) * len(payload),
                "timestamps": [time_now]
            }
        else:
            # Existing flow update
            flow = flows[flow_key]
            if src_ip == flow["src_ip"]:
                flow["bytes_in"] += length
                flow["num_pkts_in"] += 1
            else:
                flow["bytes_out"] += length
                flow["num_pkts_out"] += 1

            flow["entropy"] = (flow["entropy"] + calculate_entropy(payload)) / 2
            flow["total_entropy"] += calculate_entropy(payload) * len(payload)
            flow["timestamps"].append(time_now)

        # Update start and end times
        start_time = min(flows[flow_key]["timestamps"])
        end_time = max(flows[flow_key]["timestamps"])
        duration = round(end_time - start_time, 6)

        # Calculate mean inter-packet time
        if len(flows[flow_key]["timestamps"]) > 1:
            inter_packet_times = [
                flows[flow_key]["timestamps"][i] - flows[flow_key]["timestamps"][i - 1]
                for i in range(1, len(flows[flow_key]["timestamps"]))
            ]
            mean_ipt = sum(inter_packet_times) / len(inter_packet_times)
        else:
            mean_ipt = 0

        # Add updated flow details to table
        table.add_row([
            src_ip, src_port, dest_ip, dest_port, protocol,
            flows[flow_key]["bytes_in"], flows[flow_key]["bytes_out"],
            flows[flow_key]["num_pkts_in"], flows[flow_key]["num_pkts_out"],
            round(flows[flow_key]["entropy"], 2), round(flows[flow_key]["total_entropy"], 2),
            round(mean_ipt, 6), round(start_time, 2), round(end_time, 2), duration, "Benign"
        ])

        # Print updated table
        print(table)

    except Exception as e:
        print(f"Error processing packet: {e}")

# Start live packet capture
print(f"🚀 Capturing network flows on {INTERFACE}... Press Ctrl+C to stop.")

try:
    capture = pyshark.LiveCapture(interface=INTERFACE, use_json=True, include_raw=True)
    capture.apply_on_packets(packet_handler, packet_count=20)  # Capture 20 packets
except KeyboardInterrupt:
    print("\n🛑 Capture stopped.")
except Exception as e:
    print(f"Error starting capture: {e}")
