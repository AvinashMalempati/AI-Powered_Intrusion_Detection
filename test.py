import pyshark
import pandas as pd
from statistics import mean, stdev

# Configurable Variables
INTERFACE = 'en0'  # Set your network interface
PACKET_COUNT = 50  # The number of packets to capture
OUTPUT_CSV = 'packet_features.csv'  # The output file with extracted features for ML


# Function to extract detailed flow-level features from captured packets
def extract_flow_features(packets):
    """
    Extracts required features for ML model prediction from a packet flow.
    Args:
        packets (list): A list of packets captured in the flow.
    Returns:
        dict: Extracted features.
    """
    try:
        # Initialize forward/backward packet details
        fwd_lengths = []
        bwd_lengths = []
        fwd_iat = []
        bwd_iat = []
        total_duration = 0
        flow_start_time = None
        previous_packet_time = None

        # Initialize the feature dictionary
        features = {
            'Total Fwd Packets': 0,
            'Total Backward Packets': 0,
            'Fwd Packets Length Total': 0,
            'Bwd Packets Length Total': 0,
            'Fwd IAT Tot': 0,
            'Bwd IAT Tot': 0,
            'Fwd Pkt Len Max': 0,
            'Fwd Pkt Len Min': 0,
            'Fwd Pkt Len Mean': 0,
            'Fwd Pkt Len Std': 0,
            'Bwd Pkt Len Max': 0,
            'Bwd Pkt Len Min': 0,
            'Bwd Pkt Len Mean': 0,
            'Bwd Pkt Len Std': 0,
            'Flow Bytes/s': 0,
            'Flow Packets/s': 0,
            'Pkt Size Avg': 0,
        }

        for packet in packets:
            # Check if the packet contains the IP layer
            if not hasattr(packet, 'ip'):
                continue  # Skip packets without an IP layer

            # Extract packet details
            src_ip = getattr(packet.ip, 'src', None)
            dst_ip = getattr(packet.ip, 'dst', None)
            length = int(packet.length)
            timestamp = packet.sniff_time

            if flow_start_time is None:
                flow_start_time = timestamp  # Mark the start of the flow

            # Determine packet direction and categorize into forward/backward
            if src_ip == '192.168.1.100':  # Replace with your actual local IP
                is_forward = True
            else:
                is_forward = False

            # Forward packet processing
            if is_forward:
                fwd_lengths.append(length)
                features['Total Fwd Packets'] += 1
                features['Fwd Packets Length Total'] += length
                if previous_packet_time:
                    fwd_iat.append((timestamp - previous_packet_time).total_seconds())

            # Backward packet processing
            else:
                bwd_lengths.append(length)
                features['Total Backward Packets'] += 1
                features['Bwd Packets Length Total'] += length
                if previous_packet_time:
                    bwd_iat.append((timestamp - previous_packet_time).total_seconds())

            previous_packet_time = timestamp  # Update previous packet time

        # Calculate flow duration
        if flow_start_time and previous_packet_time:
            total_duration = (previous_packet_time - flow_start_time).total_seconds()

        # Calculate Forward Packet Length Statistics
        if fwd_lengths:
            features['Fwd Pkt Len Max'] = max(fwd_lengths)
            features['Fwd Pkt Len Min'] = min(fwd_lengths)
            features['Fwd Pkt Len Mean'] = mean(fwd_lengths)
            features['Fwd Pkt Len Std'] = stdev(fwd_lengths) if len(fwd_lengths) > 1 else 0

        # Calculate Backward Packet Length Statistics
        if bwd_lengths:
            features['Bwd Pkt Len Max'] = max(bwd_lengths)
            features['Bwd Pkt Len Min'] = min(bwd_lengths)
            features['Bwd Pkt Len Mean'] = mean(bwd_lengths)
            features['Bwd Pkt Len Std'] = stdev(bwd_lengths) if len(bwd_lengths) > 1 else 0

        # Calculate Inter-Arrival Times
        features['Fwd IAT Tot'] = sum(fwd_iat)
        features['Bwd IAT Tot'] = sum(bwd_iat)

        # Calculate flow rates
        if total_duration > 0:
            features['Flow Bytes/s'] = (
                                               features['Fwd Packets Length Total'] + features[
                                           'Bwd Packets Length Total']
                                       ) / total_duration
            features['Flow Packets/s'] = (
                                                 features['Total Fwd Packets'] + features['Total Backward Packets']
                                         ) / total_duration

        # Packet size average (if total packets exist)
        total_packet_count = features['Total Fwd Packets'] + features['Total Backward Packets']
        total_length = features['Fwd Packets Length Total'] + features['Bwd Packets Length Total']
        features['Pkt Size Avg'] = total_length / total_packet_count if total_packet_count > 0 else 0

        return features

    except Exception as e:
        print(f"Error while extracting flow features: {e}")
        return {}


# Main function
def main():
    print(f"🚀 Capturing {PACKET_COUNT} packets on interface '{INTERFACE}'...")

    # Create the collector for packet capture
    capture = pyshark.LiveCapture(interface=INTERFACE)
    flows = []  # Placeholder for flows (in a real scenario, you'll combine related packets into flows)
    processed_features = []

    try:
        # Collect and process packets
        for packet in capture.sniff_continuously(packet_count=PACKET_COUNT):
            flows.append(packet)  # Append all packets to the flows list; improve for real flow-based logic

        # Extract features for each packet or flow
        processed_features.append(extract_flow_features(flows))

        # Save extracted features to CSV
        if processed_features:
            df = pd.DataFrame(processed_features)  # Convert to DataFrame
            print(f"💾 Saving extracted features to '{OUTPUT_CSV}'...")
            df.to_csv(OUTPUT_CSV, index=False)
            print("✅ Features saved successfully!")
        else:
            print("⚠️ No valid packets were captured.")

    except KeyboardInterrupt:
        print("\n🛑 Capture interrupted.")
    except Exception as e:
        print(f"An error occurred: {e}")

    print("\nDone capturing packets.")


if __name__ == "__main__":
    main()
