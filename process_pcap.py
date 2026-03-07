import sys
import os
import pickle
import pandas as pd
from scapy.all import rdpcap, IP, TCP
from datetime import datetime
import warnings

warnings.filterwarnings('ignore')

# Load the trained model and preprocessing tools
try:
    with open('best_model.pkl', 'rb') as f:
        model = pickle.load(f)
    with open('scaler.pkl', 'rb') as f:
        scaler = pickle.load(f)
    with open('label_encoder.pkl', 'rb') as f:
        encoder = pickle.load(f)
    with open('feature_names.txt', 'r') as f:
        FEATURES = f.read().split(',')
except FileNotFoundError:
    print("Model files not found. Please run train_models.py first.")
    sys.exit(1)

def process_pcap_file(pcap_path, output_csv):
    print(f"Loading {pcap_path} for offline processing...")

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Failed to read pcap: {e}")
        return

    active_flows = {}
    print(f"Loaded {len(packets)} packets. Analyzing flows...")

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            proto = "TCP"

            flow_key = (src_ip, src_port, dst_ip, dst_port, proto)
            rev_flow_key = (dst_ip, dst_port, src_ip, src_port, proto)

            # Scapy time is a float timestamp
            timestamp = float(pkt.time)
            length = len(pkt)

            if flow_key not in active_flows and rev_flow_key not in active_flows:
                active_flows[flow_key] = {
                    'start_time': timestamp,
                    'last_time': timestamp,
                    'fwd_packets': 1,
                    'bwd_packets': 0,
                    'fwd_length': length,
                    'bwd_length': 0,
                    'fwd_max': length,
                    'fwd_min': length,
                    'bwd_max': 0,
                    'bwd_min': 0,
                    'fin_flag': pkt[TCP].flags.F,
                    'syn_flag': pkt[TCP].flags.S,
                    'rst_flag': pkt[TCP].flags.R,
                    'psh_flag': pkt[TCP].flags.P,
                    'ack_flag': pkt[TCP].flags.A
                }
            elif flow_key in active_flows:
                flow = active_flows[flow_key]
                flow['fwd_packets'] += 1
                flow['fwd_length'] += length
                flow['fwd_max'] = max(flow['fwd_max'], length)
                flow['fwd_min'] = min(flow['fwd_min'], length)
                flow['last_time'] = timestamp
                flow['fin_flag'] = max(flow['fin_flag'], pkt[TCP].flags.F)
                flow['syn_flag'] = max(flow['syn_flag'], pkt[TCP].flags.S)
            elif rev_flow_key in active_flows:
                flow = active_flows[rev_flow_key]
                flow['bwd_packets'] += 1
                flow['bwd_length'] += length
                if flow['bwd_max'] == 0:
                    flow['bwd_max'] = length
                    flow['bwd_min'] = length
                else:
                    flow['bwd_max'] = max(flow['bwd_max'], length)
                    flow['bwd_min'] = min(flow['bwd_min'], length)
                flow['last_time'] = timestamp

    results = []

    for key, flow in active_flows.items():
        duration = flow['last_time'] - flow['start_time']
        flow_duration = duration * 1e6 # microseconds
        total_packets = flow['fwd_packets'] + flow['bwd_packets']
        total_bytes = flow['fwd_length'] + flow['bwd_length']

        features = [
            flow_duration,
            flow['fwd_packets'],
            flow['bwd_packets'],
            flow['fwd_length'],
            flow['bwd_length'],
            flow['fwd_max'],
            flow['fwd_min'],
            flow['bwd_max'],
            flow['bwd_min'],
            (total_bytes / duration) if duration > 0 else 0,
            (total_packets / duration) if duration > 0 else 0,
            flow['fin_flag'],
            flow['syn_flag'],
            flow['rst_flag'],
            flow['psh_flag'],
            flow['ack_flag']
        ]

        feature_df = pd.DataFrame([features], columns=FEATURES)
        scaled_features = scaler.transform(feature_df)

        pred_idx = model.predict(scaled_features)[0]
        prob = max(model.predict_proba(scaled_features)[0])
        prediction = encoder.inverse_transform([pred_idx])[0]

        dt_time = datetime.fromtimestamp(flow['last_time']).strftime('%Y-%m-%d %H:%M:%S')

        results.append({
            'Timestamp': dt_time,
            'Source IP': key[0],
            'Dest IP': key[2],
            'Protocol': key[4],
            'Prediction': prediction,
            'Probability': f"{prob:.2f}"
        })

    if results:
        df = pd.DataFrame(results)
        # If the file doesn't exist, create it with headers, otherwise append without headers
        if not os.path.exists(output_csv):
            df.to_csv(output_csv, index=False)
        else:
            df.to_csv(output_csv, mode='a', header=False, index=False)

        print(f"Successfully processed {len(results)} flows and saved to {output_csv}.")
    else:
        print("No TCP flows found in the PCAP file.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python process_pcap.py <path_to_pcap> [output_csv]")
        sys.exit(1)

    pcap = sys.argv[1]
    out_csv = sys.argv[2] if len(sys.argv) > 2 else 'live_predictions.csv'
    process_pcap_file(pcap, out_csv)
