import sys
import os
import pickle
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from datetime import datetime
import warnings

warnings.filterwarnings('ignore')

# We load the files assuming they are in the same directory as process_pcap.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    with open(os.path.join(BASE_DIR, 'best_model.pkl'), 'rb') as f:
        model = pickle.load(f)
    with open(os.path.join(BASE_DIR, 'scaler.pkl'), 'rb') as f:
        scaler = pickle.load(f)
    with open(os.path.join(BASE_DIR, 'label_encoder.pkl'), 'rb') as f:
        encoder = pickle.load(f)
    with open(os.path.join(BASE_DIR, 'feature_names.txt'), 'r') as f:
        FEATURES = f.read().split(',')
except FileNotFoundError as e:
    print(f"Model files not found. Error: {e}")
    sys.exit(1)

def extract_features_from_flow(flow):
    duration_sec = max(flow['last_time'] - flow['start_time'], 0.000001) # Minimum 1us to avoid division by zero
    flow_duration_us = duration_sec * 1e6 # microseconds

    total_packets = flow['fwd_packets'] + flow['bwd_packets']
    total_bytes = flow['fwd_length'] + flow['bwd_length']

    features = [
        flow_duration_us,
        flow['fwd_packets'],
        flow['bwd_packets'],
        flow['fwd_length'],
        flow['bwd_length'],
        flow['fwd_max'],
        flow['fwd_min'],
        flow['bwd_max'],
        flow['bwd_min'],
        (total_bytes / duration_sec),   # Flow Bytes/s
        (total_packets / duration_sec), # Flow Packets/s
        flow['fin_flag'],
        flow['syn_flag'],
        flow['rst_flag'],
        flow['psh_flag'],
        flow['ack_flag']
    ]
    return features

def predict_flows(flows_dict):
    results = []

    if not flows_dict:
        return results

    features_list = []
    keys_list = []

    for key, flow in flows_dict.items():
        feats = extract_features_from_flow(flow)
        features_list.append(feats)
        keys_list.append((key, flow['last_time']))

    feature_df = pd.DataFrame(features_list, columns=FEATURES)
    scaled_features = scaler.transform(feature_df)

    # Predict all at once for speed
    predictions_idx = model.predict(scaled_features)
    probabilities = model.predict_proba(scaled_features).max(axis=1)
    predictions = encoder.inverse_transform(predictions_idx)

    for i, (key, last_time) in enumerate(keys_list):
        dt_time = datetime.fromtimestamp(last_time).strftime('%Y-%m-%d %H:%M:%S')
        results.append({
            'Timestamp': dt_time,
            'Source IP': key[0],
            'Dest IP': key[2],
            'Protocol': key[4],
            'Prediction': predictions[i],
            'Probability': f"{probabilities[i]:.4f}"
        })

    return results

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
        if IP in pkt and (TCP in pkt or UDP in pkt):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Extract ports and protocol
            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                proto = "TCP"
                # Extract flags if TCP
                fin = pkt[TCP].flags.F
                syn = pkt[TCP].flags.S
                rst = pkt[TCP].flags.R
                psh = pkt[TCP].flags.P
                ack = pkt[TCP].flags.A
            else: # UDP
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                proto = "UDP"
                fin = syn = rst = psh = ack = 0

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
                    'fin_flag': fin,
                    'syn_flag': syn,
                    'rst_flag': rst,
                    'psh_flag': psh,
                    'ack_flag': ack
                }
            elif flow_key in active_flows:
                flow = active_flows[flow_key]
                flow['fwd_packets'] += 1
                flow['fwd_length'] += length
                flow['fwd_max'] = max(flow['fwd_max'], length)
                flow['fwd_min'] = min(flow['fwd_min'], length)
                flow['last_time'] = timestamp
                flow['fin_flag'] = max(flow['fin_flag'], fin)
                flow['syn_flag'] = max(flow['syn_flag'], syn)
                flow['rst_flag'] = max(flow['rst_flag'], rst)
                flow['psh_flag'] = max(flow['psh_flag'], psh)
                flow['ack_flag'] = max(flow['ack_flag'], ack)
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

    results = predict_flows(active_flows)

    if results:
        df = pd.DataFrame(results)
        # If the file doesn't exist, create it with headers, otherwise append without headers
        if not os.path.exists(output_csv):
            df.to_csv(output_csv, index=False)
        else:
            df.to_csv(output_csv, mode='a', header=False, index=False)

        print(f"Successfully processed {len(results)} flows and saved to {output_csv}.")
    else:
        print("No TCP/UDP flows found in the PCAP file.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python process_pcap.py <path_to_pcap> [output_csv]")
        sys.exit(1)

    pcap = sys.argv[1]
    out_csv = sys.argv[2] if len(sys.argv) > 2 else 'live_predictions.csv'

    # Make sure output path is relative to the script directory if it's just a filename
    if not os.path.isabs(out_csv) and os.path.dirname(out_csv) == '':
        out_csv = os.path.join(BASE_DIR, out_csv)

    process_pcap_file(pcap, out_csv)
