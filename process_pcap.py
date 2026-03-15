import sys
import hashlib
import os
import pickle
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from datetime import datetime


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
    duration_sec = max(flow['last_time'] - flow['start_time'], 0.000001)
    flow_duration_us = duration_sec * 1e6

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
        (total_bytes / duration_sec),
        (total_packets / duration_sec),
        flow['fin_flag'],
        flow['syn_flag'],
        flow['rst_flag'],
        flow['psh_flag'],
        flow['ack_flag']
    ]
    return features, duration_sec, total_packets, total_bytes

def predict_flows(flows_dict):
    results = []
    if not flows_dict:
        return results

    features_list = []
    keys_list = []
    meta_list = []

    for key, flow in flows_dict.items():
        feats, duration_sec, total_packets, total_bytes = extract_features_from_flow(flow)
        features_list.append(feats)
        keys_list.append((key, flow['last_time']))
        meta_list.append((duration_sec, total_packets, total_bytes))

    feature_df = pd.DataFrame(features_list, columns=FEATURES)
    scaled_features = scaler.transform(feature_df)

    predictions_idx = model.predict(scaled_features)
    probabilities = model.predict_proba(scaled_features).max(axis=1)
    predictions = encoder.inverse_transform(predictions_idx)

    for i, (key, last_time) in enumerate(keys_list):
        dt_time = datetime.fromtimestamp(last_time).strftime('%Y-%m-%d %H:%M:%S')
        duration_sec, total_packets, total_bytes = meta_list[i]

        bytes_per_s = total_bytes / duration_sec
        packets_per_s = total_packets / duration_sec

        src_ip, src_port, dst_ip, dst_port, proto = key
        flow_id_str = f"{min(src_ip, dst_ip)}-{max(src_ip, dst_ip)}-{min(src_port, dst_port)}-{max(src_port, dst_port)}-{proto}"
        flow_id = hashlib.md5(flow_id_str.encode()).hexdigest()[:8]

        results.append({
            'Flow ID': flow_id,
            'Timestamp': dt_time,
            'Source IP': src_ip,
            'Dest IP': dst_ip,
            'Protocol': proto,
            'Total Packets': total_packets,
            'Total Bytes': total_bytes,
            'Flow Duration (s)': f"{duration_sec:.2f}",
            'Packets/s': f"{packets_per_s:.2f}",
            'Bytes/s': f"{bytes_per_s:.2f}",
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

            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                proto = "TCP"
                fin = pkt[TCP].flags.F
                syn = pkt[TCP].flags.S
                rst = pkt[TCP].flags.R
                psh = pkt[TCP].flags.P
                ack = pkt[TCP].flags.A
            else:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                proto = "UDP"
                fin = syn = rst = psh = ack = 0

            flow_key = (src_ip, src_port, dst_ip, dst_port, proto)
            rev_flow_key = (dst_ip, dst_port, src_ip, src_port, proto)

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

    if not os.path.isabs(out_csv) and os.path.dirname(out_csv) == '':
        out_csv = os.path.join(BASE_DIR, out_csv)

    process_pcap_file(pcap, out_csv)
