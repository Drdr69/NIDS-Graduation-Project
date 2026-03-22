import os
import sys
import time
import pickle
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import threading
import warnings
import queue
import hashlib
import shap
import nips_mitigation
from collections import defaultdict

warnings.filterwarnings('ignore')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PAUSE_FILE = os.path.join(BASE_DIR, '.pause_monitor')

# Load ML components
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

OUTPUT_FILE = os.path.join(BASE_DIR, 'live_predictions.csv')

def init_csv():
    if not os.path.exists(OUTPUT_FILE):
        df = pd.DataFrame(columns=[
            'Flow ID', 'Timestamp', 'Source IP', 'Dest IP', 'Protocol',
            'Total Packets', 'Total Bytes', 'Flow Duration (s)', 'Packets/s', 'Bytes/s',
            'Prediction', 'Probability', 'Detection Engine', 'XAI Explanation', 'Mitigation Status'
        ])
        df.to_csv(OUTPUT_FILE, index=False)

active_flows = {}
flow_lock = threading.Lock()
write_queue = queue.Queue()
suspicious_ips = defaultdict(int)
NIPS_THRESHOLD = 3 # Block IP after 3 attacks

explainer = shap.TreeExplainer(model)

def is_paused():
    return os.path.exists(PAUSE_FILE)

def fast_path_signature_match(flow_data):
    pkts = flow_data['fwd_packets'] + flow_data['bwd_packets']
    dur = max(flow_data['last_time'] - flow_data['start_time'], 0.000001)
    rate = pkts / dur

    if rate > 10000:
        return True, "DDoS (Signature)"
    if flow_data['syn_flag'] == 1 and flow_data['ack_flag'] == 0 and flow_data['fin_flag'] == 0 and rate > 500:
        return True, "DoS Hulk (Signature)"
    if pkts <= 3 and dur < 0.1 and flow_data['fwd_length'] == 0:
        return True, "PortScan (Signature)"

    return False, None

def generate_xai_explanation(scaled_features, prediction):
    if prediction == 'BENIGN' or 'Signature' in prediction:
        return "N/A"
    try:
        shap_values = explainer.shap_values(scaled_features)
        pred_idx = encoder.transform([prediction])[0]
        class_shap_values = shap_values[pred_idx][0]
        feature_importance = pd.DataFrame({'Feature': FEATURES, 'Importance': class_shap_values})
        top_features = feature_importance.reindex(feature_importance.Importance.abs().sort_values(ascending=False).index).head(2)
        reasons = []
        for _, row in top_features.iterrows():
            direction = "high" if row['Importance'] > 0 else "low"
            reasons.append(f"{row['Feature']} was unusually {direction}")
        return " flagged because " + " and ".join(reasons)
    except Exception as e:
        return f"XAI Error: {str(e)[:50]}"

def packet_callback(pkt):
    # Only process packets if the dashboard has not paused the engine
    if is_paused():
        return

    if IP in pkt and (TCP in pkt or UDP in pkt):
        timestamp = float(pkt.time)
        length = len(pkt)

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

        with flow_lock:
            if flow_key not in active_flows and rev_flow_key not in active_flows:
                flow_id_str = f"{min(src_ip, dst_ip)}-{max(src_ip, dst_ip)}-{min(src_port, dst_port)}-{max(src_port, dst_port)}-{proto}"
                flow_id = hashlib.md5(flow_id_str.encode()).hexdigest()[:8]

                active_flows[flow_key] = {
                    'flow_id': flow_id,
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
                    'ack_flag': ack,
                    'is_finished': False,
                    'last_analyzed_packets': 0
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
                if fin or rst:
                    flow['is_finished'] = True
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
                if fin or rst:
                    flow['is_finished'] = True

def predict_flow(flow):
    duration_sec = max(flow['last_time'] - flow['start_time'], 0.000001)
    flow_duration_us = duration_sec * 1e6

    total_packets = flow['fwd_packets'] + flow['bwd_packets']
    total_bytes = flow['fwd_length'] + flow['bwd_length']

    is_match, sig_prediction = fast_path_signature_match(flow)
    if is_match:
        return sig_prediction, 1.0, duration_sec, total_packets, total_bytes, "Signature Fast-Path", "N/A"

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

    feature_df = pd.DataFrame([features], columns=FEATURES)
    scaled_features = scaler.transform(feature_df)

    pred_idx = model.predict(scaled_features)[0]
    prob = max(model.predict_proba(scaled_features)[0])
    prediction = encoder.inverse_transform([pred_idx])[0]

    xai_reason = "N/A"
    if prediction != 'BENIGN':
        xai_reason = generate_xai_explanation(scaled_features, prediction)

    return prediction, prob, duration_sec, total_packets, total_bytes, "Deep ML Model", xai_reason

def analyze_active_flows():
    FLOW_TIMEOUT = 120.0
    while True:
        time.sleep(2.0)

        if is_paused():
            continue

        flows_to_process = []
        current_time = time.time()

        with flow_lock:
            keys = list(active_flows.keys())
            for key in keys:
                flow_data = active_flows[key]
                inactive_time = current_time - flow_data['last_time']

                total_pkts = flow_data['fwd_packets'] + flow_data['bwd_packets']
                has_new_data = total_pkts > flow_data.get('last_analyzed_packets', 0)

                if has_new_data or flow_data['is_finished']:
                    snapshot = dict(flow_data)
                    flows_to_process.append((key, snapshot))
                    flow_data['last_analyzed_packets'] = total_pkts

                if flow_data['is_finished'] or inactive_time > FLOW_TIMEOUT:
                    del active_flows[key]

        for key, flow in flows_to_process:
            if flow['fwd_packets'] + flow['bwd_packets'] >= 1:
                try:
                    prediction, prob, duration_sec, total_packets, total_bytes, engine, xai = predict_flow(flow)
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    bytes_per_s = total_bytes / duration_sec
                    packets_per_s = total_packets / duration_sec

                    mitigation = "None"
                    if prediction != 'BENIGN':
                        suspicious_ips[key[0]] += 1
                        if suspicious_ips[key[0]] >= NIPS_THRESHOLD:
                            blocked = nips_mitigation.block_ip(key[0], reason=f"Detected {prediction} attack via {engine}")
                            mitigation = "System Firewall Block Applied" if blocked else "Failed to Block / Ignored Local"
                            suspicious_ips[key[0]] = 0
                        else:
                            mitigation = f"Monitoring ({suspicious_ips[key[0]]}/{NIPS_THRESHOLD} strikes)"

                    result = {
                        'Flow ID': flow['flow_id'],
                        'Timestamp': timestamp,
                        'Source IP': key[0],
                        'Dest IP': key[2],
                        'Protocol': key[4],
                        'Total Packets': total_packets,
                        'Total Bytes': total_bytes,
                        'Flow Duration (s)': f"{duration_sec:.2f}",
                        'Packets/s': f"{packets_per_s:.2f}",
                        'Bytes/s': f"{bytes_per_s:.2f}",
                        'Prediction': prediction,
                        'Probability': f"{prob:.4f}",
                        'Detection Engine': engine,
                        'XAI Explanation': xai,
                        'Mitigation Status': mitigation
                    }

                    write_queue.put(result)

                    if prediction != 'BENIGN' or prob < 0.90:
                        print(f"[{timestamp}] [ALERT] {key[0]} -> {key[2]} | {prediction} ({prob:.2f}) | {engine}")
                except Exception as e:
                    pass

def csv_writer():
    global OUTPUT_FILE
    header = ["Flow ID", "Timestamp", "Source IP", "Dest IP", "Protocol", "Total Packets", "Total Bytes", "Flow Duration (s)", "Packets/s", "Bytes/s", "Prediction", "Probability", "Detection Engine", "XAI Explanation", "Mitigation Status"]
    while True:
        try:
            results = []
            results.append(write_queue.get(timeout=5))

            while not write_queue.empty() and len(results) < 100:
                results.append(write_queue.get_nowait())

            df = pd.DataFrame(results)
            if not os.path.exists(OUTPUT_FILE):
                df.to_csv(OUTPUT_FILE, mode='w', header=header, index=False)
            else:
                df.to_csv(OUTPUT_FILE, mode='a', header=False, index=False)

            for _ in range(len(results)):
                write_queue.task_done()

        except queue.Empty:
            continue
        except Exception as e:
            print(f"CSV Writer Error: {e}")

def start_sniffer():
    print("Starting LIVE network monitor with Hybrid Engine & NIPS Active Mitigation...")
    init_csv()

    # Ensure pause file is cleared on startup so we start sniffing immediately
    if os.path.exists(PAUSE_FILE):
        try:
            os.remove(PAUSE_FILE)
        except:
            pass

    analyzer = threading.Thread(target=analyze_active_flows, daemon=True)
    analyzer.start()

    writer = threading.Thread(target=csv_writer, daemon=True)
    writer.start()

    try:
        print("Sniffing REAL network traffic. Press Ctrl+C to stop.")
        sniff(prn=packet_callback, store=False, filter="tcp or udp")
    except PermissionError:
        print("\n[CRITICAL ERROR] Permission denied! You must run this script as root/Administrator.")
        sys.exit(1)
    except OSError as e:
        print(f"\n[CRITICAL ERROR] OS Socket Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopping monitor gracefully...")
    except Exception as e:
        print(f"\nSniffing error: {e}")

if __name__ == "__main__":
    start_sniffer()
