import os
import sys
import time
import pickle
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import threading
import queue
import hashlib


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

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
    """ Initialize the output CSV file with appropriate headers if it doesn't exist. """
    if not os.path.exists(OUTPUT_FILE):
        df = pd.DataFrame(columns=[
            'Flow ID', 'Timestamp', 'Source IP', 'Dest IP', 'Protocol',
            'Total Packets', 'Total Bytes', 'Flow Duration (s)', 'Packets/s', 'Bytes/s',
            'Prediction', 'Probability'
        ])
        df.to_csv(OUTPUT_FILE, index=False)

active_flows = {}
flow_lock = threading.Lock()
write_queue = queue.Queue()

def packet_callback(pkt):
    """
    Called by scapy for each sniffed packet.
    Extracts relevant bidirectional features and updates the ongoing active_flows dictionary.
    """
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
        else: # UDP
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto = "UDP"
            fin = syn = rst = psh = ack = 0

        flow_key = (src_ip, src_port, dst_ip, dst_port, proto)
        rev_flow_key = (dst_ip, dst_port, src_ip, src_port, proto)

        with flow_lock:
            # If neither the forward nor reverse flow exists, initialize a new flow record
            if flow_key not in active_flows and rev_flow_key not in active_flows:
                # Generate a unique Flow ID based on the bidirectional 5-tuple
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
                # Update forward direction metrics
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
                # Update backward direction metrics
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
    """ Format features exactly as CICIDS2017 pipeline expects, scale them, and classify via ML. """
    duration_sec = max(flow['last_time'] - flow['start_time'], 0.000001) # Minimum 1us to avoid division by zero
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

    feature_df = pd.DataFrame([features], columns=FEATURES)
    scaled_features = scaler.transform(feature_df)

    pred_idx = model.predict(scaled_features)[0]
    prob = max(model.predict_proba(scaled_features)[0])

    prediction = encoder.inverse_transform([pred_idx])[0]
    return prediction, prob, duration_sec, total_packets, total_bytes

def analyze_active_flows():
    """
    Background thread running every 2 seconds. Evaluates and predicts on active flows.
    Only logs to the queue if new packets arrived to reduce I/O thrashing.
    Purges completed or timed-out flows to conserve memory.
    """
    FLOW_TIMEOUT = 120.0 # Flow expires after 2 minutes of inactivity

    while True:
        time.sleep(2.0)

        flows_to_process = []
        current_time = time.time()

        with flow_lock:
            keys = list(active_flows.keys())
            for key in keys:
                flow_data = active_flows[key]
                inactive_time = current_time - flow_data['last_time']

                total_pkts = flow_data['fwd_packets'] + flow_data['bwd_packets']
                has_new_data = total_pkts > flow_data.get('last_analyzed_packets', 0)

                # Snapshot the flow for analysis if it changed or explicitly finished
                if has_new_data or flow_data['is_finished']:
                    snapshot = dict(flow_data)
                    flows_to_process.append((key, snapshot))
                    flow_data['last_analyzed_packets'] = total_pkts

                # Garbage collect stale flows
                if flow_data['is_finished'] or inactive_time > FLOW_TIMEOUT:
                    del active_flows[key]

        for key, flow in flows_to_process:
            if flow['fwd_packets'] + flow['bwd_packets'] >= 1:
                try:
                    prediction, prob, duration_sec, total_packets, total_bytes = predict_flow(flow)
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    bytes_per_s = total_bytes / duration_sec
                    packets_per_s = total_packets / duration_sec

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
                        'Probability': f"{prob:.4f}"
                    }

                    write_queue.put(result)

                    if prediction != 'BENIGN' or prob < 0.90:
                        print(f"[{timestamp}] [ALERT] {key[0]} -> {key[2]} | {prediction} ({prob:.2f}) | Pkts: {total_packets}")
                except Exception as e:
                    pass

def csv_writer():
    global OUTPUT_FILE

    header = ["Flow ID", "Timestamp", "Source IP", "Dest IP", "Protocol", "Total Packets", "Total Bytes", "Flow Duration (s)", "Packets/s", "Bytes/s", "Prediction", "Probability"]
    """ Background thread continuously batch-writing queued predictions to the CSV. """
    while True:
        try:
            results = []
            results.append(write_queue.get(timeout=5))

            # Flush queue into batch write
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
    """ Validates privileges and launches the sniffing pipeline. """
    print("Starting LIVE network monitor...")

    init_csv()

    analyzer = threading.Thread(target=analyze_active_flows, daemon=True)
    analyzer.start()

    writer = threading.Thread(target=csv_writer, daemon=True)
    writer.start()

    try:
        print("Sniffing REAL network traffic. Press Ctrl+C to stop.")
        # Strict checking: we expect the user to run with privileges to capture raw packets correctly.
        sniff(prn=packet_callback, store=False, filter="tcp or udp")
    except PermissionError:
        print("\n[CRITICAL ERROR] Permission denied! You must run this script as root/Administrator to capture live network packets.")
        print("Linux/Mac: sudo python network_monitor.py")
        print("Windows: Open Command Prompt or PowerShell as Administrator and run python network_monitor.py")
        sys.exit(1)
    except OSError as e:
        print(f"\n[CRITICAL ERROR] OS Socket Error (possibly missing privileges or npcap): {e}")
        print("Ensure you have npcap installed on Windows, or use sudo on Linux.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopping monitor gracefully...")
    except Exception as e:
        print(f"\nSniffing error: {e}")

if __name__ == "__main__":
    start_sniffer()
