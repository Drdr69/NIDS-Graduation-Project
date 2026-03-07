import os
import sys
import time
import pickle
import pandas as pd
from scapy.all import sniff, IP, TCP, conf
from datetime import datetime
import threading
import warnings
import random

warnings.filterwarnings('ignore')

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

OUTPUT_FILE = 'live_predictions.csv'

def init_csv():
    if not os.path.exists(OUTPUT_FILE):
        df = pd.DataFrame(columns=['Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Prediction', 'Probability'])
        df.to_csv(OUTPUT_FILE, index=False)

def predict_flow(flow_features):
    feature_df = pd.DataFrame([flow_features], columns=FEATURES)
    scaled_features = scaler.transform(feature_df)

    pred_idx = model.predict(scaled_features)[0]
    prob = max(model.predict_proba(scaled_features)[0])

    prediction = encoder.inverse_transform([pred_idx])[0]
    return prediction, prob

# We will use a mocked generator because real sniffing requires root privileges which might not be available
def generate_mock_flow():
    """Generates features matching the 16 core expected features"""
    return [
        random.uniform(100, 100000), # Flow Duration
        random.randint(1, 100),       # Total Fwd Packets
        random.randint(0, 100),       # Total Bwd Packets
        random.randint(0, 1500),      # Total Length of Fwd Packets
        random.randint(0, 1500),      # Total Length of Bwd Packets
        random.randint(0, 1500),      # Fwd Max
        random.randint(0, 100),       # Fwd Min
        random.randint(0, 1500),      # Bwd Max
        random.randint(0, 100),       # Bwd Min
        random.uniform(0, 1000),      # Flow Bytes/s
        random.uniform(0, 1000),      # Flow Packets/s
        random.randint(0, 1),         # FIN
        random.randint(0, 1),         # SYN
        random.randint(0, 1),         # RST
        random.randint(0, 1),         # PSH
        random.randint(0, 1)          # ACK
    ]

def mock_sniffer_loop():
    print("Starting simulated network monitor (running as unprivileged user)...")
    init_csv()

    while True:
        try:
            time.sleep(random.uniform(1.0, 3.0))
            features = generate_mock_flow()

            src_ip = f"192.168.1.{random.randint(2, 254)}"
            dst_ip = f"10.0.0.{random.randint(1, 20)}"

            prediction, prob = predict_flow(features)

            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            result = {
                'Timestamp': timestamp,
                'Source IP': src_ip,
                'Dest IP': dst_ip,
                'Protocol': 'TCP',
                'Prediction': prediction,
                'Probability': f"{prob:.2f}"
            }

            df = pd.DataFrame([result])
            df.to_csv(OUTPUT_FILE, mode='a', header=False, index=False)
            print(f"[{timestamp}] Analyzed Flow: {src_ip} -> {dst_ip} | Prediction: {prediction} ({prob:.2f})")

        except KeyboardInterrupt:
            print("Stopping monitor...")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    mock_sniffer_loop()
