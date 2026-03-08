import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
import xgboost as xgb
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os

print("Starting model training process...")

# 1. Create Mock CICIDS2017 Dataset
# The 16 core features we can reliably extract using scapy
FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Min',
    'Bwd Packet Length Max',
    'Bwd Packet Length Min',
    'Flow Bytes/s',
    'Flow Packets/s',
    'FIN Flag Count',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count'
]

def generate_mock_data(n_samples=5000):
    np.random.seed(42)
    data = {}

    for feature in FEATURES:
        # Generate some semi-realistic numbers
        if 'Flag' in feature:
            data[feature] = np.zeros(n_samples) # Mostly benign, no flags
        elif 'Duration' in feature:
            data[feature] = np.random.exponential(500, n_samples)
        elif 'Length' in feature:
            data[feature] = np.random.normal(100, 20, n_samples)
        else:
            data[feature] = np.random.rand(n_samples) * 10

    df = pd.DataFrame(data)

    # Mostly benign
    labels = np.random.choice(
        ['BENIGN', 'DoS Hulk', 'PortScan', 'DDoS', 'Bot', 'FTP-Patator', 'SSH-Patator', 'Web Attack - Brute Force'],
        n_samples,
        p=[0.9, 0.02, 0.02, 0.02, 0.01, 0.01, 0.01, 0.01]
    )
    df['Label'] = labels

    # Introduce explicit, very strong patterns so the model learns them flawlessly and doesn't hallucinate

    # Benign: small packets, few flags
    benign_idx = df['Label'] == 'BENIGN'
    df.loc[benign_idx, 'Flow Bytes/s'] = np.random.uniform(10, 500, sum(benign_idx))
    df.loc[benign_idx, 'Flow Packets/s'] = np.random.uniform(1, 50, sum(benign_idx))

    # PortScan: Lots of SYN flags, small packets, high packet rate
    portscan_idx = df['Label'] == 'PortScan'
    df.loc[portscan_idx, 'SYN Flag Count'] = 1
    df.loc[portscan_idx, 'Flow Packets/s'] = np.random.uniform(5000, 20000, sum(portscan_idx))
    df.loc[portscan_idx, 'Flow Duration'] = np.random.uniform(1, 10, sum(portscan_idx))

    # DoS Hulk/DDoS: Huge packet rate, large flows
    dos_idx = df['Label'].isin(['DoS Hulk', 'DDoS'])
    df.loc[dos_idx, 'Flow Packets/s'] = np.random.uniform(50000, 200000, sum(dos_idx))
    df.loc[dos_idx, 'Total Length of Fwd Packets'] = np.random.uniform(10000, 50000, sum(dos_idx))

    # Web Attack: Large payloads
    web_idx = df['Label'] == 'Web Attack - Brute Force'
    df.loc[web_idx, 'Fwd Packet Length Max'] = np.random.uniform(2000, 5000, sum(web_idx))

    # Bot/Patator: Long durations, periodic
    bot_idx = df['Label'].isin(['Bot', 'FTP-Patator', 'SSH-Patator'])
    df.loc[bot_idx, 'Flow Duration'] = np.random.uniform(500000, 1000000, sum(bot_idx))

    return df

print("Generating better synthetic dataset...")
df = generate_mock_data(n_samples=20000)
df.to_csv("cicids2017_sample.csv", index=False)
print("Saved sample dataset to cicids2017_sample.csv")

# 2. Preprocessing
X = df[FEATURES]
y = df['Label']

# Encode labels
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y_encoded, test_size=0.2, random_state=42)

# 3. Train Models
models = {
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
    "XGBoost": xgb.XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=42),
    "KNN": KNeighborsClassifier(n_neighbors=5)
}

best_model = None
best_accuracy = 0
best_name = ""

for name, model in models.items():
    print(f"\nTraining {name}...")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    print(f"{name} Accuracy: {acc:.4f}")

    if acc > best_accuracy:
        best_accuracy = acc
        best_model = model
        best_name = name

print(f"\nBest Model: {best_name} with Accuracy {best_accuracy:.4f}")

# 4. Save Artifacts
print("Saving best model, scaler, and label encoder...")
with open("best_model.pkl", "wb") as f:
    pickle.dump(best_model, f)

with open("scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

with open("label_encoder.pkl", "wb") as f:
    pickle.dump(encoder, f)

with open("feature_names.txt", "w") as f:
    f.write(",".join(FEATURES))

print("Model training complete!")
