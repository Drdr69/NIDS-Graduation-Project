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

# 1. Load Real CICIDS2017 Dataset Sample
dataset_file = "cicids2017_real_sample.csv"

if not os.path.exists(dataset_file):
    print("Warning: Real dataset not found locally. Attempting to download from Hugging Face...")
    try:
        from datasets import load_dataset
        dataset = load_dataset('bvk/CICIDS-2017', split='train')
        df = dataset.to_pandas()

        attacks = df[df['Label'] != 'BENIGN']
        benign = df[df['Label'] == 'BENIGN']

        if len(benign) > 100000:
            benign_sample = benign.sample(n=100000, random_state=42)
        else:
            benign_sample = benign

        df_balanced = pd.concat([benign_sample, attacks])
        df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)

        df_balanced.to_csv(dataset_file, index=False)
        df = df_balanced
        print("Successfully downloaded and balanced dataset!")
    except Exception as e:
        print(f"Error downloading dataset: {e}")
        print("Please manually download the CICIDS2017 dataset and place it as 'cicids2017_real_sample.csv' in the project directory.")
        exit(1)
else:
    df = pd.read_csv(dataset_file)

# Ensure dataset size is manageable but large enough
if len(df) > 200000:
    # Stratified downsample to 200k to ensure KNN and RF train in reasonable time
    df = df.groupby('Label', group_keys=False).apply(lambda x: x.sample(min(len(x), int(200000 * len(x)/len(df))), random_state=42))

feature_mapping = {
    'Flow Duration': 'Flow Duration',
    'Total Fwd Packet': 'Total Fwd Packets',
    'Total Bwd packets': 'Total Backward Packets',
    'Total Length of Fwd Packet': 'Total Length of Fwd Packets',
    'Total Length of Bwd Packet': 'Total Length of Bwd Packets',
    'Fwd Packet Length Max': 'Fwd Packet Length Max',
    'Fwd Packet Length Min': 'Fwd Packet Length Min',
    'Bwd Packet Length Max': 'Bwd Packet Length Max',
    'Bwd Packet Length Min': 'Bwd Packet Length Min',
    'Flow Bytes/s': 'Flow Bytes/s',
    'Flow Packets/s': 'Flow Packets/s',
    'FIN Flag Count': 'FIN Flag Count',
    'SYN Flag Count': 'SYN Flag Count',
    'RST Flag Count': 'RST Flag Count',
    'PSH Flag Count': 'PSH Flag Count',
    'ACK Flag Count': 'ACK Flag Count'
}

df.rename(columns=feature_mapping, inplace=True)
FEATURES = list(feature_mapping.values())

# Clean up infinite values and NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(subset=FEATURES + ['Label'], inplace=True)

# Merge detailed attempts into main categories
df['Label'] = df['Label'].replace({
    'Infiltration - Portscan': 'PortScan',
    'Infiltration': 'Infiltration',
    'Infiltration - Attempted': 'Infiltration',
    'DoS Hulk - Attempted': 'DoS Hulk',
    'Botnet - Attempted': 'Bot',
    'Botnet': 'Bot',
    'DoS Slowloris': 'DoS',
    'DoS Slowhttptest': 'DoS',
    'DoS Slowloris - Attempted': 'DoS',
    'DoS Slowhttptest - Attempted': 'DoS',
    'DoS GoldenEye': 'DoS',
    'DoS GoldenEye - Attempted': 'DoS',
    'Web Attack - Brute Force - Attempted': 'Web Attack',
    'Web Attack - XSS - Attempted': 'Web Attack',
    'Web Attack - Brute Force': 'Web Attack',
    'Web Attack - SQL Injection': 'Web Attack',
    'Web Attack - SQL Injection - Attempted': 'Web Attack',
    'Web Attack - XSS': 'Web Attack',
    'FTP-Patator - Attempted': 'FTP-Patator',
    'SSH-Patator - Attempted': 'SSH-Patator',
    'DDoS': 'DDoS',
    'Portscan': 'PortScan',
    'Heartbleed': 'Heartbleed'
})

print(f"Data ready for training. Shape: {df.shape}")
print(df['Label'].value_counts())

# 2. Preprocessing
X = df[FEATURES]
y = df['Label']

encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y_encoded, test_size=0.3, random_state=42, stratify=y_encoded)

# 3. Train Models
models = {
    "Random Forest": RandomForestClassifier(n_estimators=50, max_depth=15, n_jobs=-1, random_state=42),
    "XGBoost": xgb.XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=42, n_jobs=-1, max_depth=8),
    "KNN": KNeighborsClassifier(n_neighbors=5, n_jobs=-1)
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

print("\nClassification Report (Real-Time Attack Types):")
y_pred_best = best_model.predict(X_test)
print(classification_report(y_test, y_pred_best))

# 4. Save Artifacts
print("Saving artifacts...")
with open("best_model.pkl", "wb") as f:
    pickle.dump(best_model, f)
with open("scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)
with open("label_encoder.pkl", "wb") as f:
    pickle.dump(encoder, f)
with open("feature_names.txt", "w") as f:
    f.write(",".join(FEATURES))

print("Model training complete!")
