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
            data[feature] = np.random.randint(0, 2, n_samples)
        elif 'Duration' in feature:
            data[feature] = np.random.exponential(100000, n_samples)
        elif 'Length' in feature:
            data[feature] = np.random.randint(0, 1500, n_samples)
        else:
            data[feature] = np.random.rand(n_samples) * 100

    df = pd.DataFrame(data)

    # Assign labels (Simulating CICIDS2017 classes)
    labels = np.random.choice(
        ['BENIGN', 'DoS Hulk', 'PortScan', 'DDoS', 'Bot', 'FTP-Patator', 'SSH-Patator', 'Web Attack - Brute Force'],
        n_samples,
        p=[0.6, 0.1, 0.1, 0.05, 0.05, 0.05, 0.03, 0.02]
    )
    df['Label'] = labels

    # Introduce some correlations to make models actually learn something
    df.loc[df['Label'] == 'PortScan', 'SYN Flag Count'] = 1
    df.loc[df['Label'] == 'DoS Hulk', 'Flow Packets/s'] = df.loc[df['Label'] == 'DoS Hulk', 'Flow Packets/s'] * 10

    return df

print("Generating mock dataset...")
df = generate_mock_data()
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
    "Random Forest": RandomForestClassifier(n_estimators=50, random_state=42),
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
