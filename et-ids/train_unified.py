"""
train_unified.py - Unified Two-Stage ML Training Pipeline

This script trains both detection stages cleanly from scratch:
  - Stage 1: Calibrated Binary Classifier (BENIGN vs. MALICIOUS)
  - Stage 2: Attack Type Multiclass Classifier

Corrected Bugs from original notebooks:
  1. [CRITICAL] Unified Feature Engineering: Aligned the 'burstiness' andengineered features
     identically across both Stage 1 and Stage 2 models.
  2. [CRITICAL] Calibration Layer: Applies isotonic probability calibration to Stage 1
     so the real-time threshold actually works.
  3. [HIGH] Sample Balancing: Resolves dataset class imbalances cleanly using stratified weights.
"""

import pandas as pd
import numpy as np
import joblib
import json
import os
import warnings
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.calibration import CalibratedClassifierCV
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import classification_report, confusion_matrix
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

def clean_and_prepare_features(df):
    """
    Apply robust NaN/Inf cleanups and identical feature engineering formulas
    used in real-time streaming inference.
    """
    print("  Cleaning and handling Inf/NaN anomalies...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # Remove extremely large values
    for col in df.select_dtypes(include=np.number).columns:
        df = df[df[col] < 1e15]
        df = df[df[col] > -1e15]

    print("  Running consistent Feature Engineering...")
    df['bytes_per_packet']   = df['total_bytes']   / (df['total_packets']   + 1e-6)
    df['packets_per_second'] = df['total_packets'] / (df['flow_duration']   + 1e-6)
    df['avg_packet_size']    = df['total_bytes']   / (df['total_packets']   + 1e-6)
    df['byte_rate']          = df['total_bytes']   / (df['flow_duration']   + 1e-6)
    df['burstiness']         = df['pkt_len_std']   / (df['avg_pkt_len']     + 1e-6)
    df['flag_sum']           = (df['syn_flag'] + df['ack_flag'] +
                                df['rst_flag'] + df['psh_flag'])
    return df

def map_attack(x):
    """
    Standardize attack category naming across the unified dataset.
    """
    val = str(x).upper().strip()
    if 'DDOS' in val:
        return 'DDoS'
    elif 'DOS' in val:
        return 'DoS'
    elif 'SCAN' in val or 'RECON' in val:
        return 'Recon'
    elif 'PATATOR' in val or 'BRUTE' in val:
        return 'BruteForce'
    elif 'XSS' in val or 'SQL' in val or 'INJECTION' in val:
        return 'WebAttack'
    elif 'BOT' in val:
        return 'Botnet'
    elif 'MIRAI' in val or 'IOT' in val:
        return 'IoT'
    elif 'MITM' in val:
        return 'MITM'
    elif 'BACKDOOR' in val or 'MALWARE' in val:
        return 'Malware'
    elif val in ['0', '0.0', 'BENIGN', 'NORMAL', '']:
        return 'BENIGN'
    else:
        return 'Other'

def main():
    print("==================================================")
    print("🚀 Starting Unified NIDS Training Pipeline")
    print("==================================================")

    # Setup paths
    dataset_path = "../data/raw/unified_dataset.csv"
    if not os.path.exists(dataset_path):
        dataset_path = "data/raw/unified_dataset.csv"  # Fallback
        
    if not os.path.exists(dataset_path):
        print(f"❌ Unified dataset not found at {dataset_path}!")
        print("Please run 'integrate_datasets.py' first.")
        return

    print(f"\nLoading consolidated dataset: {dataset_path}...")
    df = pd.read_csv(dataset_path, low_memory=False)
    print(f"Loaded Shape: {df.shape}")

    # Standardize column structure & engineer features
    df = clean_and_prepare_features(df)
    print(f"Cleaned Shape: {df.shape}")

    selected_features = [
        'dst_port', 'protocol', 'flow_duration', 'total_packets', 'total_bytes',
        'min_pkt_len', 'max_pkt_len', 'avg_pkt_len', 'pkt_len_std', 'flow_rate',
        'iat', 'syn_flag', 'ack_flag', 'rst_flag', 'psh_flag', 'ttl',
        'bytes_per_packet', 'packets_per_second', 'avg_packet_size',
        'byte_rate', 'burstiness', 'flag_sum'
    ]

    # Save feature sequence columns
    os.makedirs("models", exist_ok=True)
    joblib.dump(selected_features, "models/feature_columns.pkl")
    print(f"Saved feature column order to models/feature_columns.pkl")

    # ─────────────────────────────────────────────────────────────
    # ⚡ STAGE 1: Train Binary Classifier (BENIGN vs. MALICIOUS)
    # ─────────────────────────────────────────────────────────────
    print("\n--------------------------------------------------")
    print("⚡ [Stage 1] Training Binary Classifier")
    print("--------------------------------------------------")
    
    # Slice features and binary label
    X_bin = df[selected_features].astype(np.float32)
    y_bin_raw = df['binary_label']

    le_bin = LabelEncoder()
    y_bin = le_bin.fit_transform(y_bin_raw)
    print(f"Binary classes: {le_bin.classes_}")

    # Perform stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X_bin, y_bin, test_size=0.2, stratify=y_bin, random_state=42
    )

    # Compute sample weights to balance the minority malicious/benign proportions
    sample_weights = compute_sample_weight(class_weight="balanced", y=y_train)

    # Pipeline definition with a lighter max_depth=6 to reduce overfitting
    pipeline_bin = Pipeline([
        ('scaler', StandardScaler()),
        ('model', XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            eval_metric='logloss',
            use_label_encoder=False,
            random_state=42,
            n_jobs=-1,
        ))
    ])

    print("Fitting Binary pipeline...")
    pipeline_bin.fit(X_train, y_train, model__sample_weight=sample_weights)

    # Calibrate probability scores
    print("Calibrating probabilities...")
    calibrated_bin = CalibratedClassifierCV(pipeline_bin, method="isotonic", cv=3)
    calibrated_bin.fit(X_train, y_train, sample_weight=sample_weights)

    # Evaluate Binary Stage
    y_pred = calibrated_bin.predict(X_test)
    print("\n=== STAGE 1 CLASSIFICATION REPORT ===")
    print(classification_report(y_test, y_pred, target_names=le_bin.classes_))

    cm = confusion_matrix(y_test, y_pred)
    print(f"Confusion Matrix:\n{cm}")
    benign_idx = list(le_bin.classes_).index("BENIGN")
    fp = cm[benign_idx].sum() - cm[benign_idx, benign_idx]
    print(f"False Positive Rate: {fp}/{cm[benign_idx].sum()} = {fp/max(cm[benign_idx].sum(), 1)*100:.2f}%")

    # Save Stage 1 models
    joblib.dump(calibrated_bin, "models/binary_pipeline.pkl")
    joblib.dump(le_bin, "models/binary_label_encoder.pkl")
    print("Calibrated Binary model saved successfully!")

    # ─────────────────────────────────────────────────────────────
    # ⚡ STAGE 2: Train Attack Classifier (Multiclass attacks)
    # ─────────────────────────────────────────────────────────────
    print("\n--------------------------------------------------")
    print("⚡ [Stage 2] Training Attack Classifier")
    print("--------------------------------------------------")

    # Slice to malicious records only
    df_attack = df[df['binary_label'] == 'MALICIOUS']
    print(f"Malicious dataset shape: {df_attack.shape}")

    # Standardize multiclass mapping
    df_attack['attack_type'] = df_attack['attack_type'].apply(map_attack)
    df_attack = df_attack[df_attack['attack_type'] != 'BENIGN']
    print("\nInitial Attack class distribution:")
    print(df_attack['attack_type'].value_counts())

    # Under-sample large classes (e.g. DDoS/DoS) to max 100k records to speed training
    max_samples = 100000
    balanced_chunks = []
    for cls in df_attack['attack_type'].unique():
        subset = df_attack[df_attack['attack_type'] == cls]
        if len(subset) > max_samples:
            subset = subset.sample(max_samples, random_state=42)
        balanced_chunks.append(subset)
    df_attack = pd.concat(balanced_chunks)

    print("\nBalanced Attack class distribution:")
    print(df_attack['attack_type'].value_counts())

    X_atk = df_attack[selected_features].astype(np.float32)
    y_atk_raw = df_attack['attack_type']

    le_atk = LabelEncoder()
    y_atk = le_atk.fit_transform(y_atk_raw)
    n_classes = len(le_atk.classes_)
    print(f"Attack classes ({n_classes}): {le_atk.classes_}")

    # Perform stratified split
    X_train_atk, X_test_atk, y_train_atk, y_test_atk = train_test_split(
        X_atk, y_atk, test_size=0.2, stratify=y_atk, random_state=42
    )

    # Stratified balance weights
    sample_weights_atk = compute_sample_weight(class_weight="balanced", y=y_train_atk)

    pipeline_atk = Pipeline([
        ('scaler', StandardScaler()),
        ('model', XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            eval_metric='mlogloss',
            num_class=n_classes,
            objective='multi:softprob',
            use_label_encoder=False,
            random_state=42,
            n_jobs=-1,
        ))
    ])

    print("Fitting Attack pipeline...")
    pipeline_atk.fit(X_train_atk, y_train_atk, model__sample_weight=sample_weights_atk)

    # Evaluate Attack Stage
    y_pred_atk = pipeline_atk.predict(X_test_atk)
    print("\n=== STAGE 2 CLASSIFICATION REPORT ===")
    print(classification_report(y_test_atk, y_pred_atk, target_names=le_atk.classes_))

    # Save Stage 2 models
    joblib.dump(pipeline_atk, "models/attack_pipeline.pkl")
    joblib.dump(le_atk, "models/attack_label_encoder.pkl")
    print("Attack multiclass model saved successfully!")

    # Save class names JSON
    with open("models/class_names.json", "w") as f:
        json.dump(list(le_atk.classes_), f, indent=2)

    print("\n==================================================")
    print("🎉 All Stage 1 and Stage 2 models successfully trained!")
    print("==================================================")

if __name__ == "__main__":
    main()
