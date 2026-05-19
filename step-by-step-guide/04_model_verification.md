# Step 04 — Model Verification

## 🎯 Objective
Verify that the pre-trained ML model artifacts are valid, loadable, and contain the expected classification structure.

## 💡 Thought Process
Before starting the server, I need to confirm the model files aren't corrupted and that the two-stage pipeline (binary → attack classification) is correctly configured. This prevents runtime errors and ensures predictions will be meaningful.

## 🔧 What I Did

### 1. Verified all model files
```
et-ids/models/
├── binary_pipeline.pkl          (4,846,428 bytes) — Stage 1 classifier
├── attack_pipeline.pkl          (21,112,923 bytes) — Stage 2 classifier
├── binary_label_encoder.pkl     (547 bytes)        — Binary labels
├── attack_label_encoder.pkl     (644 bytes)        — Attack labels
└── feature_columns.pkl          (302 bytes)        — Feature ordering
```

### 2. Validated model types
| File | Type | Classes |
|------|------|---------|
| `binary_pipeline.pkl` | sklearn Pipeline | 0 (BENIGN), 1 (MALICIOUS) |
| `attack_pipeline.pkl` | sklearn Pipeline | 0-9 (10 attack types) |
| `binary_label_encoder.pkl` | LabelEncoder | ['BENIGN', 'MALICIOUS'] |
| `attack_label_encoder.pkl` | LabelEncoder | ['Botnet', 'BruteForce', 'DDoS', 'DoS', 'IoT', 'MITM', 'Malware', 'Other', 'Recon', 'WebAttack'] |

### 3. Verified feature columns (22 features)
All 22 features match the training pipeline:
`dst_port, protocol, flow_duration, total_packets, total_bytes, min_pkt_len, max_pkt_len, avg_pkt_len, pkt_len_std, flow_rate, iat, syn_flag, ack_flag, rst_flag, psh_flag, ttl, bytes_per_packet, packets_per_second, avg_packet_size, byte_rate, burstiness, flag_sum`

### 4. Two-Stage Detection Flow
```
                           ┌─── BENIGN ──▶ "Safe" (no further analysis)
                           │
Packet ──▶ Flow Aggregator ──▶ Stage 1 (Binary)
                           │
                           └─── MALICIOUS ──▶ Stage 2 (Attack Type)
                                                  │
                                    ┌─────────────┤
                                    │             │
                              Confidence ≥ 80%  Confidence < 80%
                                    │             │
                              ATTACK LABEL    "Suspicious"
                              (DDoS, Bot...)   (Low confidence)
```

## ✅ Result
All 5 model artifacts verified. The two-stage XGBoost pipeline with 22 features is ready for inference.

---

## 🛠️ 5. Clean Standalone Re-Training from Scratch

If you want to re-train the models cleanly from scratch on the merged datasets (**CICIDS2017**, **NF-UNSW-NB15-v2**, **NF-ToN-IoT-v2**, and **CICIOT2023**), you can run our pristine training scripts:

### Step A: Place Raw Datasets
Ensure your raw CSV files are placed in:
```
data/raw/
├── cicids2017/*.csv
├── nf_ton_iot/NF-ToN-IoT-v2.csv
├── nf_unsw_nb15/NF-UNSW-NB15-v2.csv
└── ciciot2023/*.csv
```

### Step B: Run Dataset Integration
This merges the datasets and applies correct binary mappings and multiclass names:
```powershell
python integrate_datasets.py
```

### Step C: Run Unified Model Training
This trains the Stage 1 calibrated binary model and Stage 2 attack model cleanly with aligned feature definitions:
```powershell
python train_unified.py
```
👉 This will overwrite your `models/` directory with pristine, high-accuracy, calibrated `.pkl` model artifacts!

