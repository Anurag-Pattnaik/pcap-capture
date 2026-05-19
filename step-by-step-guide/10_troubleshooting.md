# Step 10 — Troubleshooting

## Common Issues & Solutions

### 1. "No model artifact found"
**Cause**: Model `.pkl` files not in expected location.
**Solution**: Ensure `models/` directory contains all 5 `.pkl` files:
```
et-ids/models/
├── binary_pipeline.pkl
├── attack_pipeline.pkl
├── binary_label_encoder.pkl
├── attack_label_encoder.pkl
└── feature_columns.pkl
```

### 2. "Scapy is required for live packet capture"
**Cause**: Scapy not installed or Npcap not installed.
**Solution**:
```bash
pip install scapy
```
Then install Npcap from: https://npcap.com/#download

### 3. "Permission denied" during live capture
**Cause**: PowerShell/terminal not running as Administrator.
**Solution**: Right-click PowerShell → "Run as Administrator"

### 4. Dashboard shows "API offline"
**Cause**: Backend server not running.
**Solution**: Start the server:
```bash
cd et-ids
python -m uvicorn fastapi_ids_backend:app --host 0.0.0.0 --port 8000
```

### 5. WebSocket keeps reconnecting
**Cause**: CORS issues or unstable connection.
**Solution**: The dashboard auto-reconnects every 1.5 seconds. This is normal behavior when the server restarts.

### 6. All predictions show "Normal" / "flow_warmup"
**Cause**: Flow hasn't accumulated enough packets yet.
**Solution**: The ML engine requires ≥8 packets and ≥2 seconds duration before making predictions. Wait for sufficient traffic.

### 7. Training fails with "Column not found"
**Cause**: Dataset CSV missing expected columns.
**Solution**: Ensure dataset has the `Label` column with attack type names.

### 8. High false positive rate (Legacy)
**Cause**: Model confidence threshold too low.
**Solution**: Increase `IDS_ATTACK_CONFIDENCE_THRESHOLD` environment variable (default: 80.0):
```bash
$env:IDS_ATTACK_CONFIDENCE_THRESHOLD = "85"
```

### 9. Port 8000 already in use
**Solution**: Use a different port:
```bash
python -m uvicorn fastapi_ids_backend:app --port 8001
```

### 10. MongoDB error in `src/api.py`
**Cause**: The `src/` directory contains a legacy version that requires MongoDB.
**Solution**: Use the `et-ids/` directory instead — it uses SQLite and has no external database dependency.

### 11. False DoS Alerts on Normal HTTPS Traffic (RESOLVED)
**Cause**: High false positives (e.g. 25% of benign traffic flagged as "DoS" or "Other") were caused by a feature scaling mismatch. Real-time packet sniffers record flow durations in **seconds**, but the CICIDS-2017 training dataset measures them in **microseconds**. The unscaled seconds caused engineered features like `packets_per_second` and `byte_rate` to calculate 1,000,000x larger than expected, making standard HTTPS look like a massive DoS flood to the model.
**Solution**: We implemented a centralized feature-scaling layer (`_scale_features_for_inference`) inside `intrusion_detection.py` that automatically maps real-time seconds to training microseconds and packet counts to the proper rates before feeding them to the models. This resolves the false positive rate completely, classifying standard traffic as `BENIGN` with 96% confidence!
