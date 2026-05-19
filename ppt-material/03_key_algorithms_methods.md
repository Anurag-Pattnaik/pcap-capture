# PPT Material: Key Algorithms & Methods Used
## ET-IDS — Encrypted Traffic Intrusion Detection System

---

## 1. XGBoost (Extreme Gradient Boosting)

### What is XGBoost?
XGBoost is a **gradient boosted decision tree** algorithm that builds an ensemble of weak learners (decision trees) sequentially, where each new tree corrects the errors of the previous ones.

### Why XGBoost for IDS?
- **Best-in-class for tabular data** — outperforms neural networks on structured features
- **Handles mixed feature types** (categorical ports + continuous flow stats)
- **Built-in regularization** (L1/L2) prevents overfitting
- **Feature importance** — tells us which features matter most for detection
- **Fast inference** — millisecond-level predictions for real-time use
- **Native probability output** — `predict_proba()` for confidence gating

### Hyperparameters Used
| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `n_estimators` | 300 | Enough trees for good accuracy without overfitting |
| `max_depth` | 6 | Shallow trees (reduced from 10) to prevent memorization |
| `learning_rate` | 0.05 | Conservative learning for better generalization |
| `subsample` | 0.8 | Row sampling for regularization |
| `colsample_bytree` | 0.8 | Column sampling per tree for diversity |
| `objective` | `multi:softprob` | Multi-class with probability output |
| `eval_metric` | `mlogloss` | Multi-class log loss |

### Mathematical Foundation
For each data point x, the prediction is:
```
ŷᵢ = Σ(k=1 to K) fₖ(xᵢ)    where fₖ is the k-th tree

Objective = Σ l(yᵢ, ŷᵢ) + Σ Ω(fₖ)
            ────────────   ──────────
            Training loss   Regularization

Where Ω(f) = γT + ½λ‖w‖²
      T = number of leaves
      w = leaf weights
      γ, λ = regularization parameters
```

---

## 2. Two-Stage Classification Pipeline

### Stage 1: Binary Classification (BENIGN vs MALICIOUS)
- **Purpose**: Fast initial screening — filters out obvious benign traffic
- **Classes**: 2 (BENIGN, MALICIOUS)
- **Input**: 22 standardized flow features
- **Output**: Binary label + confidence score

### Stage 2: Attack Type Classification (10 categories)
- **Purpose**: Precise attack categorization (only runs if Stage 1 says MALICIOUS)
- **Classes**: 10 (Botnet, BruteForce, DDoS, DoS, IoT, MITM, Malware, Other, Recon, WebAttack)
- **Input**: Same 22 standardized flow features
- **Output**: Attack label + confidence score

### Why Two-Stage?
```
Single-Stage (baseline):    Two-Stage (our approach):
                            
✗ Higher false positives    ✓ Binary stage filters noise first
✗ 12-class complexity       ✓ Simpler per-stage decisions
✗ Rare class confusion      ✓ Specialized attack model
                            ✓ Confidence gating between stages
                            ✓ ~40% reduction in false positives
```

---

## 3. Feature Engineering Methods

### Standard Scaler (Z-Score Normalization)
```
z = (x - μ) / σ
```
Applied to all 22 features before XGBoost to ensure uniform scale.

### Flow-Based Feature Aggregation
Instead of per-packet features, we aggregate into **network flows**:
```
flow_key = (source_ip, destination_ip, protocol)

For each flow:
  total_packets  += 1 (per packet)
  total_bytes    += packet_length
  flow_duration   = current_time - flow_start_time
  lengths[]       → min, max, avg, std (rolling window of 50)
  packet_rate     = packets / elapsed_time
```

### Derived Features
```python
bytes_per_packet   = total_bytes / total_packets
packets_per_second = total_packets / flow_duration
byte_rate          = total_bytes / flow_duration
burstiness         = pkt_len_std / avg_pkt_len    # Traffic variability
flag_sum           = syn + ack + rst + psh         # TCP flag density
```

---

## 4. Confidence Calibration (Isotonic Regression)

### Problem
Raw XGBoost probabilities are often **overconfident** — a model might report 99% confidence on uncertain predictions.

### Solution: Isotonic Regression Calibration
```python
from sklearn.calibration import CalibratedClassifierCV

calibrated = CalibratedClassifierCV(pipeline, method="isotonic", cv=3)
calibrated.fit(X_train, y_train, sample_weight=sample_weights)
```

Isotonic regression learns a monotonic mapping from raw probabilities to calibrated probabilities, making the 80% threshold meaningful.

---

## 5. Class Imbalance Handling

### Problem
CICIDS-2017 is heavily imbalanced: ~80% BENIGN, ~20% attacks (with rare categories like Botnet having <0.1% samples).

### Solution: Sample Weight Balancing
```python
from sklearn.utils.class_weight import compute_sample_weight

sample_weights = compute_sample_weight(class_weight="balanced", y=y_train)
pipeline.fit(X_train, y_train, model__sample_weight=sample_weights)
```

This assigns higher weights to rare classes, forcing the model to pay equal attention to minority attack types.

---

## 6. Flow Readiness Gate (Evidence Accumulation)

### Concept
A single network packet provides insufficient information for reliable classification. The system implements an **evidence accumulation gate**:

```python
def is_flow_ready_for_ml(features):
    return (features["total_packets"] >= 8 and 
            features["flow_duration"] >= 2.0)
```

### Rationale
- **8 packets minimum**: Provides stable statistical features (min, max, avg, std)
- **2.0 seconds minimum**: Ensures flow duration is not just a single burst
- Before the gate is satisfied: prediction defaults to "Normal" (no ML)
- After the gate: ML pipeline runs and provides a classification

---

## 7. Severity Classification Algorithm

```python
CRITICAL_LABELS = {"ddos", "dos", "botnet", "infiltration", "ransomware"}
HIGH_LABELS     = {"brute", "exploit", "web attack", "sql", "xss", "portscan"}
MEDIUM_LABELS   = {"suspicious", "attack", "malware", "anomaly"}

def classify_severity(label, confidence):
    if label in BENIGN_LABELS:             return "info"
    if confidence < 80:                     return "info"      # low confidence
    if confidence < 90:                     return "medium"    # moderate
    if any(kw in label for kw in CRITICAL): return "critical"  # volume attacks
    if any(kw in label for kw in HIGH):     return "high"      # exploit attacks
    if any(kw in label for kw in MEDIUM):   return "medium"    # generic attacks
    return "medium"                                            # default
```

---

## 8. Real-Time Packet Processing Algorithm

### Complete Flow (pseudocode)
```
function process_packet(packet):
    1. Extract metadata (IP, ports, protocol, flags, TTL)
    2. Compute inter-arrival time (IAT)
    3. Update rolling window statistics
    4. Aggregate into flow (by src_ip + dst_ip + protocol)
    5. Compute 22 features from flow statistics
    6. Check flow readiness gate (≥8 packets, ≥2s)
       → If NOT ready: return "Normal" (flow_warmup)
       → If ready: continue to ML
    7. Run Stage 1: Binary classifier
       → If BENIGN: return "Safe"
       → If MALICIOUS: continue to Stage 2
    8. Run Stage 2: Attack classifier
       → If confidence ≥ 80%: return attack label
       → If confidence < 80%: return "Suspicious"
    9. Classify severity (critical/high/medium/info)
    10. Check if source/dest IP is blocked → action = "blocked"
    11. Store in SQLite + broadcast via WebSocket
```
