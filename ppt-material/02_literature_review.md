# PPT Material: Literature Review
## ET-IDS — Encrypted Traffic Intrusion Detection System

---

## 1. Background & Motivation

The exponential growth of encrypted internet traffic (TLS/SSL) presents a significant challenge for traditional Network Intrusion Detection Systems (NIDS). According to Google's Transparency Report, over **95% of web traffic** is now encrypted. While encryption protects user privacy, it also creates a "blind spot" for security monitoring — traditional deep packet inspection (DPI) methods cannot analyze encrypted payloads.

This project addresses this challenge by using **metadata-based machine learning** to classify encrypted traffic without decrypting it.

---

## 2. Related Work

### 2.1 Traditional IDS Approaches
- **Snort (1998)**: Signature-based IDS that matches packet payloads against known attack patterns. Ineffective against encrypted traffic and zero-day attacks.
- **Suricata**: Multi-threaded IDS with DPI capabilities. Also limited by encrypted traffic.
- **Zeek (formerly Bro)**: Network analysis framework that generates connection logs. Provides metadata but requires separate ML integration.

### 2.2 Machine Learning in IDS

| Author(s) | Year | Method | Dataset | Key Finding |
|-----------|------|--------|---------|-------------|
| Sharafaldin et al. | 2018 | Random Forest, KNN | CICIDS-2017 | RF achieved 98% accuracy on unencrypted flows |
| Khraisat et al. | 2019 | C5 Decision Tree | NSL-KDD | Hybrid anomaly+signature approach improved detection |
| Ahmad et al. | 2021 | XGBoost, LSTM | CICIDS-2017 | XGBoost outperformed LSTM for tabular flow data |
| Ferrag et al. | 2020 | Deep Learning Survey | Multiple | Comprehensive review of DL-based IDS methods |
| Anderson & McGrew | 2017 | Encrypted traffic analysis | TLS metadata | Showed that TLS handshake metadata can identify malware |
| Lotfollahi et al. | 2020 | CNN on packet headers | ISCX-VPN | Deep learning on packet header bytes for encrypted classification |

### 2.3 XGBoost in Cybersecurity
- Chen & Guestrin (2016): Introduced XGBoost as a scalable tree boosting system
- XGBoost is particularly effective for tabular data with mixed feature types
- Handles class imbalance well via `sample_weight` and `scale_pos_weight`
- Provides native `predict_proba` for confidence-based decision making

### 2.4 CICIDS-2017 Dataset
- Created by Canadian Institute for Cybersecurity (CIC), University of New Brunswick
- Contains 5 days of network traffic with 80+ features per flow
- Includes both benign and 14 attack types
- **Most cited IDS dataset** in academic literature (2,500+ citations)
- Realistic attack scenarios generated in a controlled lab environment

### 2.5 Encrypted Traffic Classification
- **Joy (Cisco)**: Open-source tool for encrypted traffic analysis using TLS metadata
- **nPrintML**: Framework for automated ML on network traffic
- **Key insight**: Even encrypted traffic leaks metadata — packet sizes, timing, flow duration, port numbers, and TCP flags are always visible

---

## 3. Research Gaps Addressed

| Gap | How ET-IDS Addresses It |
|-----|------------------------|
| Most IDS require payload inspection | Uses only metadata features (works on encrypted traffic) |
| Single-stage classifiers have high false positives | Two-stage pipeline: binary filter then attack classification |
| Academic models lack real-time deployment | Full web dashboard with live capture and WebSocket streaming |
| No confidence-based filtering | 80% confidence gate prevents low-confidence alerts |
| Complex deployment (requires MongoDB, etc.) | Zero-dependency SQLite storage, single-command startup |

---

## 4. Key References

1. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization." *ICISSP*.

2. Chen, T., & Guestrin, C. (2016). "XGBoost: A Scalable Tree Boosting System." *KDD*.

3. Anderson, B., & McGrew, D. (2017). "Machine Learning for Encrypted Malware Traffic Classification." *SIGKDD Workshop*.

4. Ferrag, M. A., Maglaras, L., Moschoyiannis, S., & Janicke, H. (2020). "Deep Learning for Cyber Security Intrusion Detection." *IEEE Access*.

5. Khraisat, A., Gondal, I., Vamplew, P., & Kamruzzaman, J. (2019). "Survey of Intrusion Detection Systems." *Cybersecurity*.

6. Lotfollahi, M., Siavoshani, M. J., Zade, R. S. H., & Saberian, M. (2020). "Deep Packet: A Novel Approach For Encrypted Traffic Classification." *Soft Computing*.

7. Paxson, V. (1999). "Bro: A System for Detecting Network Intruders in Real-Time." *Computer Networks*.

8. Roesch, M. (1999). "Snort - Lightweight Intrusion Detection for Networks." *LISA*.
