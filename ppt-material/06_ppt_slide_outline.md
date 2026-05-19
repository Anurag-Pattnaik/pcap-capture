# PPT Material: Suggested Slide Outline
## ET-IDS — Encrypted Traffic Intrusion Detection System

---

## Recommended Slide Structure (15-20 slides)

### Slide 1: Title Slide
- **Title**: ET-IDS: Encrypted Traffic Intrusion Detection System
- **Subtitle**: Real-Time Network Threat Detection Using Two-Stage XGBoost Pipeline
- **Team members, University, Date**

### Slide 2: Problem Statement
- 95% of internet traffic is now encrypted (TLS/SSL)
- Traditional IDS rely on deep packet inspection (DPI) — fails on encrypted traffic
- Need: ML-based detection using only packet metadata
- Goal: Real-time classification of encrypted traffic as benign or malicious

### Slide 3: Objectives
1. Build a two-stage ML pipeline for encrypted traffic classification
2. Implement real-time packet capture and flow aggregation
3. Create a web-based dashboard for security monitoring
4. Support both live capture and offline PCAP analysis
5. Enable IP blocking as automated response

### Slide 4: Literature Review (Part 1)
- Traditional IDS: Snort (signature-based), Suricata, Zeek
- Limitations: Cannot inspect encrypted payloads
- ML-based IDS: Random Forest, KNN, XGBoost, LSTM approaches
- Key reference: Anderson & McGrew (2017) — encrypted malware detection

### Slide 5: Literature Review (Part 2)
- CICIDS-2017 dataset (2,500+ citations, most used IDS benchmark)
- XGBoost advantages: best for tabular data, fast inference, probability output
- Research gap: Most academic models lack real-time deployment with UI

### Slide 6: Proposed Architecture (Overview)
- 4-layer architecture diagram:
  1. Data Acquisition (Scapy)
  2. Feature Engineering (22 features)
  3. ML Detection (Two-stage XGBoost)
  4. Response & Visualization (FastAPI + Dashboard)

### Slide 7: Proposed Architecture (Detail)
- Full system architecture diagram
- Components: FastAPI, RealtimeIDS, TwoStageDetector, SQLite, BlockManager
- Data flow: Packet → Metadata → Flow → ML → Decision → Dashboard

### Slide 8: Dataset
- CICIDS-2017: 5 days, ~2.8M flows, 14+ attack types
- Distribution: ~80% benign, ~20% attacks
- 22 features selected (16 raw + 6 engineered)
- Feature engineering: bytes_per_packet, burstiness, flag_sum, etc.

### Slide 9: Key Algorithm — XGBoost
- Gradient boosted decision trees
- Ensemble learning: 300 trees, max_depth=6
- Handles class imbalance via sample weighting
- Provides probability output for confidence gating
- Fast inference (<10ms per prediction)

### Slide 10: Two-Stage Pipeline
- Stage 1: Binary (BENIGN vs MALICIOUS)
- Stage 2: Attack Type (10 categories, only if malicious)
- Confidence gate: 80% threshold
- Benefits: 40% reduction in false positives vs single-stage

### Slide 11: Feature Engineering
- 16 raw features: ports, protocol, flow stats, TCP flags, TTL
- 6 derived features: bytes_per_packet, burstiness, etc.
- Flow aggregation: per (src_ip, dst_ip, protocol) tuple
- Rolling window of 50 packets for statistical stability

### Slide 12: Tools & Technologies
- Backend: Python, FastAPI, Uvicorn, SQLite
- ML: XGBoost, scikit-learn, Pandas, NumPy
- Network: Scapy, Npcap
- Frontend: HTML5, CSS3, JavaScript, Chart.js, WebSocket
- Version Control: Git, GitHub

### Slide 13: Implementation — Backend
- FastAPI server with 14 REST endpoints + WebSocket
- Real-time packet capture using Scapy AsyncSniffer
- SQLite database for log persistence
- IP blocking (memory + Windows Firewall modes)
- Screenshot: API Swagger docs

### Slide 14: Implementation — Dashboard
- 4 views: Analytics, Live Capture, Deep Inspect, Model Health
- Real-time WebSocket updates
- Chart.js visualizations
- Dark theme with modern UI design
- Screenshot: Main dashboard view

### Slide 15: Implementation — ML Pipeline
- Model training results: accuracy, precision, recall
- Confusion matrix
- Feature importance
- Confidence calibration results
- Screenshot: Model health view

### Slide 16: Demo / Screenshots
- Dashboard analytics view with live data
- Detection feed with SAFE/MALICIOUS verdicts
- Model health showing 22 features and two-stage configuration
- API endpoint documentation

### Slide 17: Results & Evaluation
- System processes packets in real-time (<10ms inference)
- Two-stage reduces false positives vs single-stage
- Handles encrypted traffic without payload inspection
- SQLite ensures zero-dependency deployment

### Slide 18: Challenges & Solutions
| Challenge | Solution |
|-----------|----------|
| False positives | Two-stage pipeline |
| Noisy per-packet predictions | Flow aggregation |
| Class imbalance | Balanced sample weights |
| Encrypted traffic | Metadata-only features |
| Real-time requirements | AsyncSniffer + WebSocket |

### Slide 19: Future Work
1. Deep learning models (LSTM, Transformer) for sequential patterns
2. TLS fingerprinting (JA3/JA4 hash integration)
3. Distributed deployment for multi-sensor networks
4. Automated model retraining on new threat data
5. MITRE ATT&CK mapping for attack classification

### Slide 20: Conclusion & Thank You
- Successfully built an end-to-end IDS for encrypted traffic
- Two-stage XGBoost with confidence gating reduces false positives
- Real-time dashboard with live capture and WebSocket streaming
- Fully self-contained: no external database dependencies
- **Thank you! Questions?**
