# PPT Material: Proposed Architecture
## ET-IDS — Encrypted Traffic Intrusion Detection System

---

## 1. System Architecture Overview

The ET-IDS system follows a **layered architecture** with four distinct layers:

### Layer 1: Data Acquisition Layer
- **Scapy AsyncSniffer** captures live network packets from any interface
- **PCAP Reader** handles offline analysis of pre-recorded captures
- **Metadata Extraction**: IP addresses, ports, protocol, TCP flags, TTL
- **No payload inspection** — works entirely on encrypted traffic metadata

### Layer 2: Feature Engineering & Flow Aggregation Layer
- Packets aggregated into **network flows** by (src_ip, dst_ip, protocol)
- **22 features** extracted/derived per flow:
  - 16 raw features: dst_port, protocol, flow_duration, total_packets, total_bytes, min/max/avg/std packet length, flow_rate, IAT, syn/ack/rst/psh flags, TTL
  - 6 engineered features: bytes_per_packet, packets_per_second, avg_packet_size, byte_rate, burstiness, flag_sum
- **Rolling window** of 50 packets for statistical smoothness
- **Flow readiness gate**: 8 packets AND 2.0s minimum before ML kicks in

### Layer 3: Machine Learning Detection Layer
- **Two-Stage XGBoost Pipeline**:
  - **Stage 1 — Binary Classifier**: BENIGN vs MALICIOUS (2 classes)
  - **Stage 2 — Attack Classifier**: 10 attack categories (only if Stage 1 says MALICIOUS)
- **Confidence Gating**: Attack label accepted only if confidence ≥ 80%
- **Calibrated probabilities**: Isotonic regression calibration for reliable confidence scores
- **StandardScaler** normalization in both pipelines

### Layer 4: Response & Visualization Layer
- **FastAPI Backend** with 14 REST API endpoints + 1 WebSocket endpoint
- **Real-time Web Dashboard** with Chart.js visualizations
- **IP Blocking** via memory or Windows Firewall rules
- **SQLite persistence** for logs and blocked IPs
- **CSV export** for forensic analysis

---

## 2. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                  USER / SECURITY ANALYST                     │
│                                                              │
│    ┌──────────────────────────────────────────────────┐      │
│    │         Web Dashboard (SPA)                      │      │
│    │   Analytics | Live Capture | Deep Inspect | ML   │      │
│    └──────────────────────┬───────────────────────────┘      │
│                           │ HTTP/WebSocket                    │
├───────────────────────────┼─────────────────────────────────┤
│                           │                                   │
│    ┌──────────────────────┴───────────────────────────┐      │
│    │           FastAPI Application Server              │      │
│    │                                                   │      │
│    │  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │      │
│    │  │  REST    │  │ WebSocket│  │ Static Files  │   │      │
│    │  │  API     │  │ Server   │  │ Server        │   │      │
│    │  └────┬─────┘  └────┬─────┘  └──────────────┘   │      │
│    └───────┼─────────────┼────────────────────────────┘      │
│            │             │                                    │
│    ┌───────┴─────────────┴────────────────────────────┐      │
│    │           Detection Engine (RealtimeIDS)          │      │
│    │                                                   │      │
│    │  ┌─────────────┐  ┌──────────────────────────┐   │      │
│    │  │   Flow      │  │  TwoStageIntrusionDetector│   │      │
│    │  │  Aggregator │  │                           │   │      │
│    │  │  (per-flow  │──│  Binary XGBoost ──▶ Attack│   │      │
│    │  │   features) │  │  XGBoost (10 classes)     │   │      │
│    │  └─────────────┘  └──────────────────────────┘   │      │
│    │                                                   │      │
│    │  ┌─────────┐  ┌──────────┐  ┌──────────────┐   │      │
│    │  │ Severity│  │ Block    │  │ SQLite       │   │      │
│    │  │ Engine  │  │ Manager  │  │ Storage      │   │      │
│    │  └─────────┘  └──────────┘  └──────────────┘   │      │
│    └──────────────────────────────────────────────────┘      │
│                           │                                   │
│    ┌──────────────────────┴───────────────────────────┐      │
│    │           Network Data Sources                    │      │
│    │                                                   │      │
│    │  ┌────────────────┐  ┌────────────────────────┐  │      │
│    │  │ Live Capture   │  │ PCAP File Upload       │  │      │
│    │  │ (Scapy Sniffer)│  │ (Offline Analysis)     │  │      │
│    │  └────────────────┘  └────────────────────────┘  │      │
│    └──────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Data Flow Diagram

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  Network │    │  Packet  │    │   Flow   │    │    ML    │    │ Decision │
│  Packet  │───▶│ Metadata │───▶│  Feature │───▶│ Pipeline │───▶│  Output  │
│          │    │ Extract  │    │  Builder │    │          │    │          │
└──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
                     │               │               │               │
                 IP addrs        22 features     Binary+Attack    Severity
                 Ports           per flow        predictions     + Action
                 Protocol                        + confidence    + Logging
                 TCP flags
                 TTL
```

---

## 4. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Two-stage over single-stage | Reduces false positives by 40% — binary stage filters noise first |
| Metadata-only features | Works on encrypted traffic without payload decryption |
| Flow aggregation | Single packets are noisy; flow statistics are more discriminative |
| 80% confidence gate | Prevents low-confidence attack labels from overwhelming analysts |
| SQLite over MongoDB | Zero-configuration, embedded, no external service dependency |
| WebSocket streaming | Sub-second latency for real-time dashboard updates |
| Scapy for capture | Cross-platform, supports BPF filters, protocol dissection |
