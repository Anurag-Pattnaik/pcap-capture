# Step 09 — Architecture Deep Dive

## 🎯 Objective
Document the complete system architecture, design decisions, and technical implementation details.

## 📐 System Architecture

### High-Level Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Single-Page Application (SPA)                           │   │
│  │  • HTML5 + Vanilla CSS + JavaScript                      │   │
│  │  • Chart.js for analytics visualizations                 │   │
│  │  • WebSocket for real-time streaming                     │   │
│  │  • 4 views: Analytics, Live Capture, Deep Inspect, Model │   │
│  └──────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                    APPLICATION LAYER                             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  FastAPI v3.0.0 (ASGI Web Framework)                     │   │
│  │  • REST API: 14 endpoints (CRUD + detection)             │   │
│  │  • WebSocket: /ws/logs for real-time streaming           │   │
│  │  • CORS middleware for cross-origin support               │   │
│  │  • Static file serving for dashboard                     │   │
│  │  • Lifespan management for startup/shutdown              │   │
│  └──────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                    DETECTION ENGINE                              │
│  ┌────────────────────┐  ┌────────────────────────────────┐    │
│  │  RealtimeIDS        │  │  TwoStageIntrusionDetector     │    │
│  │  ├─ Flow Aggregator │  │  ├─ Stage 1: Binary XGBoost   │    │
│  │  ├─ Feature Builder │  │  │  (BENIGN vs MALICIOUS)      │    │
│  │  ├─ Severity Engine │  │  ├─ Stage 2: Attack XGBoost   │    │
│  │  └─ WebSocket Pub   │  │  │  (10 attack categories)     │    │
│  └────────────────────┘  │  └─ Confidence Gating (≥80%)   │    │
│                          └────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│                    DATA LAYER                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐    │
│  │  Scapy        │  │  SQLite       │  │  BlockManager     │    │
│  │  AsyncSniffer │  │  (ids.db)     │  │  (Memory/Firewall)│    │
│  │  PcapReader   │  │  packet_logs  │  │  Rule: netsh      │    │
│  └──────────────┘  │  blocked_ips  │  └───────────────────┘    │
│                    └──────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
```

## 🧠 ML Pipeline Design

### Two-Stage Classification Architecture
```
                    Input: 22 network flow features
                                │
                    ┌───────────┴───────────┐
                    │   StandardScaler       │
                    │   (normalize features) │
                    └───────────┬───────────┘
                                │
                    ┌───────────┴───────────┐
                    │   Stage 1: Binary     │
                    │   XGBoost Classifier  │
                    │   n_estimators=300    │
                    │   max_depth=6         │
                    │   learning_rate=0.05  │
                    └───────────┬───────────┘
                                │
                    ┌───────────┴───────────┐
                    │                       │
                BENIGN                  MALICIOUS
                    │                       │
            Return "Safe"        ┌──────────┴──────────┐
                                 │  Stage 2: Attack    │
                                 │  XGBoost Classifier │
                                 │  10-class multi     │
                                 └──────────┬──────────┘
                                            │
                                 ┌──────────┴──────────┐
                                 │                     │
                          Confidence ≥ 80%      Confidence < 80%
                                 │                     │
                          Attack Label          "Suspicious"
                          (DDoS, BruteForce,    (Low confidence,
                           Botnet, etc.)         needs monitoring)
```

### Feature Engineering Pipeline
| # | Feature | Source | Description |
|---|---------|--------|-------------|
| 1 | dst_port | Packet | Destination port number |
| 2 | protocol | Packet | IP protocol number (TCP=6, UDP=17) |
| 3 | flow_duration | Flow | Time since first packet in flow |
| 4 | total_packets | Flow | Cumulative packet count in flow |
| 5 | total_bytes | Flow | Cumulative byte count in flow |
| 6 | min_pkt_len | Flow | Minimum packet length in window |
| 7 | max_pkt_len | Flow | Maximum packet length in window |
| 8 | avg_pkt_len | Flow | Mean packet length in window |
| 9 | pkt_len_std | Flow | Standard deviation of lengths |
| 10 | flow_rate | Flow | Bytes per second |
| 11 | iat | Packet | Inter-arrival time |
| 12-15 | syn/ack/rst/psh_flag | Packet | TCP flag indicators |
| 16 | ttl | Packet | Time to live |
| 17 | bytes_per_packet | Derived | total_bytes / total_packets |
| 18 | packets_per_second | Derived | total_packets / flow_duration |
| 19 | avg_packet_size | Derived | total_bytes / total_packets |
| 20 | byte_rate | Derived | total_bytes / flow_duration |
| 21 | burstiness | Derived | pkt_len_std / avg_pkt_len |
| 22 | flag_sum | Derived | syn + ack + rst + psh |

### Flow Readiness Gate
ML classification only activates after:
- **Minimum 8 packets** accumulated in the flow
- **Minimum 2.0 seconds** of flow duration
- This prevents noisy predictions from incomplete flows

### Confidence Gating
- Binary classification always runs
- Attack classification runs ONLY if binary says MALICIOUS
- Attack label accepted ONLY if confidence ≥ 80%
- Below 80%: labeled "Suspicious" (needs human review)

## 🔐 Security Features

### IP Blocking
- **Memory mode**: Block IPs in application memory (default)
- **Windows Firewall mode**: Create actual firewall rules via `netsh`
- Blocked IPs tracked in SQLite `blocked_ips` table
- Blocked traffic marked with `action: "blocked"` in logs

### Encrypted Traffic Detection
- Ports 443, 465, 563, 853, 993, 995, 8443 flagged as encrypted
- Encrypted traffic classified using metadata only (no payload inspection)
- This is the key innovation: detecting threats in encrypted traffic

## 💾 Data Persistence

### SQLite Schema
```sql
CREATE TABLE packet_logs (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT NOT NULL,
    flow_id TEXT NOT NULL DEFAULT 'LEGACY',
    flow_packet_count INTEGER NOT NULL DEFAULT 0,
    flow_byte_count INTEGER NOT NULL DEFAULT 0,
    flow_duration REAL NOT NULL DEFAULT 0,
    length INTEGER NOT NULL,
    time_diff REAL NOT NULL,
    packet_rate REAL NOT NULL,
    avg_length REAL NOT NULL,
    encrypted_likely INTEGER NOT NULL,
    prediction TEXT NOT NULL,
    ml_confidence REAL,
    binary_label TEXT,
    attack_label TEXT,
    severity TEXT NOT NULL DEFAULT 'info',
    signature TEXT NOT NULL DEFAULT 'Metadata baseline',
    rule_id TEXT NOT NULL DEFAULT 'META-0000',
    action TEXT NOT NULL,
    reason TEXT NOT NULL
);

CREATE TABLE blocked_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

## 🌐 Real-Time Communication

### WebSocket Protocol
- Endpoint: `ws://host:port/ws/logs`
- On connect: sends `{"type": "snapshot", "data": [...]}` with last 100 logs
- On new packet: sends `{"type": "packet_log", "data": {...}}`
- On blocklist change: sends `{"type": "blocklist", "data": {...}}`
- Auto-reconnects on disconnect (1.5s delay)

## ✅ Result
Complete architecture documented with all layers, ML pipeline, feature engineering, security features, and data persistence.
