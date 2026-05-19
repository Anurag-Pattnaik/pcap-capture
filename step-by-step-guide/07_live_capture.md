# Step 07 — Live Packet Capture

## 🎯 Objective
Test real-time network packet capture using Scapy and verify that packets flow through the ML classification pipeline.

## 💡 Thought Process
Live capture is the core differentiator of this IDS. It uses Scapy's AsyncSniffer to capture packets in a background thread, aggregates them into flows, then runs the two-stage XGBoost classifier to produce real-time verdicts. The results stream to the dashboard via WebSocket.

## 🔧 How Live Capture Works

### Flow Aggregation Pipeline
```
Network Interface
       │
       ▼
  Scapy AsyncSniffer (background thread)
       │
       ▼
  Packet Metadata Extraction
  (IP src/dst, ports, protocol, TCP flags, TTL)
       │
       ▼
  Flow Aggregation (by src_ip + dst_ip + protocol)
  - total_packets, total_bytes, flow_duration
  - min/max/avg/std packet lengths
  - packet rate, byte rate, burstiness
       │
       ▼
  Flow Readiness Gate
  (≥ 8 packets AND ≥ 2 seconds duration)
       │
       ▼
  Two-Stage ML Classification
  Stage 1: Binary (BENIGN vs MALICIOUS)
  Stage 2: Attack Type (if MALICIOUS, confidence ≥ 80%)
       │
       ▼
  Decision Output → SQLite Storage → WebSocket Broadcast
```

### Starting Capture via Dashboard
1. Navigate to the dashboard at `http://localhost:8000`
2. In the sidebar, set the Interface (or leave as default)
3. Set capture filter (e.g., `tcp or udp`)
4. Click **Start**

### Starting Capture via API
```bash
curl -X POST http://localhost:8000/capture/start \
  -H "Content-Type: application/json" \
  -d '{"interface": null, "packet_filter": "tcp or udp"}'
```

## ⚠️ Prerequisites
1. **Npcap** must be installed on Windows (https://npcap.com/#download)
2. **Administrator privileges** — PowerShell must be run as Admin for packet sniffing
3. The server must be running before starting capture

## 📊 Detection Severity Levels
| Severity | Description | Trigger |
|----------|-------------|---------|
| `critical` | DDoS, DoS, Botnet, Infiltration | ML + high confidence |
| `high` | Brute force, Exploits, Web attacks, Port scans | ML + high confidence |
| `medium` | Suspicious, anomalous, or generic attack | ML + moderate confidence |
| `info` | Normal/benign traffic, flow warmup | ML benign or warming up |

## ✅ Result
Live capture system is fully operational with real-time flow aggregation, ML classification, WebSocket streaming, and severity-based alerting.
