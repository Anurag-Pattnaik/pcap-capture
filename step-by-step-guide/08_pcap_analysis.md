# Step 08 — PCAP Analysis (Offline Mode)

## 🎯 Objective
Test offline PCAP file analysis to classify pre-recorded network traffic.

## 💡 Thought Process
Not all IDS work needs to be real-time. Security analysts often need to analyze historical PCAP captures. The system supports uploading `.pcap`, `.pcapng`, or `.cap` files for offline analysis using the same ML pipeline.

## 🔧 How PCAP Analysis Works

### Upload via Dashboard
1. Navigate to the dashboard
2. In the sidebar under "Evidence" section
3. Click "Choose file" and select a PCAP file
4. Click **Analyze PCAP**
5. Results show: `X packets analyzed / Y alerts added`
6. Detection feed table updates with all analyzed packets

### Upload via API
```bash
curl -X POST http://localhost:8000/pcap/analyze \
  -F "file=@capture.pcap" \
  -F "packet_limit=5000"
```

### Response Format
```json
{
  "filename": "capture.pcap",
  "processed_packets": 1234,
  "alert_count": 56,
  "packet_limit": 5000
}
```

### Processing Pipeline
1. PCAP file uploaded → saved to temp directory
2. Scapy's `PcapReader` reads packets sequentially
3. Each packet processed through same pipeline as live capture
4. Flow aggregation, feature engineering, ML classification
5. Results stored in SQLite and broadcast via WebSocket
6. Temp file deleted after analysis
7. Dashboard updates with new data

### Export Functionality
- Click **Export Logs** to export all detection results to CSV
- CSV saved to `data/exports/ids_logs.csv`
- Contains all packet metadata, predictions, severity, and timestamps

## ✅ Result
PCAP analysis endpoint working with up to 50,000 packets per upload, with automatic flow aggregation and ML classification.
