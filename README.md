# ET-IDS: Encrypted Traffic Intrusion Detection System

An enterprise-grade, real-time **Encrypted Network Intrusion Detection System (ET-IDS)** that uses a state-of-the-art Two-Stage ensemble machine learning pipeline (XGBoost) and flow-based aggregation to identify malicious activities directly from network traffic metadata without decrypting packets.

---

## 🌟 Key Features

*   **Two-Stage Detection Pipeline**:
    *   **Stage 1 (Calibrated Binary Filter)**: Evaluates whether incoming network flows are `BENIGN` or `MALICIOUS` using an Isotonic calibrated probability threshold to achieve near-zero false-positive rates on normal traffic.
    *   **Stage 2 (Multiclass Classifier)**: If malicious, dynamically categorizes the flow into 10 distinct attack categories (DDoS, DoS, Recon, Botnet, IoT, WebAttack, BruteForce, Malware, MITM, or Other).
*   **Flow-Based Aggregation**: Aggregates raw IP packets into standard bidirectional network flows on a rolling time-window to extract 22 core features.
*   **Encrypted Traffic Visibility**: Evaluates ONLY protocol headers and metadata (like TLS handshake specs) to respect user privacy and operate cleanly on HTTPS/TLS traffic.
*   **Stunning Dark Dashboard**: Full SPA built with HTML5, CSS3 glassmorphism, and Chart.js containing real-time KPI metrics, threat feeds, WebSocket streams, and live chart animations.
*   **Active Defense (IP Blocking)**: Includes built-in auto-blocking policies that integrate with Windows Firewall to shield the host in real time.
*   **Offline PCAP Analysis**: Allows users to upload standard `.pcap`, `.pcapng`, or `.cap` capture logs for instant offline threat assessment and CSV exports.

---

## 📂 Project Structure

```
ET-IDS/
├── data/
│   └── raw/                       # Place raw dataset CSVs here
├── et-ids/
│   ├── models/                    # Saved ML model artifacts (.pkl)
│   ├── static/                    # Frontend glassmorphism Dashboard files
│   ├── data/                      # Local SQLite log databases
│   ├── fastapi_ids_backend.py     # FastAPI core web API and sniffer
│   ├── ids_realtime.py            # Aggregator, sniffer, and mock simulator
│   ├── ids_storage.py             # SQLite persistence layer
│   ├── ids_device.py              # Unique device identity manager
│   ├── intrusion_detection.py     # Two-Stage XGBoost classifier code
│   ├── integrate_datasets.py      # Standing data-merging pipeline
│   ├── train_unified.py           # Standing two-stage model training
│   ├── start_ids.ps1              # Full powershell launcher script
│   └── requirements.txt           # Python dependency checklist
├── step-by-step-guide/            # Full system walkthrough markdown guides
├── ppt-material/                  # Slides content and figures for defenses
├── integrate_datasets.py          # Standalone dataset integration launcher
├── train_unified.py               # Standalone training pipeline launcher
└── README.md                      # This main documentation sheet
```

---

## 📥 1. Dataset & Re-Training Setup

This project is trained on four highly-cited, industry-standard benchmark NIDS datasets consolidated into a clean, normalized structure:
1. **CICIDS2017** (DoS, DDoS, Web Attacks)
2. **NF-UNSW-NB15-v2** (Modern web exploits)
3. **NF-ToN-IoT-v2** (Industrial & Internet of Things attacks)
4. **CICIOT2023** (Connected device threat vectors)

### Get the Dataset
*   Download the preprocessed CSV package from Google Drive:
    👉 **[Download Dataset CSV Files](https://drive.google.com/file/d/1F_0ZUcVap4OPr0Z1unpHa7sEFjz-37xR/view?usp=drive_link)**
*   Extract the CSV files into:
    `data/raw/` (e.g. `data/raw/cicids2017/`, `data/raw/nf_ton_iot/`, etc.)

### One-Click Re-Integration & Re-Training (From Scratch)
If you want to merge these datasets and train the models cleanly from scratch on your own machine, simply run:
```powershell
# Step A: Integrate the raw datasets with correct binary mapping fixes
python integrate_datasets.py

# Step B: Train the two-stage XGBoost pipelines with standard features
python train_unified.py
```
👉 This will rebuild `models/` automatically!

---

## 🚀 Installation & Running

### Step A: Install Requirements
Open a terminal in the project folder and install the dependencies:
```bash
pip install -r et-ids/requirements.txt
```

### Step B: Launch the System
For a zero-friction launch (which automatically tests dependencies, binds network interfaces, and launches the dashboard in your default browser), run our PowerShell launcher script:
```powershell
.\et-ids\start_ids.ps1
```
*Note: If Npcap or a capture driver is missing on your machine, the system will automatically fall back to an active simulation thread so that you can demonstrate the live dashboard and KPI updates without breaking!*

---

## 🧪 Technology Stack Used

*   **Backend**: Python, FastAPI, Uvicorn, Scapy (Sniffing & PCAP aggregation)
*   **Machine Learning**: XGBoost, scikit-learn, joblib, CalibratedClassifierCV
*   **Database**: SQLite (Zero config, light relational logs persistence)
*   **Frontend**: HTML5, custom CSS3, Vanilla JS, Chart.js, WebSocket API
