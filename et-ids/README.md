# ET-IDS: Submodule Directory & ML Pipeline

This folder contains the core implementation of the **Encrypted Traffic Intrusion Detection System (ET-IDS)**.

---

## 📂 Core Folder Components

*   `models/` - Pickled two-stage XGBoost model pipelines, label encoders, and feature column sequence files.
*   `static/` - HTML5, glassmorphism CSS3, and Chart.js UI assets for the WebSocket dashboard.
*   `fastapi_ids_backend.py` - Core FastAPI web application hosting REST routes and WebSocket live log streams.
*   `ids_realtime.py` - Network flow aggregator and packet sniffer (using Scapy), featuring an auto-simulation thread fallback.
*   `ids_storage.py` - SQLite interaction layer persistence.
*   `intrusion_detection.py` - ML model load and Two-Stage scoring engine wrapper.
*   `integrate_datasets.py` - Clean, bug-free standalone merging script for the consolidated datasets.
*   `train_unified.py` - Clean, bug-free standalone model training pipeline script.

---

## 🚀 Running locally

To install dependencies and start the system, run from this directory:
```bash
# 1. Install packages
pip install -r requirements.txt

# 2. Start the FastAPI server
python -m uvicorn fastapi_ids_backend:app --reload --host 127.0.0.1 --port 8000
```
👉 Open your browser to `http://127.0.0.1:8000` to view the running dashboard!

---

## 🛠️ Model Re-Training (Scratch)

To merge the raw datasets and re-train the models cleanly:
```bash
python integrate_datasets.py
python train_unified.py
```
👉 This overwrites and updates the pickled files in the `models/` subdirectory!
