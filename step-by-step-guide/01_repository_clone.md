# Step 01 — Repository Clone & Directory Structure Verification

## 🎯 Objective
Clone the ET-IDS repository from GitHub and verify that all source files are present and correctly structured.

## 💡 Thought Process
The ET-IDS project is hosted on GitHub as a public repository. The first step is to clone it locally and examine the directory structure to understand what components are already built versus what needs to be created.

## 🔧 What I Did

### 1. Cloned the repository
```bash
git clone https://github.com/Pratyush-KumarSahani/ET-IDS.git .
```

### 2. Verified the directory structure
The repository contains:

| Directory/File | Purpose |
|---------------|---------|
| `et-ids/` | Main application folder containing all backend + frontend code |
| `et-ids/fastapi_ids_backend.py` | FastAPI web server with REST API + WebSocket |
| `et-ids/intrusion_detection.py` | ML model loading, prediction, two-stage detector |
| `et-ids/ids_realtime.py` | Live packet capture engine using Scapy |
| `et-ids/ids_storage.py` | SQLite-based persistence layer |
| `et-ids/ids_device.py` | Device identity management |
| `et-ids/train_fixed.py` | Corrected model training script |
| `et-ids/start_ids.ps1` | PowerShell launcher for easy startup |
| `et-ids/models/` | Pre-trained model artifacts (.pkl files) |
| `et-ids/static/` | Web dashboard (HTML, CSS, JS) |
| `et-ids/src/` | Jupyter notebooks for data processing & training |
| `src/` | Legacy API + real-time capture (older version) |
| `models/` | Root-level model copies |
| `logs/` | Log file directory |

### 3. Key Observations
- The project has **two versions**: 
  - `src/` contains an older version with MongoDB dependency
  - `et-ids/` contains the newer, self-contained version with SQLite
- The `et-ids/` folder is the **primary working directory**
- Pre-trained models are already present in `.pkl` format
- The web dashboard is a single-page application with Chart.js visualizations

## ✅ Result
Repository successfully cloned with 43 files across all directories. The newer `et-ids/` version is confirmed as the primary working application.
