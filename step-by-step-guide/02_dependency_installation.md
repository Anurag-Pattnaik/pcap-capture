# Step 02 — Dependency Installation

## 🎯 Objective
Install all required Python packages to run the ET-IDS system.

## 💡 Thought Process
The project requires several specialized libraries:
- **FastAPI + Uvicorn**: For the web server and async API
- **Scapy**: For live network packet capture and PCAP analysis
- **XGBoost + scikit-learn**: For the ML classification pipeline
- **Pandas + NumPy**: For data manipulation and feature engineering
- **joblib**: For model serialization/deserialization
- **python-multipart**: For file upload handling (PCAP uploads)

## 🔧 What I Did

### 1. Reviewed requirements.txt
```
fastapi
uvicorn[standard]
pydantic
python-multipart
pandas
numpy
scapy
joblib
scikit-learn
xgboost
```

### 2. Installed dependencies
```bash
pip install -r et-ids/requirements.txt
```

### 3. Verified critical imports
```python
import fastapi      # ✅ Web framework
import uvicorn      # ✅ ASGI server
import scapy        # ✅ Network packet capture
import xgboost      # ✅ Gradient boosting ML
import sklearn      # ✅ ML pipeline utilities
import joblib       # ✅ Model serialization
import pandas       # ✅ Data processing
import numpy        # ✅ Numerical computing
```

## ⚠️ Important Notes
- **Npcap** must be installed on Windows for Scapy live capture: https://npcap.com/#download
- **Administrator privileges** are required for live packet sniffing
- XGBoost requires compatible C++ runtime on Windows

## ✅ Result
All 10 dependencies successfully installed and verified.
