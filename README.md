## 🚀 Setup & Run Instructions

### 📥 1. Download Dataset

* Open the link:
  https://drive.proton.me/urls/KQM4B3EBE0#2yga3D5TlsNJ
* Download all files
* Extract (if zipped)

---

### 📁 2. Place Dataset

Move all downloaded CSV files into:

```
data/raw/
```

Final structure should look like:

```
ET-IDS/
│── data/
│   └── raw/
│       ├── Monday-WorkingHours.pcap_ISCX.csv
│       ├── Tuesday-WorkingHours.pcap_ISCX.csv
│       └── ...
```

---

### 📦 3. Install Requirements

Open terminal in project folder:

```
pip install -r requirements.txt
```

### ⚙️ 4. Run FAST API

Start backend API:

```
uvicorn src.api:app --reload

```

👉 This will load the trained model and start the server

---

### 🔁 5. Run Real Time Data Capture

In a new terminal:

```
python real_time.py
```

---

### 🧪 6. Final Observation

*Real Time Capture Script will :

  * Capture real time data
  * Send requests to API
  * Display predictions (BENIGN / MALICIOUS)

---

### ⚠️ Notes

* Make sure dataset is placed correctly before training
* Keep API running while simulation runs

---
