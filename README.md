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

---

### 🧠 4. Train Model (Jupyter Notebook)

Run the notebook:

```
src/train.ipynb
```

Execute cells **in order (top to bottom):**

1. Import libraries
2. Load dataset (`data/raw/`)
3. Data preprocessing
4. Feature selection
5. Train model
6. Evaluate model
7. Save model (`.pkl` file in models/)

---

### ⚙️ 5. Run API

Start backend API:

```
python src/api.py
```

👉 This will load the trained model and start the server

---

### 🔁 6. Run Simulation

In a new terminal:

```
python src/simulate.py
```

---

### 🧪 7. Test with Simulated Data

* Simulation script will:

  * Generate/test network traffic data
  * Send requests to API
  * Display predictions (Normal / Attack)

---

### ⚠️ Notes

* Make sure dataset is placed correctly before training
* Train model first before running API
* Keep API running while simulation runs

---
