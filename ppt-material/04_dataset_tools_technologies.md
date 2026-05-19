# PPT Material: Dataset, Tools & Technologies
## ET-IDS — Encrypted Traffic Intrusion Detection System

---

## 1. Dataset

### CICIDS-2017 (CIC Intrusion Detection Systems 2017)

| Property | Details |
|----------|---------|
| **Provider** | Canadian Institute for Cybersecurity (CIC), University of New Brunswick |
| **Year** | 2017 |
| **Duration** | 5 days of network traffic (Monday–Friday) |
| **Total Flows** | ~2.8 million |
| **Features** | 80+ per flow (we use 22) |
| **Attack Types** | 14+ categories |
| **Format** | CSV files (one per day) |
| **License** | Open access for academic use |
| **Citations** | 2,500+ (most cited IDS dataset) |

### Attack Categories in Dataset
| Category | Day | Examples |
|----------|-----|---------|
| BENIGN | Monday | Normal legitimate web, email, file transfer |
| Brute Force | Tuesday | FTP Patator, SSH Patator |
| DoS | Wednesday | Slowloris, Hulk, GoldenEye, Slowhttptest |
| Heartbleed | Wednesday | OpenSSL Heartbleed exploit |
| Web Attack | Thursday | SQL Injection, XSS, Brute Force login |
| Infiltration | Thursday | Dropbox downloads, network sweep |
| Botnet | Friday | Ares botnet C&C communication |
| Port Scan | Friday | TCP, UDP, SYN scanning |
| DDoS | Friday | LOIT DDoS attack |

### Data Distribution (Approximate)
```
BENIGN:      ~80% (majority class)
DDoS:         ~5%
DoS:          ~5%
Port Scan:    ~4%
Brute Force:  ~3%
Web Attack:   ~1%
Botnet:       ~1%
Infiltration: ~0.5%
Others:       ~0.5%
```

---

## 2. Tools & Technologies

### Core Stack

| Technology | Version | Role |
|------------|---------|------|
| **Python** | 3.12+ | Primary programming language |
| **FastAPI** | Latest | Async web framework for REST API |
| **Uvicorn** | Latest | ASGI server for FastAPI |
| **XGBoost** | Latest | Gradient boosted trees for classification |
| **scikit-learn** | Latest | ML pipeline, preprocessing, evaluation |
| **Scapy** | Latest | Network packet capture and analysis |
| **Pandas** | Latest | Data manipulation and feature engineering |
| **NumPy** | Latest | Numerical computing |
| **joblib** | Latest | Model serialization/deserialization |
| **SQLite** | Built-in | Embedded database for log persistence |

### Frontend Stack

| Technology | Role |
|------------|------|
| **HTML5** | Page structure and semantic markup |
| **CSS3** | Custom dark theme with glassmorphism effects |
| **Vanilla JavaScript** | Dashboard logic, WebSocket client, DOM manipulation |
| **Chart.js** | Analytics visualizations (line, bar, doughnut, pie) |
| **Font Awesome 6** | Icons for navigation and status indicators |
| **Inter + JetBrains Mono** | Typography (Google Fonts) |
| **WebSocket API** | Real-time bidirectional communication |

### Development & Deployment

| Tool | Purpose |
|------|---------|
| **Jupyter Notebooks** | Model training and data exploration |
| **Npcap** | Windows packet capture driver (required for Scapy) |
| **Git** | Version control |
| **PowerShell** | Automated launcher script |

### Key Python Libraries Explained

#### FastAPI
- Modern, high-performance web framework
- Automatic OpenAPI/Swagger documentation
- Native async/await support
- Pydantic-based request/response validation
- WebSocket support built-in

#### XGBoost (Extreme Gradient Boosting)
- State-of-the-art gradient boosted decision trees
- Handles missing values natively
- Built-in regularization (L1/L2)
- Parallelized training
- Feature importance scores

#### Scapy
- Packet crafting, capture, and analysis library
- Supports BPF (Berkeley Packet Filter) syntax
- Protocol dissection for TCP/UDP/ICMP/IP
- PCAP file reading and writing
- AsyncSniffer for non-blocking capture

#### scikit-learn
- StandardScaler for feature normalization
- LabelEncoder for class encoding
- Pipeline for chaining preprocessing + model
- CalibratedClassifierCV for probability calibration
- classification_report for model evaluation

---

## 3. Technology Architecture Map

```
┌─────────────────────────────────────────────────┐
│              FRONTEND TECHNOLOGIES               │
│                                                   │
│  HTML5 ─── CSS3 ─── JavaScript ─── Chart.js      │
│  WebSocket API ─── Font Awesome ─── Inter Font   │
├─────────────────────────────────────────────────┤
│              BACKEND TECHNOLOGIES                 │
│                                                   │
│  FastAPI ─── Uvicorn ─── Pydantic ─── SQLite     │
│  python-multipart (file uploads)                  │
├─────────────────────────────────────────────────┤
│              ML / DATA SCIENCE                    │
│                                                   │
│  XGBoost ─── scikit-learn ─── Pandas ─── NumPy  │
│  joblib ─── LabelEncoder ─── StandardScaler      │
│  CalibratedClassifierCV (isotonic calibration)   │
├─────────────────────────────────────────────────┤
│              NETWORK ANALYSIS                     │
│                                                   │
│  Scapy ─── AsyncSniffer ─── PcapReader           │
│  Npcap (Windows driver) ─── BPF Filters          │
└─────────────────────────────────────────────────┘
```

---

## 4. Hardware/Software Requirements

### Minimum Requirements
| Component | Requirement |
|-----------|-------------|
| OS | Windows 10/11 (64-bit) |
| Python | 3.11 or 3.12 |
| RAM | 4 GB (8 GB recommended) |
| Storage | 500 MB for models + dataset |
| Network | Any network interface |
| Browser | Chrome, Firefox, Edge (modern) |
| Driver | Npcap (for live capture) |
| Privileges | Administrator (for packet capture) |
