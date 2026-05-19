# Step 05 — Backend Startup

## 🎯 Objective
Start the FastAPI backend server and verify all components load correctly.

## 💡 Thought Process
The backend is the core of the system. It loads the ML models, initializes the SQLite database, sets up WebSocket connections for real-time streaming, and serves the static web dashboard. I need to verify all these components initialize without errors.

## 🔧 What I Did

### 1. Started the server
```bash
cd et-ids
python -m uvicorn fastapi_ids_backend:app --host 0.0.0.0 --port 8000
```

### 2. Startup output confirmed:
```
INFO:     Started server process [23692]
INFO:     Waiting for application startup.
2026-05-19 | INFO | intrusion_detection | Loaded two-stage detector
  binary=F:\My Drive\ET-IDS\et-ids\models\binary_pipeline.pkl
  attack=F:\My Drive\ET-IDS\et-ids\models\attack_pipeline.pkl
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

### 3. What loads during startup
| Component | Status | Details |
|-----------|--------|---------|
| FastAPI app | ✅ | Version 3.0.0, "Encrypted Traffic IDS" |
| CORS middleware | ✅ | All origins allowed by default |
| Two-stage detector | ✅ | Binary + Attack pipelines loaded |
| SQLite storage | ✅ | `data/ids.db` created/opened |
| Block manager | ✅ | Memory mode (no firewall rules) |
| Device identity | ✅ | UUID generated or loaded from `data/device_id` |
| Static files | ✅ | Dashboard served from `/static/` |

### 4. Available API endpoints
- `GET /` — Dashboard (HTML)
- `GET /health` — System health check
- `POST /detect` — Single prediction
- `POST /capture/start` — Start live capture
- `POST /capture/stop` — Stop live capture
- `GET /capture/status` — Capture status
- `GET /capture/interfaces` — List network interfaces
- `GET /logs` — Get packet logs
- `POST /logs/export` — Export to CSV
- `POST /pcap/analyze` — Upload PCAP for analysis
- `GET /blocklist` — View blocked IPs
- `POST /blocklist` — Block an IP
- `DELETE /blocklist/{ip}` — Unblock an IP
- `WebSocket /ws/logs` — Real-time log stream

## 📸 Screenshots
See: `screenshots/05_api_swagger_docs.png` and `screenshots/06_health_endpoint.png`

## ✅ Result
Backend started successfully on port 8000 with all models loaded, database initialized, and 14 API endpoints active.
