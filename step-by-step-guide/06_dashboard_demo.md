# Step 06 — Dashboard Demo

## 🎯 Objective
Explore the web dashboard and verify all views, charts, and interactive features work correctly.

## 💡 Thought Process
The dashboard is the primary user interface for the ET-IDS system. It provides real-time analytics, live packet feeds, threat detection displays, model health monitoring, and manual response capabilities. I need to test each view to confirm functionality.

## 🔧 What I Did

### 1. Analytics View (Default)
- **KPI Cards**: Shows Flows Analyzed (4566), Threats Detected (1055), Encrypted Flows (2312), Unique Signatures (5)
- **Traffic Volume Chart**: Line chart showing Safe vs Threat traffic over time
- **Attack Distribution**: Doughnut chart showing attack type breakdown (BruteForce, DoS)
- **Top Target Ports**: Bar chart showing most targeted ports (22675, 5353, 47472, 443, etc.)
- **Top Source IPs**: Horizontal bar chart showing most active source IPs
- **Protocol Distribution**: Pie chart showing TCP vs UDP ratio
- **Deduplicated Alerts**: Shows unique alerts with severity, count, and source/destination
- **Detection Feed**: Real-time table with timestamp, source, destination port, verdict (SAFE/MALICIOUS), attack class, and severity

### 2. Live Capture View
- Sensor Control panel with interface selection and capture filter
- Start/Stop capture buttons
- Detection feed table
- Manual IP blocking interface

### 3. Deep Inspect View
- Alert timeline with time-bucketed visualization
- Sensor & Policy information
- Detection source rules documentation

### 4. Model Health View
- Model type: two_stage
- Binary model path and Attack model path confirmed
- Decision gate: High (80% threshold)
- Feature columns: 22 features displayed as tag cloud
- Flow gate: 8 packets / 2s minimum for ML classification

## 📸 Screenshots
See: 
- `screenshots/01_dashboard_analytics.png`
- `screenshots/02_live_capture_view.png`
- `screenshots/03_deep_inspect_view.png`
- `screenshots/04_model_health_view.png`

## ✅ Result
All 4 dashboard views fully functional with real-time WebSocket updates, interactive charts, and responsive design.
