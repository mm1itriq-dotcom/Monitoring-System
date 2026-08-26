# Real-Time Threat Intelligence & Security Monitoring System (SIEM)

A high-performance Security Information and Event Management (SIEM) system built with **FastAPI**, **WebSockets**, **PostgreSQL** (via SQLAlchemy & Alembic), and a **React (Vite)** frontend dashboard.

---

## 🏗️ System Architecture & Data Flow

The system is designed as a **passive, real-time security monitor** with minimal latency. Data flows through a 3-step pipeline:

```
[ External Logs (Swagger / Terminal / pfSense) ]
                      │
                      ▼
[ FastAPI Backend Ingestion (`/api/ingest/log`) ]
                      │
           ┌──────────┴──────────┐
           ▼                     ▼
[ Rule & 3-Sigma Engine ]   [ PostgreSQL Database ]
 (Threat Evaluation)         (Persistent Storage)
           │                     │
           └──────────┬──────────┘
                      ▼
[ Real-Time WebSocket Push (`/ws/logs`) ]
                      │
                      ▼
[ Passive React Dashboard UI ]
```

1. **Log Ingestion & Parsing (`log_parser.py`)**: Accepts system, auth, and firewall logs via REST API (`/api/ingest/log`) and extracts IP addresses, event types, and metadata.
2. **Threat Detection & Database Persistence (`threat_detector.py`, `models.py`)**: 
   - Stores raw and parsed logs directly into the PostgreSQL `logs` table.
   - Evaluates logs against predefined rules and statistical anomaly algorithms.
   - Saves generated alerts into the PostgreSQL `threat_alerts` table.
3. **Low-Latency Real-Time Push (`main.py`, `App.jsx`)**: Instantly broadcasts logs and threat alerts over WebSocket connections (`/ws/logs`) to update the React frontend live without page reloads or polling.

---

## ✨ Features

- **Passive Read-Only SIEM Dashboard**: Clean, modern dark-mode React interface for live monitoring.
- **Rule-Based Threat Detection**: Automatically flags:
  - **SSH Brute-Force Attacks**: 5+ failed login attempts within 1 minute.
  - **Firewall Block Escalation**: 3+ blocked firewall events within 5 minutes.
  - **Port Scanning**: Traffic probing 4+ distinct destination ports in 2 minutes.
  - **Blacklisted IP Traffic**: Instant severity boost for traffic matching blacklisted IPs.
- **Statistical Anomaly Detection**: Uses a **3-Sigma (3 standard deviations)** rolling window to flag abnormal spikes in traffic volume.
- **IP Intelligence & Blacklisting**: Query rap sheets for specific IPs or add malicious IPs to the `blacklisted_ips` database table.
- **Alert Resolution System**: IT administrators can resolve active threat alerts directly from the dashboard.

---

## 🛠️ Technology Stack

- **Backend Framework**: Python 3.9+, FastAPI, Uvicorn, WebSockets
- **Database Layer**: PostgreSQL, SQLAlchemy 2.0, Alembic, Psycopg 3
- **Data & Analytics**: NumPy, Pandas
- **Frontend Framework**: React 18, Vite, Chart.js, Vanilla CSS (with responsive `rem` styling & glassmorphism aesthetics)

---

## 🚀 Setup & Installation

### 1. Prerequisites
- Python 3.9+ installed
- Node.js (v18+) & npm
- PostgreSQL service running on `localhost:5432`

### 2. Environment Configuration
Verify or edit `.env` in the project root directory:
```env
DATABASE_URL=postgresql+psycopg://postgres:123456@localhost:5432/threat_monitor
```

### 3. Backend Setup
Create a virtual environment and install backend dependencies:
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Database Migrations
Initialize PostgreSQL tables:
```bash
alembic upgrade head
```

### 5. Frontend Build
Compile the React application assets:
```bash
cd frontend
npm install
npm run build
cd ..
```
*Note: The FastAPI backend automatically serves the production build from `frontend/dist`.*

---

## ⚙️ Running the Application

### Production / All-In-One Mode
Run the FastAPI backend server (which also serves the React frontend at `/`):
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
- **Dashboard UI**: Access [`http://localhost:8000`](http://localhost:8000)
- **Interactive Swagger API Docs**: Access [`http://localhost:8000/docs`](http://localhost:8000/docs)

---

## 🧪 Testing & Demonstration Guide

Since the dashboard is a passive monitor, logs should be submitted via external requests.

### Option 1: Swagger Interactive UI
1. Open [`http://localhost:8000/docs`](http://localhost:8000/docs).
2. Expand `POST /api/ingest/log` and click **Try it out**.
3. Submit a log entry in the request body:
   ```json
   {
     "raw_log": "Failed password for root from 192.168.1.50 port 22 ssh2",
     "log_format": "auto"
   }
   ```
4. Watch the log instantly appear on the React dashboard live stream!

### Option 2: Terminal (cURL)
Simulate a brute-force SSH attack by sending multiple failed login requests:
```bash
for i in {1..5}; do
  curl -X POST "http://localhost:8000/api/ingest/log" \
       -H "Content-Type: application/json" \
       -d '{"raw_log": "Failed password for root from 192.168.1.50 port 22 ssh2"}'
  sleep 0.5
done
```
Upon the 5th request, a **Brute Force Authentication Attempt** threat alert will be generated, saved to PostgreSQL, and pushed live to the **Threat Alerts** tab on your React dashboard.

---

## 📌 Main API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Serves React dashboard application |
| `WS` | `/ws/logs` | Real-time WebSocket connection for live log/alert push |
| `POST` | `/api/ingest/log` | Ingest and parse raw system/firewall log |
| `GET` | `/api/logs/recent` | Retrieve recent ingested logs |
| `GET` | `/api/threats` | Retrieve threat alerts (supports severity & resolution filters) |
| `GET` | `/api/threats/stats` | Retrieve threat count metrics by severity |
| `POST` | `/api/threats/{id}/resolve` | Resolve a threat alert |
| `GET` | `/api/ip/{ip}/info` | Retrieve intelligence data and history for an IP |
| `POST` | `/api/ip/blacklist` | Add an IP address to the blacklist |