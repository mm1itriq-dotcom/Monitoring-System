# Real-Time Threat Intelligence & Monitoring System

A lightweight, high-performance Security Information and Event Management (SIEM) system built with **FastAPI**, **WebSockets**, **SQLAlchemy**, and a **React/Vite** frontend.

## Features
- **Real-Time Log Ingestion**: Accept system and firewall logs via a REST API.
- **Rules-Based Threat Detection**: Automatically flags brute-force SSH logins, port scanning, and blacklisted IP traffic.
- **Statistical Anomaly Detection**: Uses a 3-sigma (standard deviation) rolling window to detect abnormal spikes in connection frequency.
- **WebSocket Live Stream**: Instantly broadcasts parsed logs and security alerts to the frontend dashboard.
- **IP Intelligence & Blacklisting**: Monitor IP addresses and prevent repeat attacks.

## Architecture
- **Backend:** Python, FastAPI, WebSockets, Pandas, Numpy.
- **Database:** PostgreSQL (production) or SQLite (development) via SQLAlchemy and Alembic.
- **Frontend:** React 18, Vite, Chart.js.

## Prerequisites
- Python 3.9+
- Node.js & npm (for frontend)
- PostgreSQL (optional, defaults to SQLite)

## Setup & Installation

### 1. Clone & Environment Setup
Clone the repository and create a Python virtual environment:
```bash
python -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies
Install all backend requirements:
```bash
pip install -r requirements.txt
```

### 3. Environment Variables
Create a `.env` file in the root directory (one has been provided) and configure your database:
```env
# To use PostgreSQL, update the URL below:
# DATABASE_URL=postgresql://user:password@localhost:5432/threat_monitor

# Default fallback is SQLite
DATABASE_URL=sqlite:///./threat_monitor.db
```

### 4. Database Migrations
Initialize the database tables using Alembic:
```bash
alembic upgrade head
```

### 5. Frontend Setup (React)
Navigate to the frontend directory, install dependencies, and build the React app:
```bash
cd frontend
npm install
npm run build
cd ..
```
*Note: The FastAPI backend is configured to automatically serve the compiled React files from `frontend/dist`.*

## Running the Application

### Option A: Production Mode (All-in-one)
Run the backend which also serves the compiled frontend dashboard:
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```
Visit `http://localhost:8000` in your browser.

### Option B: Development Mode (Hot Reloading)
**Terminal 1 (Backend):**
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
**Terminal 2 (Frontend):**
```bash
cd frontend
npm run dev
```
Visit `http://localhost:5173` to view the React app with hot module replacement.

## How to Test
Use the built-in **Live Traffic Simulator** on the React dashboard to generate fake network traffic and watch the Threat Detection Engine flag malicious behavior in real-time.

## Deployment to Production
To meet the "Live URL accessible online" requirement:
1. Push this repository to GitHub.
2. Deploy the backend to a provider like **Render** or **Heroku**.
3. Provision a managed **PostgreSQL** database on your host and update the `DATABASE_URL` environment variable in the production server settings.
4. Deploy the `frontend/dist` folder to a static host like **Vercel** or **Netlify** (or let the FastAPI server continue serving it).