# CyberShield Enterprise | Premium Security Assessment Platform

CyberShield Enterprise is a premium, enterprise-grade cybersecurity SaaS dashboard and vulnerability assessment platform. Designed to look and feel like top-tier security products (such as CrowdStrike, Datadog, and Cloudflare), it provides comprehensive real-time network and application vulnerability diagnostics, threat intelligence monitoring, administrative audits, and analytical overviews.

**Live Deployment URL:** [https://harshithanagashreer.github.io/cybershield-enterprise/](https://harshithanagashreer.github.io/cybershield-enterprise/)  
*(Runs in fully-functional offline mode with simulated diagnostics and mock databases)*

---

## Key Features

1. **Unified Cyber Blue Design System**
   - Built with a strict HSL-tailored Cyber Blue theme.
   - Clean, spacious layouts utilizing a strict 8px-multiple grid for professional density.
   - Fluid typography hierarchy powered by *Inter*, *Outfit*, and *JetBrains Mono*.

2. **Executive & Technical Views**
   - **Dashboard**: Live network health indicator, KPI stats (with SVG sparklines), and alert panels.
   - **Vulnerability Center**: Filterable table tracking software vulnerabilities, CVSS ratings, CVEs, and remediation steps.
   - **Threat Intel Feed**: Live geo-located intrusion attempts, network map block diagrams, and security logs.
   - **SSL/TLS & DNS Analyzers**: Diagnostic tools showcasing SSL certificate details, cryptographic suites, and DNS records.
   - **Analytics**: Historical vulnerability trend graphs built using responsive SVGs.
   - **System Architecture**: High-fidelity architectural block diagram rendering execution flows.

3. **Hybrid Execution Modes**
   - **Local Production Mode**: Connects the React client directly to a FastAPI backend server for live port scanning, DNS resolution, and security header evaluations.
   - **Static Hosting Mode (GitHub Pages)**: Seamlessly degrades to in-browser network simulation and mock databases when the backend API is unreachable.

---

## Technology Stack

* **Frontend**: React (Vite), Vanilla CSS, SVG Graphics, Lucide Icons.
* **Backend**: FastAPI, Python 3, Uvicorn, SQLite database.
* **Deployment**: GitHub Actions, GitHub Pages.

---

## Getting Started (Local Development)

### Prerequisites
* Python 3.8+
* Node.js 18+

### Setup & Run
You can start both the backend API and frontend Vite servers using the unified `run.py` helper script at the repository root.

1. **Install Virtual Environment & Python Dependencies**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r backend/requirements.txt  # If requirements.txt is available
   # Or directly install FastAPI dependencies:
   pip install fastapi uvicorn sqlite3
   ```

2. **Start the Unified Server**
   To run both backend and frontend servers in development mode:
   ```bash
   python run.py dev
   ```
   * Frontend URL: `http://localhost:5173`
   * Backend API: `http://localhost:8000`

3. **Start the Unified Production Server**
   To compile production bundles and serve them from FastAPI:
   ```bash
   python run.py prod
   ```
   * Production URL: `http://localhost:8000`

---

## API Endpoints

The FastAPI backend exposes the following endpoints:

* `GET /api/scans` - Retrieve all historical scan records.
* `GET /api/scans/{scan_id}` - Retrieve details of a specific scan.
* `POST /api/scan` - Start a new vulnerability scan.
* `GET /api/vulnerabilities` - Fetch active vulnerabilities database.
* `GET /api/threat-intel` - Fetch live threat telemetry logs.
* `GET /api/audit-logs` - Fetch administrative system audit history.
* `GET /api/analytics` - Fetch historical vulnerability distribution metrics.
* `GET /api/scans/{scan_id}/report` - Export scan report as a CSV.
