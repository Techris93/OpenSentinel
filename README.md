<p align="center">
  <h1 align="center">🛡️ OpenSentinel</h1>
  <p align="center">
    <strong>AI-Powered SOC Command Center</strong>
  </p>
  <p align="center">
    Natural Language → SIEM Queries · Real-Time Detection · AI Copilot · Automated Response
  </p>
  <p align="center">
    <a href="#features">Features</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#quickstart">Quickstart</a> •
    <a href="#api-reference">API</a> •
    <a href="#security">Security</a> •
    <a href="#contributing">Contributing</a>
  </p>
</p>

---

## Overview

OpenSentinel is a full-stack **Security Operations Center (SOC)** platform that combines AI-driven analysis with traditional SIEM capabilities. It translates natural language queries into Splunk SPL, runs automated detection rules mapped to MITRE ATT&CK, and provides an AI copilot for incident investigation — all behind an API hardened against the **OWASP API Security Top 10**.

## Features

### 🤖 NLP Query Engine
- Natural language → Splunk SPL translation via spaCy NER
- Support for custom fine-tuned NLP models
- Entity extraction: IPs, domains, users, security actions
- Context-aware query building with time range support

### 🔍 Sentinel Detection Engine
- 6 built-in detection rules mapped to MITRE ATT&CK
- Real-time alert lifecycle (new → acknowledged → closed)
- Configurable thresholds and time windows
- Anomaly detection module

| Rule | MITRE | Severity |
|------|-------|----------|
| Brute Force Detection | T1110 | High |
| Suspicious PowerShell | T1059.001 | Critical |
| DNS Exfiltration | T1048.003 | Critical |
| Lateral Movement (SMB) | T1021.002 | High |
| Privilege Escalation | T1068 | Critical |
| C2 Beaconing | T1071 | High |

### 📋 Incident Management
- Full incident lifecycle with timeline tracking
- Alert-to-incident linking
- Notes, status updates, and severity tracking
- BOLA-protected object-level access control

### 🧠 AI Copilot (Google Gemini)
- **Script Analyzer** — Deobfuscate and assess suspicious scripts
- **Threat Intel Enrichment** — IOC lookups via VirusTotal & AbuseIPDB
- **Investigator** — AI-guided investigation workflows
- **Summarizer** — Natural language summaries of SIEM query results

### 🎯 Threat Hunting
- Pre-built hunt library with categorized queries
- Hunt notebook for tracking investigations
- One-click hunt execution against live SIEM data

### ⚡ Automated Playbooks
- 5 built-in response playbooks
- Action-based execution engine
- Execution statistics and audit trail

### 🖥️ Dashboard
- Glassmorphism dark-theme UI
- Responsive design with hamburger menu
- Real-time status indicators
- Interactive chat interface for NLP queries

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Dashboard (HTML)                  │
├─────────────────────────────────────────────────────┤
│              FastAPI Server (main.py)                │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │ Security │  │  Auth    │  │ Input Validator   │  │
│  │Middleware│  │ Manager  │  │ (SSRF/Injection)  │  │
│  └──────────┘  └──────────┘  └───────────────────┘  │
├─────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │   SOC    │  │ Sentinel │  │   AI     │          │
│  │  Agent   │  │  Engine  │  │ Copilot  │          │
│  │(NLP→SPL)│  │(Detect)  │  │(Gemini)  │          │
│  └────┬─────┘  └──────────┘  └────┬─────┘          │
│       │                           │                 │
│  ┌────┴─────┐  ┌──────────┐  ┌────┴─────┐          │
│  │ Splunk   │  │Playbooks │  │VirusTotal│          │
│  │  SIEM    │  │ Engine   │  │AbuseIPDB │          │
│  └──────────┘  └──────────┘  └──────────┘          │
└─────────────────────────────────────────────────────┘
```

## Quickstart

### Prerequisites

- **Python 3.10+**
- **Splunk** instance (optional — Gemini AI works without SIEM)
- **API Keys** for Gemini, VirusTotal, AbuseIPDB (optional)

### Installation

```bash
# Clone the repository
git clone https://github.com/Techris93/OpenSentinel.git
cd OpenSentinel

# Create virtual environment
python -m venv venv
source venv/bin/activate  # macOS/Linux
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Download spaCy model
python -m spacy download en_core_web_sm
```

### Configuration

Create a `.env` file in the project root:

```env
# Google Gemini API (https://aistudio.google.com/app/apikey)
GEMINI_API_KEY=your_gemini_key_here

# VirusTotal API (https://www.virustotal.com)
VIRUSTOTAL_API_KEY=your_vt_key_here

# AbuseIPDB API (https://www.abuseipdb.com)
ABUSEIPDB_API_KEY=your_abuseipdb_key_here

# Splunk Connection (optional)
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=changeme

# Security
OPENSENTINEL_API_KEY=your-secure-api-key
RATE_LIMIT=60
CORS_ORIGINS=http://localhost:5001
```

### Run

```bash
python main.py
```

```
🛡️ OpenSentinel Command Center v1.0.0 starting on port 5001...
   API Docs:    http://localhost:5001/api/docs
   Dashboard:   http://localhost:5001/dashboard
   OWASP:       API1-10 protections active
```

## API Reference

All endpoints are available at `/api/v1/` (versioned) and `/api/` (legacy).

### Public Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check with system status |
| `GET` | `/dashboard` | Web dashboard UI |
| `GET` | `/api/docs` | Interactive OpenAPI docs |

### Authenticated Endpoints

> Include `X-API-Key: <your-key>` header in all requests.

| Method | Path | Role | Description |
|--------|------|------|-------------|
| `POST` | `/api/v1/connect` | admin | Connect to Splunk SIEM |
| `POST` | `/api/v1/chat` | analyst | NLP query interface |
| `POST` | `/api/v1/sentinel/start` | admin | Start detection engine |
| `POST` | `/api/v1/sentinel/stop` | admin | Stop detection engine |
| `GET` | `/api/v1/sentinel/alerts` | analyst | Get security alerts |
| `GET` | `/api/v1/anomalies` | analyst | Get detected anomalies |
| `GET` | `/api/v1/incidents` | analyst | List incidents (BOLA-filtered) |
| `GET` | `/api/v1/incidents/{id}` | analyst | Get incident detail |
| `GET` | `/api/v1/hunts` | analyst | List threat hunts |
| `POST` | `/api/v1/hunts/{id}/execute` | analyst | Execute a threat hunt |
| `POST` | `/api/v1/copilot/analyze-script` | analyst | AI script analysis |
| `POST` | `/api/v1/copilot/enrich` | analyst | IOC enrichment |
| `GET` | `/api/v1/playbooks` | analyst | List playbooks |
| `GET` | `/api/v1/playbooks/stats` | analyst | Playbook execution stats |

### Example: Chat Query

```bash
curl -X POST http://localhost:5001/api/v1/chat \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"message": "Show me failed login attempts from 192.168.1.100"}'
```

## Security

OpenSentinel implements all **OWASP API Security Top 10** protections:

| # | Vulnerability | Mitigation |
|---|---------------|------------|
| API1 | BOLA | Ownership verification on incident endpoints |
| API2 | Broken Auth | Key expiry, timing-safe comparison, brute-force lockout |
| API3 | Property Auth | Field-level response filtering by role |
| API4 | Rate Limiting | Global + per-endpoint rate limits |
| API5 | Function Auth | Role-based access (admin/analyst/readonly) |
| API6 | Anti-Automation | Per-endpoint throttling on sensitive flows |
| API7 | SSRF | Private IP blocking in recon targets |
| API8 | Misconfiguration | Security headers (HSTS, CSP, X-Frame-Options) |
| API9 | Inventory | API versioning + OpenAPI documentation |
| API10 | Unsafe Consumption | External API response truncation and sanitization |

### Role Hierarchy

```
admin > analyst > readonly
```

- **admin** — Full access: SIEM connection, sentinel control, all data
- **analyst** — Query, investigate, hunt, view own incidents
- **readonly** — View limited incident fields only

## Project Structure

```
OpenSentinel/
├── main.py                   # FastAPI server (19 endpoints)
├── soc_agent.py             # NLP → Splunk SPL engine
├── gemini_client.py         # Google Gemini AI client
├── dashboard.html           # Web UI (glassmorphism)
├── requirements.txt         # Python dependencies
├── .gitignore
│
├── security/
│   ├── __init__.py
│   ├── auth.py              # API key management & RBAC
│   ├── middleware.py         # Rate limiting, headers, audit
│   └── input_validator.py   # Injection & SSRF prevention
│
├── sentinel/
│   ├── __init__.py
│   ├── detection_engine.py  # Rule-based threat detection
│   ├── rules.py             # MITRE ATT&CK detection rules
│   ├── anomaly_detector.py  # Statistical anomaly detection
│   └── incidents.py         # Incident lifecycle manager
│
├── copilot/
│   ├── __init__.py
│   ├── summarizer.py        # AI event summarization
│   ├── script_analyzer.py   # Malicious script analysis
│   ├── investigator.py      # AI investigation assistant
│   └── threat_intel.py      # VirusTotal & AbuseIPDB
│
├── hunting/
│   ├── __init__.py
│   ├── hunt_library.py      # Pre-built hunt queries
│   └── notebook.py          # Hunt investigation notebook
│
├── playbooks/
│   ├── __init__.py
│   ├── engine.py            # Playbook execution engine
│   └── actions.py           # Response action definitions
│
└── connectors/
    └── __init__.py           # SIEM connector interface
```

## Contributing

Contributions are welcome! Areas where help is especially valued:

- **Detection Rules** — Add new MITRE ATT&CK-mapped rules
- **SIEM Connectors** — Extend beyond Splunk (Elastic, QRadar, Sentinel)
- **Playbook Actions** — Add automated response capabilities
- **Tests** — Improve test coverage
- **Documentation** — Improve guides and tutorials

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Built with ❤️ for the Blue Team
</p>
