# PhishRadar — AI-Powered Phishing Threat Monitor

**PhishRadar** detects phishing URLs and explains threats in plain English. It combines ML-based URL classification with Claude AI to provide actionable threat intelligence — going beyond binary verdicts to tell you *why* a URL is dangerous.

Built for security analysts, SOC teams, and anyone who wants to understand phishing threats without deciphering raw technical indicators.

**Live demo:** https://phishradar.noorullah.net

---

## How It Works

```
                          URL Input
                              |
              +---------------+---------------+
              |                               |
    +---------v----------+        +-----------v-----------+
    |  Threat Feed Check  |        |   Feature Extraction  |
    |  (URLhaus, VT,      |        |   (WHOIS, SSL, DNS,   |
    |   OpenPhish, etc.)  |        |    redirects, etc.)   |
    +---------+----------+        +-----------+-----------+
              |                               |
     Found in feeds                  ML + Rules Analysis
     (98% confidence)                (Random Forest + 11 rules)
              |                               |
              +---------------+---------------+
                              |
                  +-----------v-----------+
                  |   AI Threat Explainer  |
                  |   (Claude API)         |
                  +-----------+-----------+
                              |
                  +-----------v-----------+
                  |   Structured Report    |
                  |   verdict + confidence |
                  |   + plain-English      |
                  |     explanation        |
                  +-----------------------+
```

## Features

- **URL Analysis** — Extracts 26+ lexical features (domain entropy, typosquatting, suspicious keywords/TLDs, brand impersonation, etc.) plus network features (WHOIS age, SSL, redirects)
- **ML Classification** — TF-IDF character n-grams + Gradient Boosting classifier trained on 654K+ real URLs from Kaggle (86% accuracy)
- **Rule-Based Detection** — 11 rules with critical-override capability (catches what ML misses)
- **AI Explanations** — Claude-powered plain-English threat reports with severity, risk factors, and recommended actions
- **7 Threat Feeds** — URLhaus, OpenPhish, VirusTotal, Google Safe Browsing, urlscan.io, Reddit, PhishTank
- **PhishTank MCP Server** — 7 MCP tools for querying PhishTank via Claude Desktop / Claude Code
- **Dashboard** — Real-time stats, charts, scan history, and feed health monitoring
- **REST API** — Full CRUD API with authentication and batch analysis
- **Mobile Responsive** — Works on all screen sizes with hamburger navigation

## Example Response

```json
{
  "url": "https://app1e-id-verify.sketchy-domain.com/login",
  "verdict": "phishing",
  "confidence": 0.94,
  "features": {
    "typosquat_target": "apple.com",
    "domain_age_days": 3,
    "ssl_valid": false,
    "redirect_count": 2,
    "has_suspicious_keywords": true
  },
  "ai_explanation": {
    "summary": "This URL impersonates Apple's login page using typosquatting.",
    "explanation": "The domain 'app1e' is a typosquat of 'apple'. Combined with a 3-day-old registration and no valid SSL, this is a credential harvesting attempt.",
    "risk_factors": ["Typosquatting detected", "Domain < 30 days old", "No valid SSL"],
    "severity": "high",
    "recommended_action": "Block URL and report to IT security"
  }
}
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | System health check |
| `/api/v1/analyze` | POST | Analyze a single URL |
| `/api/v1/analyze/batch` | POST | Analyze multiple URLs |
| `/api/v1/scans/recent` | GET | Recent scan history |
| `/api/v1/scans/{id}` | GET | Get scan by ID |
| `/api/v1/scans/search` | GET | Search scans by URL |
| `/api/v1/stats/summary` | GET | Aggregate statistics |
| `/api/v1/stats/dashboard` | GET | Dashboard data |
| `/api/v1/feeds/indicators` | GET | Threat indicators |
| `/api/v1/feeds/status` | GET | Feed health status |
| `/api/v1/feeds/refresh` | POST | Manual feed refresh |

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.12 |
| API Framework | FastAPI |
| ML | scikit-learn (TF-IDF + Gradient Boosting) |
| AI | Claude API (Anthropic SDK) |
| Database | SQLAlchemy + SQLite |
| Threat Feeds | PhishTank, URLhaus, Reddit (PRAW), OpenPhish, VirusTotal, Google Safe Browsing, urlscan.io |
| MCP Server | Python MCP SDK |
| Frontend | HTML + Tailwind CSS + Chart.js |

## Quick Start

### Prerequisites

- Python 3.11+
- pip

### Install

```bash
# Clone the repo
git clone https://github.com/noorullah1102/security.git
cd security

# Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt

# Copy environment file and add your API keys
cp .env.example .env
# Edit .env with your API keys
```

### Configure

Set these in your `.env` file (see `.env.example` for full list):

| Variable | Required | Get it from |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | [console.anthropic.com](https://console.anthropic.com/) |
| `API_KEY` | Yes | Make one up (used for PhishRadar auth) |
| `URLHAUS_AUTH_KEY` | No | [abuse.ch](https://urlhaus.abuse.ch/api/) |
| `VIRUSTOTAL_API_KEY` | No | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |
| `GOOGLE_SAFEBROWSING_API_KEY` | No | [Google Cloud Console](https://console.cloud.google.com) |
| `URLSCAN_API_KEY` | No | [urlscan.io](https://urlscan.io/user-apikey) |

> PhishRadar works without optional keys — it uses whichever feeds are available and falls back to ML + rules.

### Run

```bash
# Seed demo data (first time only)
python scripts/seed_demo_data.py

# Start the server
uvicorn src.main:app --reload

# Open http://localhost:8000 for the dashboard
# Or visit https://phishradar.noorullah.net for the live demo
```

### Test

```bash
# Run all tests
pytest --cov=src

# Analyze a URL via API
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "X-API-Key: dev-api-key" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypa1.com/verify", "include_ai_explanation": true}'
```

### Train the ML Model

```bash
# With Kaggle data (best results — requires kaggle.json)
python scripts/download_kaggle_data.py
python -m src.ml.train_with_kaggle

# With free feeds (no Kaggle account needed)
python -m src.ml.collect_real_data
python -m src.ml.train_real
```

## PhishTank MCP Server

Standalone MCP server for querying PhishTank from Claude Desktop or Claude Code:

```bash
# Add to Claude Code
claude mcp add phishtank -- python -m src.mcp.phishtank_server

# Test with MCP Inspector
mcp dev src/mcp/phishtank_server.py
```

Provides 7 tools: `check_url`, `check_multiple_urls`, `get_recent_phish`, `search_phish_by_target`, `get_phish_details`, `get_phish_stats`, `search_phish_by_date`.

## Project Structure

```
phishradar/
├── src/
│   ├── main.py                 # FastAPI app entry point
│   ├── config.py               # Settings (pydantic)
│   ├── api/                    # REST API routes + schemas + middleware
│   ├── analyzer/               # URL feature extraction, ML + rules analysis
│   ├── explainer/              # Claude API integration + prompt templates
│   ├── feeds/                  # Threat feed clients (URLhaus, PhishTank, etc.)
│   ├── ml/                     # ML training pipeline
│   ├── mcp/                    # PhishTank MCP server
│   └── db/                     # SQLAlchemy models + repository
├── models/                     # Trained ML models + metrics
├── frontend/                   # Dashboard (HTML + Tailwind + Chart.js)
├── scripts/                    # Seed data, Kaggle downloader
├── tests/                      # 99 tests
├── docs/                       # Specs + architecture docs
├── .env.example                # Environment variable template
└── requirements.txt
```

## License

MIT
