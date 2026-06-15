<img width="634" height="590" alt="image" src="https://github.com/user-attachments/assets/cb5cb457-ec6e-433b-b4f1-a001b77c8b5e" />

# AI-WAF-Python

AI-powered Web Application Firewall (WAF) built with FastAPI and Groq LLM reasoning.  
Includes request scanning, inspection endpoint, attack simulation suite, and a web dashboard.

---

## Features

- AI-based WAF reasoning engine (Groq LLM)
- URL scanning endpoint (`/scan`)
- Raw request inspection endpoint (`/inspect`)
- OWASP-style threat detection (XSS, SQLi, injection patterns)
- Attack simulation tool (`attacks.py`)
- Web dashboard UI (`ui.html`)
- JSON logging of results

---

## Project Structure


waf.py FastAPI backend (WAF engine)
attacks.py Attack simulation script
ui.html Web dashboard UI
requirements.txt Python dependencies
attack_report.json Generated results output
cleanup.sh Utility script


---

## Setup & Run 

create Groq API key first
git clone https://github.com/carlonapo9/AI-WAF-Python.git && cd AI-WAF-Python && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && export GROQ_API_KEY=your_api_key_here && uvicorn waf:app --reload

Run Attack Simulation (separate terminal)
source venv/bin/activate && python3 attacks.py --target https://example.com

Open Dashboard
Open ui.html directly in browser:
or
explorer.exe ui.html   # Windows WSL
or
xdg-open ui.html       # Linux

API Endpoints
POST /scan → scan a target URL
POST /inspect → inspect raw request payload
GET /docs → Swagger UI
Notes
Requires Groq API key
Works in local development mode
For research / security testing only
Not production-hardened
