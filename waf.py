"""
AI-WAF: Reasoning-based Web Application Firewall
Inspired by: LLM Agents for Automated Web Vulnerability Reproduction (arXiv 2510.14700)
             SqliGPT black-box detection approach (MDPI 2024)
             OWASP Secure Headers Project + OWASP Top 10 2025
             RAG-enhanced detection (arXiv 2411.18216)
"""

import os
import re
import json
import httpx
import asyncio
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from groq import Groq

app = FastAPI(title="AI-WAF", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# ── OWASP Secure Headers checklist (OWASP Secure Headers Project 2025) ──────
REQUIRED_HEADERS = {
    "strict-transport-security": {
        "description": "HSTS — forces HTTPS, prevents protocol downgrade attacks",
        "recommended": "max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "description": "CSP — restricts resource loading, mitigates XSS",
        "recommended": "default-src 'self'",
    },
    "x-frame-options": {
        "description": "Prevents clickjacking via iframe embedding",
        "recommended": "DENY",
    },
    "x-content-type-options": {
        "description": "Prevents MIME-type sniffing attacks",
        "recommended": "nosniff",
    },
    "referrer-policy": {
        "description": "Controls referrer information in requests",
        "recommended": "strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "description": "Restricts browser feature access (camera, mic, etc.)",
        "recommended": "geolocation=(), camera=(), microphone=()",
    },
}

# ── Known attack pattern signatures (static pre-filter before LLM reasoning) ─
# Based on CWE Top 25 + OWASP Top 10 2025
STATIC_PATTERNS = {
    "sqli": [
        r"(?i)(\bor\b|\band\b)\s+[\w'\"]+\s*=\s*[\w'\"]+",
        r"(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from)",
        r"(?i)(--\s*$|;\s*--|\bxp_\w+)",
        r"(?i)(\bexec\b|\bexecute\b)\s*\(",
        r"'.*?'.*?(=|<|>)",
    ],
    "xss": [
        r"(?i)<script[^>]*>.*?</script>",
        r"(?i)javascript\s*:",
        r"(?i)on\w+\s*=\s*[\"'][^\"']*[\"']",
        r"(?i)<iframe[^>]*>",
        r"(?i)document\.(cookie|write|location)",
        r"(?i)eval\s*\(",
    ],
    "prompt_injection": [
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
        r"(?i)you\s+are\s+now\s+(a\s+)?",
        r"(?i)system\s*prompt",
        r"(?i)jailbreak",
        r"(?i)forget\s+(everything|all)\s+(you|i)",
        r"(?i)act\s+as\s+(if\s+you\s+are|a\s+)",
    ],
    "path_traversal": [
        r"(\.\./){2,}",
        r"(?i)(%2e%2e%2f|%252e%252e%252f)",
        r"(?i)\.\.[/\\]",
    ],
    "cmd_injection": [
        r"(?i)(;|\||&&)\s*(ls|cat|wget|curl|bash|sh|python|nc)\b",
        r"(?i)\$\(.*?\)",
        r"(?i)`[^`]+`",
    ],
}


class ScanRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: dict = {}
    body: str = ""
    user_agent: str = ""


class WAFRequest(BaseModel):
    method: str
    path: str
    headers: dict = {}
    query_params: dict = {}
    body: str = ""
    source_ip: str = "unknown"


def static_scan(payload: str) -> list[dict]:
    """Fast pattern-matching pre-filter. Returns list of hits."""
    hits = []
    for attack_type, patterns in STATIC_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, payload):
                hits.append({"type": attack_type, "pattern": pattern})
                break
    return hits


def check_headers(headers: dict) -> list[dict]:
    """Check HTTP security headers against OWASP checklist."""
    missing = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for header, info in REQUIRED_HEADERS.items():
        if header not in lower_headers:
            missing.append({
                "header": header,
                "description": info["description"],
                "recommended": info["recommended"],
            })
    return missing


async def llm_reason(request_summary: str, static_hits: list, missing_headers: list) -> dict:
    """
    Reasoning-based analysis using Claude.
    Inspired by the 'reasoning agent' paradigm from Qualys 2026 and arXiv 2502.20383.
    Uses RAG-style knowledge injection (OWASP rules embedded in system prompt)
    as shown effective in arXiv 2411.18216 (up to +67pp accuracy).
    """
    system = """You are an AI Web Application Firewall (AI-WAF) security reasoning engine.

Your knowledge base (RAG context):
- OWASP Top 10 2025: Broken Access Control, Cryptographic Failures, Injection, Insecure Design,
  Security Misconfiguration, Vulnerable Components, Auth Failures, Integrity Failures,
  Logging Failures, SSRF
- CWE Top 25: SQL Injection (#3), XSS (#2), Path Traversal, Command Injection, CSRF
- OWASP Agentic AI Top 10 2026: Goal hijacking, Tool misuse, Prompt injection, Memory poisoning
- OWASP Secure Headers Project 2025: HSTS, CSP, X-Frame-Options, X-Content-Type-Options

Analyse the provided HTTP request. Reason through:
1. What attack vectors are present or likely?
2. What is the severity and confidence?
3. What is the recommended action: BLOCK, FLAG, or ALLOW?
4. What specific fix should the developer implement?

Respond ONLY with valid JSON, no markdown, in this exact structure:
{
  "verdict": "BLOCK" | "FLAG" | "ALLOW",
  "confidence": 0-100,
  "severity": "critical" | "high" | "medium" | "low" | "none",
  "attack_types": ["list of detected attack types"],
  "reasoning": "2-3 sentence plain English explanation of what you found",
  "remediation": "Specific developer action to fix the issue",
  "owasp_categories": ["relevant OWASP Top 10 categories"]
}"""

    user = f"""Analyse this HTTP request:

{request_summary}

Static pattern pre-filter detected: {json.dumps(static_hits)}
Missing security headers: {json.dumps([h['header'] for h in missing_headers])}

Reason through this carefully and return your JSON verdict."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        max_tokens=1000,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )

    raw = response.choices[0].message.content.strip()
    raw = re.sub(r"^```json\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)
    return json.loads(raw)


@app.post("/scan")
async def scan_url(req: ScanRequest):
    """
    Full URL scan: fetch target, inspect headers, analyse response.
    Implements the black-box scanning approach from SqliGPT (MDPI 2024).
    """
    parsed = urlparse(req.url)
    if not parsed.scheme or not parsed.netloc:
        return JSONResponse({"error": "Invalid URL"}, status_code=400)

    # Fetch the target URL
    fetched_headers = {}
    fetch_error = None
    status_code = None
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as http:
            resp = await http.get(req.url, headers={"User-Agent": req.user_agent or "AI-WAF/1.0"})
            fetched_headers = dict(resp.headers)
            status_code = resp.status_code
    except Exception as e:
        fetch_error = str(e)

    # Check query params + path for attack patterns
    query_string = parsed.query or ""
    full_payload = f"{parsed.path}?{query_string} {req.body}"
    static_hits = static_scan(full_payload)

    # Header analysis
    missing_headers = check_headers(fetched_headers)

    # Build request summary for LLM
    summary = f"""URL: {req.url}
Method: {req.method}
Path: {parsed.path}
Query: {query_string}
Status: {status_code or 'unreachable'}
Fetch error: {fetch_error or 'none'}
Response headers present: {list(fetched_headers.keys())}
Request body: {req.body[:500] if req.body else 'none'}"""

    llm_result = await llm_reason(summary, static_hits, missing_headers)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "url": req.url,
        "status_code": status_code,
        "fetch_error": fetch_error,
        "static_hits": static_hits,
        "missing_headers": missing_headers,
        "llm_analysis": llm_result,
    }


@app.post("/inspect")
async def inspect_request(req: WAFRequest):
    """
    Inline WAF mode: inspect an incoming request before it hits the app.
    Implements the agent-based inline interception pattern from arXiv 2502.20383.
    """
    # Combine all user-controlled input for scanning
    query_string = "&".join(f"{k}={v}" for k, v in req.query_params.items())
    full_payload = f"{req.path}?{query_string} {req.body}"
    static_hits = static_scan(full_payload)

    # Also scan headers for injection (indirect prompt injection via headers)
    header_payload = " ".join(req.headers.values())
    header_hits = static_scan(header_payload)
    all_hits = static_hits + [{"type": h["type"] + "_in_header", "pattern": h["pattern"]} for h in header_hits]

    missing_headers = check_headers(req.headers)

    summary = f"""Method: {req.method}
Path: {req.path}
Query params: {query_string}
Source IP: {req.source_ip}
User-Agent: {req.headers.get('user-agent', 'unknown')}
Body (first 500 chars): {req.body[:500] if req.body else 'none'}
Custom headers: {[k for k in req.headers if not k.startswith(':')]}"""

    llm_result = await llm_reason(summary, all_hits, missing_headers)

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "request": {"method": req.method, "path": req.path, "source_ip": req.source_ip},
        "static_hits": all_hits,
        "missing_headers": missing_headers,
        "llm_analysis": llm_result,
        "action": llm_result.get("verdict", "FLAG"),
    }


@app.get("/health")
async def health():
    return {"status": "ok", "model": "llama-3.3-70b-versatile", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
