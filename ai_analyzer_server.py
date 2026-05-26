"""
ai_analyzer_server.py  —  Local AI Analysis Server
====================================================
Run this BEFORE loading the Burp extension:
    python3 ai_analyzer_server.py

Requires:
    pip install flask anthropic python-dotenv

Endpoints:
    POST /analyze        — quick passive analysis (called on every request)
    POST /analyze/deep   — deep analysis (right-click in Burp)
    GET  /findings       — JSON list of all findings
    GET  /architecture   — app map built from collected traffic
    POST /ask            — ask Claude about the app
    GET  /ui             — web dashboard (3 tabs: Findings, Architecture, Ask AI)
    GET  /stats          — counts by severity
"""

import os
import json
import time
import threading
from datetime import datetime
from collections import deque
from flask import Flask, request, jsonify, render_template
import anthropic
from dotenv import load_dotenv


app = Flask(__name__)


load_dotenv()
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")  # <- Your API key here or in .env file
MAX_FINDINGS = 500
findings_store = deque(maxlen=MAX_FINDINGS)
findings_lock = threading.Lock()
request_counter = 0
pause_lock = threading.Lock()  
counter_lock = threading.Lock() 

client = None
if ANTHROPIC_API_KEY:
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
else:
    print("[!] No ANTHROPIC_API_KEY set. Set it with:")
    print("    export ANTHROPIC_API_KEY=sk-ant-...")
    print("    Server will still run but AI analysis will be skipped.\n")

PASSIVE_MODEL = "claude-haiku-4-5-20251001"
DEEP_MODEL    = "claude-sonnet-4-6"


# ── Architecture Map ──────────────────────────────────────────────────────────

app_map = {
    "endpoints":  {},   # url -> {methods, params, auth, status_codes, tech}
    "tech_stack": set(),
    "parameters": {},   # param_name -> [urls where it appears]
}
app_map_lock = threading.Lock() 


def update_app_map(data: dict):
    """Build a running map of the application as traffic flows in."""
    url    = data.get("url", "")
    method = data.get("method", "GET")
    status = data.get("response_status", 0)

    # Parse parameters from URL query string
    params = []
    if "?" in url:
        query = url.split("?")[1]
        params += [p.split("=")[0] for p in query.split("&") if "=" in p]

    # Parse parameters from request body
    body = data.get("request_body", "")
    if body:
        try:
            parsed = json.loads(body)
            params += list(parsed.keys()) if isinstance(parsed, dict) else []
        except Exception:
            params += [p.split("=")[0] for p in body.split("&") if "=" in p]

    # Detect authentication type from request headers
    auth = "none"
    for h in (data.get("request_headers") or []):
        h = str(h).lower()
        if "authorization: bearer" in h:   auth = "jwt/bearer"
        elif "authorization: basic" in h:  auth = "basic"
        elif "cookie:" in h:               auth = "cookie"
        elif "x-api-key" in h:             auth = "api-key"

    # Detect tech stack from response headers
    tech = []
    for h in (data.get("response_headers") or []):
        h = str(h).lower()
        for t in ["nginx", "apache", "wordpress", "php", "django",
                  "express", "spring", "laravel", "rails", "asp.net"]:
            if t in h:
                tech.append(t)

    # Use base URL without query string as map key
    base_url = url.split("?")[0]

    with app_map_lock:
        if base_url not in app_map["endpoints"]:
            app_map["endpoints"][base_url] = {
                "methods":      set(),
                "params":       set(),
                "auth":         auth,
                "status_codes": set(),
                "tech":         set(),
            }
        ep = app_map["endpoints"][base_url]
        ep["methods"].add(method)
        ep["params"].update(params)
        ep["status_codes"].add(status)
        ep["tech"].update(tech)
        app_map["tech_stack"].update(tech)

        # Track which URLs each parameter appears in
        for p in params:
            if p not in app_map["parameters"]:
                app_map["parameters"][p] = []
            if base_url not in app_map["parameters"][p]:
                app_map["parameters"][p].append(base_url)


# ── Prompts ───────────────────────────────────────────────────────────────────

PASSIVE_SYSTEM = """You are an expert web application penetration tester doing passive HTTP traffic analysis.

Analyze the HTTP request/response and look for security issues. Be precise and concise.

Respond ONLY with a JSON object (no markdown, no preamble):
{
  "findings": [
    {
      "title": "Short finding name",
      "severity": "critical|high|medium|low|info",
      "detail": "One sentence: what you found and why it matters",
      "category": "injection|auth|disclosure|config|crypto|idor|xss|ssrf|other"
    }
  ]
}

Return an empty findings array if nothing interesting is found.
Only report things clearly visible in the data — no guessing.

Look for:
- Sensitive data in responses (tokens, keys, PII, passwords, internal paths)
- Security headers missing or misconfigured
- Debug info / stack traces / verbose errors
- JWT issues (alg:none, no expiry, base64-decodable sensitive payload)
- Interesting parameters that could be injection points (id, file, path, cmd, url, redirect)
- IDOR signals (numeric/sequential object IDs, user-specific data in response)
- Dangerous response patterns (SQL errors, PHP warnings, server internals)
- Insecure cookies (no httponly, no secure, no samesite)
- CORS misconfigurations
- Auth tokens in URLs or GET params
"""

DEEP_SYSTEM = """You are a senior web application penetration tester doing a deep manual review.

Analyze the HTTP exchange thoroughly. Think like an attacker.

Respond ONLY with a JSON object:
{
  "findings": [
    {
      "title": "Short finding name",
      "severity": "critical|high|medium|low|info",
      "detail": "Detailed description of the issue",
      "category": "injection|auth|disclosure|config|crypto|idor|xss|ssrf|other",
      "proof_of_concept": "Specific step or payload to confirm/exploit this",
      "recommendation": "How to fix it"
    }
  ],
  "attack_surface": "2-sentence summary of what this endpoint does and its risk profile",
  "suggested_next_tests": ["test 1", "test 2", "test 3"]
}

Be thorough — this is a manual deep-dive, not passive monitoring.
Consider: auth bypass, parameter tampering, injection points, logic flaws, state issues.
"""


# ── Analysis functions ────────────────────────────────────────────────────────

def build_traffic_summary(data: dict) -> str:
    """Compact but complete representation of the HTTP exchange."""
    lines = []
    lines.append(f"=== REQUEST ===")
    lines.append(f"{data['method']} {data['url']}")
    for h in (data.get('request_headers') or [])[:20]:
        lines.append(str(h))
    if data.get('request_body'):
        lines.append(f"\n{data['request_body'][:2000]}")

    lines.append(f"\n=== RESPONSE ===")
    lines.append(f"Status: {data.get('response_status', '?')}")
    for h in (data.get('response_headers') or [])[:20]:
        lines.append(str(h))
    if data.get('response_body'):
        lines.append(f"\n{data['response_body'][:2000]}")

    return "\n".join(lines)


def analyze_with_ai(data: dict, deep: bool = False) -> dict:
    if not client:
        return {"findings": []}

    system = DEEP_SYSTEM if deep else PASSIVE_SYSTEM
    traffic = build_traffic_summary(data)

    try:
        response = client.messages.create(
            model=DEEP_MODEL if deep else PASSIVE_MODEL,  # fast + cheap for passive monitoring
            max_tokens=4000 if deep else 1200,
            system=system,
            messages=[{
                "role": "user",
                "content": f"Analyze this HTTP exchange:\n\n{traffic}"
            }]
        )
        raw = response.content[0].text.strip()
        # Strip markdown fences if model adds them
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"[!] JSON parse error: {e}")
        return {"findings": []}
    except anthropic.RateLimitError:
        print("[!] Rate limited — slow down or use a higher tier key")
        return {"findings": []}
    except Exception as e:
        print(f"[!] AI error: {e}")
        return {"findings": []}


def store_finding(data: dict, result: dict):
    """Persist findings with metadata."""
    url = data.get("url", "")
    method = data.get("method", "GET")
    status = data.get("response_status", 0)
    timestamp = datetime.now().isoformat()

    for f in result.get("findings", []):
        entry = {
            "id": int(time.time() * 1000),
            "timestamp": timestamp,
            "url": url,
            "method": method,
            "status": status,
            "host": data.get("host", ""),
            **f
        }
        with findings_lock:
            findings_store.appendleft(entry)

    # Store extra deep-analysis fields at the top level
    if result.get("attack_surface") or result.get("suggested_next_tests"):
        meta = {
            "id": int(time.time() * 1000),
            "timestamp": timestamp,
            "url": url,
            "method": method,
            "status": status,
            "host": data.get("host", ""),
            "title": "Deep Analysis Summary",
            "severity": "info",
            "detail": result.get("attack_surface", ""),
            "category": "other",
            "suggested_next_tests": result.get("suggested_next_tests", []),
        }
        with findings_lock:
            findings_store.appendleft(meta)


# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/analyze", methods=["POST"])
def analyze():
    global request_counter
    data = request.get_json(force=True)
    with counter_lock:
        request_counter += 1
    update_app_map(data)
    result = analyze_with_ai(data, deep=False)
    if result.get("findings"):
        store_finding(data, result)
    return jsonify(result)

@app.route("/analyze/deep", methods=["POST"])
def analyze_deep():
    data = request.get_json(force=True)
    update_app_map(data)
    result = analyze_with_ai(data, deep=True)
    if result.get("findings"):
        store_finding(data, result)
    return jsonify(result)


@app.route("/findings", methods=["GET"])
def get_findings():
    severity = request.args.get("severity")
    host = request.args.get("host")
    category = request.args.get("category")

    with findings_lock:
        items = list(findings_store)

    if severity:
        items = [f for f in items if f.get("severity") == severity]
    if host:
        items = [f for f in items if host in f.get("host", "")]
    if category:
        items = [f for f in items if f.get("category") == category]

    return jsonify(items)


@app.route("/stats", methods=["GET"])
def stats():
    with findings_lock:
        items = list(findings_store)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    categories = {}
    hosts = {}
    for f in items:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
        cat = f.get("category", "other")
        categories[cat] = categories.get(cat, 0) + 1
        h = f.get("host", "unknown")
        hosts[h] = hosts.get(h, 0) + 1

    return jsonify({
        "total": len(items),
        "requests_analyzed": request_counter,
        "by_severity": counts,
        "by_category": categories,
        "by_host": hosts,
    })


@app.route("/clear", methods=["POST"])
def clear():
    global request_counter
    with findings_lock:
        findings_store.clear()
    request_counter = 0
    return jsonify({"ok": True})



@app.route("/architecture", methods=["GET"])
def architecture():
    with app_map_lock:
        # Convert sets to lists for JSON serialization
        endpoints = {}
        for url, data in app_map["endpoints"].items():
            endpoints[url] = {
                "methods":      list(data["methods"]),
                "params":       list(data["params"]),
                "auth":         data["auth"],
                "status_codes": list(data["status_codes"]),
                "tech":         list(data["tech"]),
            }
        return jsonify({
            "total_endpoints": len(endpoints),
            "tech_stack":      list(app_map["tech_stack"]),
            "endpoints":       endpoints,
            "parameters":      dict(app_map["parameters"]),
            "interesting": {
                "no_auth":     [u for u,d in endpoints.items()
                                if d["auth"] == "none" and
                                any(m in d["methods"] for m in ["POST","PUT","DELETE"])],
                "file_params": [p for p in app_map["parameters"]
                                if any(x in p.lower() for x in
                                ["file","path","url","redirect","next","src","img"])],
                "id_params":   [p for p in app_map["parameters"]
                                if any(x in p.lower() for x in
                                ["id","uid","user","account","order","uuid"])],
            }
        })
    


# ── Web UI ────────────────────────────────────────────────────────────────────

@app.route("/ui")
def ui():
    return render_template("ui.html")

@app.route("/arch")
def architecture_ui():
    return render_template("arch.html")

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  AI Traffic Analyzer Server")
    print("=" * 55)
    print(f"  API Key : {'set ✓' if ANTHROPIC_API_KEY else 'NOT SET ✗'}")
    print(f"  Model   : claude-haiku-4-5 (fast passive)")
    print(f"  Server  : http://127.0.0.1:8719")
    print(f"  Web UI  : http://127.0.0.1:8719/ui")
    print("=" * 55)
    print("\n  1. Start this server")
    print("  2. Load burp_ai_extension.py in Burp → Extender")
    print("  3. Browse your target — findings appear live\n")

    app.run(host="0.0.0.0", port=8719, debug=False, threaded=True)