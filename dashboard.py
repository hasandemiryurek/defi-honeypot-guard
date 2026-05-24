import json
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

LOG_FILE = Path("/app/threat_log.jsonl")

@app.get("/api/threats")
def get_threats():
    if not LOG_FILE.exists():
        return []
    threats = []
    for line in LOG_FILE.read_text().strip().splitlines():
        try:
            threats.append(json.loads(line))
        except Exception:
            pass
    return list(reversed(threats[-100:]))

@app.get("/api/stats")
def get_stats():
    threats = get_threats()
    stats = {"total": len(threats), "by_class": {}, "by_severity": {}, "paused": False}
    for t in threats:
        cls = t["report"]["attack_class"]
        sev = t["report"]["severity"]
        stats["by_class"][cls]     = stats["by_class"].get(cls, 0) + 1
        stats["by_severity"][sev]  = stats["by_severity"].get(sev, 0) + 1
    return stats

@app.get("/", response_class=HTMLResponse)
def index():
    return Path("/app/dashboard.html").read_text()