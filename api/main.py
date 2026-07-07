"""
Thin FastAPI wrapper around the existing detection + AI-explanation backend.
No detection logic lives here -- this only adapts backend.scanner.run_full_scan()
and backend.ai.groq_client.explain_finding() into a JSON API for the React
frontend (frontend/). In-memory state only (except scan history, which is a
small local JSON file via backend.history): this is a single-user local tool,
not a multi-tenant service.
"""

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend import config, history
from backend.ai.groq_client import explain_finding
from backend.models import CheckResult, Finding, Severity
from backend.scanner import run_full_scan
from backend.scoring import compute_security_score

app = FastAPI(title="AWS Misconfiguration Detector API")

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

_lock = threading.Lock()
_current_checks: List[CheckResult] = []
_current_findings: List[Finding] = []
_scan_id = 0
_scan_in_progress = False
_scanned_at: Optional[str] = None


def _sorted_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))


def _findings_response() -> dict:
    return {
        "scan_id": _scan_id,
        "scanned_at": _scanned_at,
        "score": compute_security_score(_current_findings),
        "findings": [{"id": i, **f.to_dict()} for i, f in enumerate(_current_findings)],
    }


@app.post("/api/scan")
def scan() -> dict:
    global _current_checks, _current_findings, _scan_id, _scan_in_progress, _scanned_at

    with _lock:
        if _scan_in_progress:
            raise HTTPException(status_code=409, detail="A scan is already in progress.")
        _scan_in_progress = True

    try:
        checks = run_full_scan()
    except (ClientError, NoCredentialsError, ProfileNotFound) as e:
        raise HTTPException(status_code=502, detail=f"AWS scan failed: {e}")
    finally:
        with _lock:
            _scan_in_progress = False

    findings = []
    for r in checks:
        finding = r.to_finding()
        if finding is not None:
            findings.append(finding)

    with _lock:
        _current_checks = checks
        _current_findings = _sorted_findings(findings)
        _scan_id += 1
        _scanned_at = datetime.now(timezone.utc).isoformat()
        score = compute_security_score(_current_findings)

        severity_counts = {
            sev.value: sum(1 for f in _current_findings if f.severity == sev) for sev in SEVERITY_ORDER
        }
        history.append_scan({
            "scanned_at": _scanned_at,
            "total_findings": len(_current_findings),
            "severity_counts": severity_counts,
            "score": score["score"],
            "label": score["label"],
        })

    return _findings_response()


@app.get("/api/findings")
def get_findings() -> dict:
    return _findings_response()


@app.get("/api/resources")
def get_resources() -> dict:
    with _lock:
        return {
            "scan_id": _scan_id,
            "scanned_at": _scanned_at,
            "checks": [{"id": i, **c.to_dict()} for i, c in enumerate(_current_checks)],
        }


@app.get("/api/history")
def get_history() -> dict:
    return {"scans": history.load_history()}


@app.get("/api/config")
def get_config() -> dict:
    return {
        "aws_region": config.AWS_REGION,
        "aws_profile": config.AWS_PROFILE or "default credential chain",
        "groq_model": config.GROQ_MODEL,
        "iam_unused_key_days": config.IAM_UNUSED_KEY_DAYS,
    }


class ConfigUpdate(BaseModel):
    iam_unused_key_days: int


@app.post("/api/config")
def update_config(body: ConfigUpdate) -> dict:
    if body.iam_unused_key_days < 0:
        raise HTTPException(status_code=422, detail="iam_unused_key_days must be >= 0")
    # In-memory only -- not persisted to .env, resets on server restart.
    config.IAM_UNUSED_KEY_DAYS = body.iam_unused_key_days
    return get_config()


@app.post("/api/findings/{scan_id}/{finding_id}/explain")
def explain(scan_id: int, finding_id: int) -> dict:
    with _lock:
        if scan_id != _scan_id:
            raise HTTPException(status_code=409, detail="This finding is from a stale scan -- re-fetch findings.")
        if finding_id < 0 or finding_id >= len(_current_findings):
            raise HTTPException(status_code=404, detail="Finding not found.")
        finding = _current_findings[finding_id]

    try:
        explanation = explain_finding(finding)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"explanation": explanation}


# Production/demo mode: serve the built React app if it exists. In dev, the
# Vite dev server serves the frontend and proxies /api/* here instead.
_frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _frontend_dist.is_dir():
    app.mount("/", StaticFiles(directory=str(_frontend_dist), html=True), name="frontend")
