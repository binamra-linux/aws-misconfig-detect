"""
Owns the current-scan state and the "only one scan at a time" lock.

This lives in backend/ rather than api/main.py because *two* callers need it: the
HTTP handlers and the background scheduler. Previously the lock was held only
inside the HTTP handlers, which meant a scheduled scan calling run_full_scan()
directly would bypass it entirely and race with a manual scan on the module
globals below. Every scan -- manual or scheduled -- must now go through
try_begin_scan()/end_scan().

State is in-memory (scan history is separately persisted via backend.history), so
it resets on restart. That's fine for a single-process tool, but it *is* why the
app must run single-worker: with multiple workers each process would hold its own
copy of this state and answer /api/findings inconsistently.
"""

import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from backend import history
from backend.models import CheckResult, Finding, Severity
from backend.scoring import compute_security_score

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

# A finding's stable identity across scans. Used to tell "this is new since the
# last scan" from "this is the same backlog item we already alerted about".
Fingerprint = Tuple[str, str, Optional[str]]

_lock = threading.Lock()
_current_checks: List[CheckResult] = []
_current_findings: List[Finding] = []
_scan_id = 0
_scanned_at: Optional[str] = None

_scan_in_progress = False
_scan_owner: Optional[str] = None  # "manual" | "scheduled"


def try_begin_scan(source: str) -> bool:
    """Claim the scan slot. Returns False if a scan is already running -- callers
    decide whether that's a 409 (HTTP) or a skip (scheduler)."""
    global _scan_in_progress, _scan_owner
    with _lock:
        if _scan_in_progress:
            return False
        _scan_in_progress = True
        _scan_owner = source
        return True


def end_scan() -> None:
    global _scan_in_progress, _scan_owner
    with _lock:
        _scan_in_progress = False
        _scan_owner = None


def scan_owner() -> Optional[str]:
    with _lock:
        return _scan_owner


def busy_message() -> str:
    owner = scan_owner()
    if owner == "scheduled":
        return "A scheduled scan is already running. Try again in a moment."
    return "A scan is already in progress."


def fingerprints(findings: List[Finding]) -> Set[Fingerprint]:
    return {(f.check_type, f.resource_id, f.region) for f in findings}


def current_findings() -> List[Finding]:
    with _lock:
        return list(_current_findings)


def _sorted_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))


def findings_response() -> dict:
    with _lock:
        return {
            "scan_id": _scan_id,
            "scanned_at": _scanned_at,
            "score": compute_security_score(_current_findings),
            "findings": [{"id": i, **f.to_dict()} for i, f in enumerate(_current_findings)],
        }


def resources_response() -> dict:
    with _lock:
        return {
            "scan_id": _scan_id,
            "scanned_at": _scanned_at,
            "checks": [{"id": i, **c.to_dict()} for i, c in enumerate(_current_checks)],
        }


def finding_at(scan_id: int, finding_id: int) -> Tuple[Optional[Finding], Optional[str]]:
    """Look up a finding by (scan_id, index), returning (finding, error) so callers
    can map the error to their own status codes."""
    with _lock:
        if scan_id != _scan_id:
            return None, "stale"
        if finding_id < 0 or finding_id >= len(_current_findings):
            return None, "not_found"
        return _current_findings[finding_id], None


def finalize_scan(checks: List[CheckResult]) -> Tuple[Dict, List[Finding]]:
    """Record a completed scan as the new current state and append it to history.

    Returns (response, new_findings) as a tuple rather than folding new_findings
    into the response dict -- they're Finding objects, not JSON, and an endpoint
    returning them by accident would 500.

    `new_findings` is what wasn't present in the previous scan. The scheduler
    alerts on those only: re-emailing an unchanged backlog every night is how
    alerts get filtered into a folder and ignored.
    """
    global _current_checks, _current_findings, _scan_id, _scanned_at

    findings = [f for f in (r.to_finding() for r in checks) if f is not None]

    with _lock:
        previous = fingerprints(_current_findings)

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

        new_findings = [
            f for f in _current_findings if (f.check_type, f.resource_id, f.region) not in previous
        ]

        response = {
            "scan_id": _scan_id,
            "scanned_at": _scanned_at,
            "score": score,
            "findings": [{"id": i, **f.to_dict()} for i, f in enumerate(_current_findings)],
        }
        return response, new_findings


def reset() -> None:
    """Clear all scan state and wipe persisted history."""
    global _current_checks, _current_findings, _scan_id, _scanned_at

    with _lock:
        _current_checks = []
        _current_findings = []
        _scan_id = 0
        _scanned_at = None

    history.clear_history()
