"""
Server-side security score -- single source of truth, mirrored exactly by
frontend/src/lib/score.ts's weights (the frontend maps the label to a color,
since that's a presentation concern; this module only computes score+label).

A simple severity-weighted heuristic, not a literal "% of checks passed" --
deducts points per finding, weighted by severity, floored at 0. See
backend/scanner.py::run_full_scan() for a real pass/fail count if that's
ever needed instead.
"""

from typing import Dict, List, TypedDict

from backend.models import Finding, Severity

SEVERITY_WEIGHT: Dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
}


class SecurityScore(TypedDict):
    score: int
    label: str


def compute_security_score(findings: List[Finding]) -> SecurityScore:
    deduction = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    score = max(0, round(100 - deduction))

    if score >= 90:
        label = "Secure"
    elif score >= 60:
        label = "Needs Attention"
    else:
        label = "At Risk"

    return {"score": score, "label": label}
