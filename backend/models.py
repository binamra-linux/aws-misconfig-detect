from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    resource_id: str
    resource_type: str
    check_type: str
    severity: Severity
    description: str
    detail: Dict[str, Any] = field(default_factory=dict)
    region: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


@dataclass
class CheckResult:
    """
    The outcome of a single check against a single resource, recorded whether
    it passed or failed. A CheckResult is only ever created for checks that
    actually apply to the resource (e.g. no MFA-check CheckResult is created
    for a user with no console password) -- that keeps "how many checks were
    run" a meaningful denominator for anything built on top of this (the
    Resources tab, a real pass-rate score, etc).
    """

    resource_id: str
    resource_type: str
    check_type: str
    status: CheckStatus
    description: str
    severity: Optional[Severity] = None
    detail: Dict[str, Any] = field(default_factory=dict)
    region: Optional[str] = None

    def to_finding(self) -> Optional[Finding]:
        if self.status == CheckStatus.PASS:
            return None
        assert self.severity is not None, "FAIL CheckResult must carry a severity"
        return Finding(
            resource_id=self.resource_id,
            resource_type=self.resource_type,
            check_type=self.check_type,
            severity=self.severity,
            description=self.description,
            detail=self.detail,
            region=self.region,
        )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value if self.severity else None
        return d
