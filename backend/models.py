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
