"""Data model shared by the detector, the engine and the output sinks."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def severity_from_score(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 45:
        return "MEDIUM"
    return "LOW"


def severity_rank(name: str) -> int:
    return SEVERITIES.index(name.upper())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    """One suspicious domain observed in a Certificate Transparency log."""

    domain: str
    target: str
    registered_domain: str
    score: int
    reasons: List[str] = field(default_factory=list)
    unicode_domain: Optional[str] = None
    timestamp: str = field(default_factory=_now_iso)
    # certificate metadata (filled in by the engine)
    issuer: Optional[str] = None
    cert_fingerprint: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    log_source: Optional[str] = None
    san_count: int = 0
    sans: List[str] = field(default_factory=list)
    # DNS enrichment (optional)
    ips: List[str] = field(default_factory=list)
    resolved: Optional[bool] = None

    @property
    def severity(self) -> str:
        return severity_from_score(self.score)

    def bump(self, points: int, reason: str) -> None:
        self.score = min(100, self.score + points)
        self.reasons.append(reason)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        head = {"timestamp": data.pop("timestamp"), "severity": self.severity}
        head.update(data)
        return head
