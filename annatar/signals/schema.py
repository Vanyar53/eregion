from __future__ import annotations

from dataclasses import dataclass, field

_TTP_SEVERITY: dict[str, str] = {
    "T1486": "critical",   # Data Encrypted for Impact (ransomware)
    "T1041": "high",       # Exfiltration Over C2 Channel
    "T1537": "high",       # Transfer Data to Cloud Account
    "T1055": "medium",     # Process Injection
    "T1078": "high",       # Valid Accounts
    "T1190": "critical",   # Exploit Public-Facing Application
}


def severity_for_ttp(ttp: str) -> str:
    return _TTP_SEVERITY.get(ttp, "medium")


@dataclass
class Signal:
    signal_id: str
    timestamp: str
    provider: str
    resource_id: str
    resource_type: str
    ttp: str
    severity: str
    event: str
    raw_signal: dict = field(default_factory=dict)
    context: dict = field(default_factory=dict)
