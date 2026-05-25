from __future__ import annotations

from dataclasses import dataclass, field

_TTP_SEVERITY: dict[str, str] = {
    "T1486": "critical",    # Data Encrypted for Impact (ransomware)
    "T1041": "high",        # Exfiltration Over C2 Channel
    "T1110": "high",        # Brute Force
    "T1110.001": "high",    # Brute Force: Password Guessing
    "T1548": "critical",    # Abuse Elevation Control Mechanism
    "T1548.003": "critical", # Sudo and Sudo Caching
    "T1537": "high",        # Transfer Data to Cloud Account
    "T1055": "medium",      # Process Injection
    "T1078": "high",        # Valid Accounts
    "T1190": "critical",    # Exploit Public-Facing Application
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
