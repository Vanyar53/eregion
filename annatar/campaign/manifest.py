"""Campaign manifest — the audit/steering artifact (see collab/design_campaign_manifest.md).

Annatar writes it; Glorfindel reads it POST-HOC (never pre/per execution → blind loop
stays honest) for auto-activation + replay. Atomic writes (tmp + rename) so a reader
never sees a half-written JSON.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "1.0"

CAMPAIGN_STATES = ("planned", "ratified", "running", "done", "aborted")
SCENARIO_STATES = ("pending", "running", "executed", "skipped", "error")


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_campaign_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


@dataclass
class ScenarioEntry:
    seq: int
    ttp: str
    tactic: str
    name: str
    scenario_file: str            # relative to the campaign dir
    target_resource_id: str
    destructive: bool = False
    safe_target: str = ""
    status: str = "pending"
    run_id: str | None = None
    detection: str | None = None  # "detected" | "missed" | "unknown"
    detection_latency_s: float | None = None
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None


@dataclass
class Scope:
    sandbox: str = "celebrimbor"
    subscription_id: str = ""
    allowed_resource_groups: list[str] = field(default_factory=list)
    allowed_resource_ids: list[str] = field(default_factory=list)


@dataclass
class Budget:
    max_scenarios: int = 10
    max_cost_usd: float = 5.0
    allow_destructive: bool = False
    detection_window_s: int = 600
    reset_nsg_between: bool = True


@dataclass
class CampaignManifest:
    campaign_id: str
    objective: str
    scope: Scope
    budget: Budget
    scenarios: list[ScenarioEntry] = field(default_factory=list)
    state: str = "planned"
    kill_switch: bool = False
    schema_version: str = SCHEMA_VERSION
    created_by: str = "annatar-planner"
    created_at: str = field(default_factory=_utcnow)
    updated_at: str = field(default_factory=_utcnow)

    # ── results (recomputed from scenarios) ──────────────────────────────────
    @property
    def results(self) -> dict:
        ex = [s for s in self.scenarios if s.status == "executed"]
        return {
            "executed": len(ex),
            "detected": sum(1 for s in ex if s.detection == "detected"),
            "missed": sum(1 for s in ex if s.detection == "missed"),
            "skipped": sum(1 for s in self.scenarios if s.status == "skipped"),
            "errors": sum(1 for s in self.scenarios if s.status == "error"),
            "cost_usd_est": 0.0,
        }

    # ── serialization ────────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "campaign_id": self.campaign_id,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "objective": self.objective,
            "scope": asdict(self.scope),
            "budget": asdict(self.budget),
            "state": self.state,
            "kill_switch": self.kill_switch,
            "scenarios": [asdict(s) for s in self.scenarios],
            "results": self.results,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CampaignManifest":
        return cls(
            campaign_id=d["campaign_id"],
            objective=d.get("objective", ""),
            scope=Scope(**d.get("scope", {})),
            budget=Budget(**d.get("budget", {})),
            scenarios=[ScenarioEntry(**s) for s in d.get("scenarios", [])],
            state=d.get("state", "planned"),
            kill_switch=d.get("kill_switch", False),
            schema_version=d.get("schema_version", SCHEMA_VERSION),
            created_by=d.get("created_by", "annatar-planner"),
            created_at=d.get("created_at", _utcnow()),
            updated_at=d.get("updated_at", _utcnow()),
        )

    # ── persistence ────────────────────────────────────────────────────────
    def save(self, campaign_dir: str | Path) -> Path:
        """Atomically write manifest.json under the campaign dir."""
        d = Path(campaign_dir)
        d.mkdir(parents=True, exist_ok=True)
        self.updated_at = _utcnow()
        target = d / "manifest.json"
        fd, tmp = tempfile.mkstemp(dir=str(d), prefix=".manifest-", suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self.to_dict(), f, indent=2)
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return target

    @classmethod
    def load(cls, campaign_dir: str | Path) -> "CampaignManifest":
        path = Path(campaign_dir) / "manifest.json"
        return cls.from_dict(json.loads(path.read_text()))

    # ── state transitions ────────────────────────────────────────────────────
    def set_state(self, state: str) -> None:
        if state not in CAMPAIGN_STATES:
            raise ValueError(f"invalid campaign state: {state}")
        self.state = state
        self.updated_at = _utcnow()


def campaigns_root(runs_dir: str | Path = "runs") -> Path:
    return Path(runs_dir) / "campaigns"


def campaign_dir(campaign_id: str, runs_dir: str | Path = "runs") -> Path:
    return campaigns_root(runs_dir) / campaign_id
