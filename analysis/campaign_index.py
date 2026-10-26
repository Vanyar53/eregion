"""D-2 (#184): put past campaigns into the report's index, so that the next report can face
its previous campaign.

    python -m analysis.campaign_index runs/campaigns/<id> [runs/campaigns/<id> …]
    python -m analysis.campaign_index --all runs/campaigns      # every done or aborted one

On H0 (Jonathan; the index is on the VM's disk, mounted into the watch's container):

    make glorfindel-host-ssh
    docker exec eregion-watch python -m analysis.campaign_index --all runs/campaigns

The choice of the previous campaign (analysis/campaign_report.py ``previous_campaign``)
reads, on each run of the index, its campaign's state and start and the run's VM. A report
written before D-2 indexed its runs without them: never chosen. This adds them.

A run already in the index keeps the facts it was indexed with — those of its campaign's
report, seen while its exercise window was still on the disk (a window is emptied a week
after its end, eregion_core/exercise.py ``PURGE_AFTER_S``: computed again later, the
decision would be unknown, or the run refused). Only the campaign's state and start, and
the run's VM when its facts lack it (the manifest's ``target_resource_id``), are added. A
run not yet in the index is computed from the files, as the report computes it (the watch's
``watch-*`` files, the windows in ``runs/exercises``; a campaign that came through the
channel has its VMs' enrollment read from their tags, H-1). Run twice, the index is the
same: the command is idempotent. It calls no model, and writes nothing but the index.

A campaign is put in only once it has ended (``done`` or ``aborted``: an aborted campaign is
never chosen as the previous one, but its runs stay citable by a trend); one still running,
or whose manifest cannot be read, is said and left.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from analysis import campaign_report as cr
from eregion_core.exercise_channel import safe_part

ENDED = ("done", "aborted")


@dataclass
class Versed:
    campaign_id: str
    state: str = ""
    kept: list[str] = field(default_factory=list)       # runs already indexed: their facts kept
    computed: list[str] = field(default_factory=list)   # runs computed from the files
    missing: list[str] = field(default_factory=list)    # runs neither indexed nor computable
    left: str = ""                                      # why the campaign was not put in
    start_refused: str = ""                             # its manifest's start not believed (D2b)

    def line(self) -> str:
        if self.left:
            return f"{self.campaign_id} : laissée ({self.left})"
        out = (f"{self.campaign_id} ({self.state}) : {len(self.kept) + len(self.computed)} run(s) "
               f"dans l'index — {len(self.kept)} gardé(s) tel(s) quel(s), "
               f"{len(self.computed)} calculé(s) depuis les fichiers")
        if self.missing:
            out += f" ; absent(s) des faits : {', '.join(self.missing)}"
        if self.start_refused:
            out += f" ; {self.start_refused}"
        return out


def _run_ids(manifest: dict) -> dict[str, dict]:
    """The scenarios with a plain run id, by run id — those the report indexes."""
    out = {}
    for s in manifest.get("scenarios") or []:
        rid = str(s.get("run_id") or "") if isinstance(s, dict) else ""
        if rid and safe_part(rid):
            out[rid] = s
    return out


def verse(campaign_dir: Path, path: Path | None = None, warn=cr._say) -> Versed:
    """Put one campaign into the index (``path``, else the report's): what was done."""
    campaign_dir = Path(campaign_dir)
    try:
        manifest = json.loads((campaign_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return Versed(campaign_dir.name, left=f"manifeste illisible : {type(e).__name__}")
    if not isinstance(manifest, dict):
        return Versed(campaign_dir.name, left="manifeste illisible")
    info = cr.campaign_info(campaign_dir)
    out = Versed(info.campaign_id, info.state, start_refused=info.start_refused)
    if info.state not in ENDED:
        out.left = f"état {info.state or 'inconnu'} : pas terminée"
        return out
    scenarios = _run_ids(manifest)
    if not scenarios:
        return out
    got = cr._collection(path).get(ids=list(scenarios))
    indexed: dict[str, cr.RunFact] = {}
    for rid, meta in zip(got.get("ids") or [], got.get("metadatas") or []):
        fact = cr.fact_of(meta)
        if fact is not None and fact.run_id == rid and fact.campaign_id == info.campaign_id:
            if not fact.target:   # indexed before D-2: the manifest names its VM
                fact.target = str(scenarios[rid].get("target_resource_id") or "")
            indexed[rid] = fact
    computed: list[cr.RunFact] = []
    if len(indexed) < len(scenarios):
        cr.check_enrollment(campaign_dir)
        computed = [f for f in cr.collect_facts(campaign_dir, warn=warn)
                    if f.run_id in scenarios and f.run_id not in indexed]
    out.kept = sorted(indexed)
    out.computed = sorted(f.run_id for f in computed)
    out.missing = sorted(set(scenarios) - set(indexed) - set(out.computed))
    cr.index_facts([*indexed.values(), *computed], path, info)
    return out


def campaigns(root: Path) -> list[Path]:
    """The campaign directories under ``root`` (those with a manifest), by name."""
    root = Path(root)
    return sorted(p for p in root.iterdir() if (p / "manifest.json").is_file()) if root.is_dir() else []


def main(argv: list[str]) -> int:
    if not argv or argv == ["--all"]:
        print("\n".join(line.strip() for line in __doc__.splitlines()[3:5]))
        return 2
    dirs = campaigns(Path(argv[1])) if argv[0] == "--all" else [Path(a) for a in argv]
    if argv[0] == "--all" and not dirs:
        print(f"aucune campagne sous {argv[1]}")
        return 1
    print(f"index : {cr.index_path()}")
    failed = 0
    for d in dirs:
        try:
            result = verse(d)
        except Exception as e:  # one campaign that fails never stops the others
            print(f"{d.name} : en échec ({type(e).__name__}: {e})")
            failed += 1
            continue
        print(result.line())
        failed += bool(result.left and not argv[0] == "--all")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
