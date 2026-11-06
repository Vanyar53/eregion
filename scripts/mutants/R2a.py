"""R2a (Partie de #79): the Stratus Red Team adapter — a technique id resolved against a CLOSED
allow-list, the pinned binary checked at run time, the warmup/detonate/revert/cleanup cycle run
from an armed Orodruin with every phase journaled, and a read-only Graph probe of the initial
state. M4315–M4334, measured by tests/unit/test_annatar_stratus.py."""
ENG = "annatar/engines/stratus.py"
HOST = "annatar/executors/stratus_host.py"
RUN = "annatar/runner/engine.py"
PARSER = "annatar/runner/parser.py"
_T = "tests/unit/test_annatar_stratus.py"

MUTANTS = [
    # ── The adapter: fail closed on the id and the allow-list ─────────────────────────
    ("M4315", "the technique-id regex accepts a non-Azure platform (aws/gcp)", ENG,
     'r"^azure\\.[a-z0-9]+(?:-[a-z0-9]+)*\\.[a-z0-9]+(?:-[a-z0-9]+)*$"',
     'r"^[a-z0-9]+\\.[a-z0-9]+(?:-[a-z0-9]+)*\\.[a-z0-9]+(?:-[a-z0-9]+)*$"'),
    ("M4316", "a technique off the catalog's closed allow-list is resolved anyway", ENG,
     "    entry = entries.get(tid)\n    if entry is None:",
     "    entry = entries.get(tid) or {}\n    if False:"),
    # ── The pinned binary is checked at run time (SEC5) ───────────────────────────────
    ("M4317", "a changed Stratus binary passes the sha256 check", ENG,
     "    if digest != pinned:", "    if digest != pinned and False:"),
    ("M4318", "a binary with no sha256 in the PIN is accepted", ENG,
     "    if pinned is None:", "    if pinned is None and False:"),
    # ── The read-only Graph probe can only read ───────────────────────────────────────
    ("M4319", "the Graph probe accepts a path that is not a read path", ENG,
     '        if not _GRAPH_READ.fullmatch(self.read or ""):', "        if False:"),
    ("M4320", "the Graph probe is issued with a non-GET (mutating) method", ENG,
     '        return "GET", self.read', '        return "POST", self.read'),
    ("M4321", "the probe reads absence as presence (the initial-state check inverts)", ENG,
     "        return (not present) if self.expect_absent else present",
     "        return present if self.expect_absent else present"),
    ("M4326", "a probe without expect_absent defaults to present, not absent", ENG,
     '    absent = spec.get("expect_absent", True)',
     '    absent = spec.get("expect_absent", False)'),
    # ── Offline — Orodruin has no Internet ────────────────────────────────────────────
    ("M4322", "the offline env drops the provider plugin cache (TF_PLUGIN_CACHE_DIR)", ENG,
     "    if plugin_cache is not None:", "    if plugin_cache is not None and False:"),
    ("M4323", "the offline env drops the provider mirror (TF_CLI_CONFIG_FILE)", ENG,
     "    if terraformrc is not None:", "    if terraformrc is not None and False:"),
    # ── The cycle and the exact argv ──────────────────────────────────────────────────
    ("M4324", "the cycle loses its cleanup phase (prerequisites left behind)", ENG,
     'PHASES = ("warmup", "detonate", "revert", "cleanup")',
     'PHASES = ("warmup", "detonate", "revert")'),
    ("M4325", "a phase's argv puts the technique id before the phase verb", ENG,
     "        StratusPhase(name=name, argv=[binary, name, tid], label=f\"stratus {name} {tid}\")",
     "        StratusPhase(name=name, argv=[binary, tid, name], label=f\"stratus {name} {tid}\")"),
    # ── The injector transport: journal, cap, passive, read-only probe ────────────────
    ("M4327", "a phase runs without being journaled first (Orodruin audit skipped)", HOST,
     "        self._before_call(name, phase.label)", "        pass"),
    ("M4328", "a Stratus phase that exits non-zero is treated as success", HOST,
     '        if getattr(completed, "returncode", 0) != 0:',
     '        if getattr(completed, "returncode", 0) != 0 and False:'),
    ("M4329", "a phase runs with no armed contract (passive gate removed)", HOST,
     "        if self._session is None:", "        if self._session is None and False:"),
    ("M4330", "the read-only Graph probe is counted as an injector call against the cap", HOST,
     '            self._session.declare(f"stratus:graph-probe:{when}", f"{probe.name} GET {path}")',
     '            self._session.before_call(f"stratus:graph-probe:{when}", self.target,'
     ' f"{probe.name} GET {path}")'),
    # ── The runner's dispatch (control plane) ─────────────────────────────────────────
    ("M4331", "the run's report mislabels the engine as atomic", RUN,
     '            "engine": "stratus",', '            "engine": "atomic",'),
    ("M4332", "the control-plane run claims a detection it never measured (ID1)", RUN,
     '            metrics["detection"] = "unknown"', '            metrics["detection"] = "detected"'),
    ("M4333", "detonate runs even on a dirty initial state (the before-probe failed)", RUN,
     "            if attack_error is None:", "            if attack_error is None or True:"),
    # ── Authoring ─────────────────────────────────────────────────────────────────────
    ("M4334", "the stratus engine is dropped from KNOWN_ENGINES (refused at authoring)", PARSER,
     'KNOWN_ENGINES = frozenset({"local-script", "atomic", "stratus"})',
     'KNOWN_ENGINES = frozenset({"local-script", "atomic"})'),
]

TESTS = {
    "M4315": f"{_T}::test_resolve_refuses_a_malformed_id",
    "M4316": f"{_T}::test_resolve_refuses_a_technique_off_the_allowlist",
    "M4317": f"{_T}::test_verify_binary_refuses_a_changed_binary",
    "M4318": f"{_T}::test_verify_binary_refuses_when_pin_has_no_binary",
    "M4319": f"{_T}::test_graph_probe_rejects_a_non_read_path",
    "M4320": f"{_T}::test_resolve_parses_a_read_only_graph_probe",
    "M4321": f"{_T}::test_graph_probe_holds_on_absence_and_presence",
    "M4322": f"{_T}::test_airgap_env_points_terraform_offline",
    "M4323": f"{_T}::test_airgap_env_points_terraform_offline",
    "M4324": f"{_T}::test_resolve_builds_the_four_phases",
    "M4325": f"{_T}::test_resolve_builds_the_four_phases",
    "M4326": f"{_T}::test_graph_probe_defaults_to_expect_absent",
    "M4327": f"{_T}::test_executor_journals_each_phase_before_it_runs",
    "M4328": f"{_T}::test_executor_raises_on_a_nonzero_exit",
    "M4329": f"{_T}::test_executor_passive_without_a_session",
    "M4330": f"{_T}::test_graph_probe_reads_and_is_declared_not_counted",
    "M4331": f"{_T}::test_run_stratus_cycle_runs_all_phases_and_emits_attack_started",
    "M4332": f"{_T}::test_run_stratus_cycle_runs_all_phases_and_emits_attack_started",
    "M4333": f"{_T}::test_run_stratus_cycle_does_not_detonate_on_a_dirty_initial_state",
    "M4334": f"{_T}::test_known_engines_has_stratus",
}
