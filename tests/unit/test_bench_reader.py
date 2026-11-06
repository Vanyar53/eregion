"""BRO1 (#614): the bench's read identity, for the Claude session « Banc » alone — an application of
the bench's tenant, its principal, a PUBLIC certificate (the private key drawn on the operator's
machine, never in Terraform's state), and Log Analytics Reader on the bench's workspace alone —, off
by default, the canonical instance only.

Read from the files, no Azure, no Graph, no Terraform needed; the Make targets run against a fake
terraform, the script against a fake az, both first on the PATH; HOME and the reader's directory
are tmp dirs. The same Terraform contract, planned against mock providers:
infra/terraform/tests/bench_reader.tftest.hcl (`terraform test`). Mutants M4420–M4424
(scripts/mutants/BRO1.py).
"""
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TF = ROOT / "infra/terraform"
SCRIPT = ROOT / "scripts" / "bench_reader.py"

_spec = importlib.util.spec_from_file_location("bench_reader", SCRIPT)
br = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(br)

TENANT = "00000000-0000-0000-0000-0000000000f0"
CLIENT = "00000000-0000-0000-0000-0000000000b2"
WORKSPACE = "00000000-0000-0000-0000-0000000000a1"
WS_ID = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/"
         "Microsoft.OperationalInsights/workspaces/law-celebrimbor-example")
OUTPUT = {"tenant_id": TENANT, "client_id": CLIENT, "workspace_id": WORKSPACE, "workspace_resource_id": WS_ID,
          "role": "Log Analytics Reader", "certificate_end_date": "2026-12-06T00:00:00Z"}


def _reader_tf() -> str:
    return (TF / "bench_reader.tf").read_text(encoding="utf-8")


def _every_tf() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(TF.glob("*.tf")))


def _block(text: str, kind: str, name: str) -> str:
    return text.split(f'{kind} "{name}"')[1].split("\n}\n")[0]


# ── Terraform: what it holds ─────────────────────────────────────────────────

def test_off_by_default_on_the_canonical_instance_only():
    text = _reader_tf()
    body = re.search(r'(?ms)^variable "bench_reader_enabled" \{\n(.*?)^\}', text).group(1)
    assert re.search(r"(?m)^\s*type\s*=\s*bool\s*$", body)
    assert re.search(r"(?m)^\s*default\s*=\s*false\s*$", body)
    assert re.search(r"(?m)^\s*nullable\s*=\s*false\s*$", body)
    assert 'bench_reader_enabled = var.bench_reader_enabled && local.instance == "default"' in text
    counts = re.findall(r'(?m)^resource "[^"]+" "[^"]+" \{\n\s*count = (.*)$', text)
    assert len(counts) == 4 and all(c == "local.bench_reader_enabled ? 1 : 0" for c in counts), counts
    assert 'check "bench_reader_on_the_canonical_instance"' in text
    assert 'condition     = local.instance == "default" || !var.bench_reader_enabled' in text
    # The certificate file is read only when on: off, nothing on the operator's disk is touched.
    # Sensitive: a private key pasted there by mistake is never shown by the precondition's diagnostic.
    assert ('bench_reader_certificate = local.bench_reader_enabled ? '
            'sensitive(try(file(pathexpand(var.bench_reader_certificate_file)), "")) : ""') in text
    example = (TF / "terraform.tfvars.example").read_text(encoding="utf-8")
    assert re.search(r"(?m)^# bench_reader_enabled = true", example)
    assert not re.search(r"(?m)^\s*bench_reader_enabled\s*=", example)


def test_one_role_log_analytics_reader_on_the_workspace_alone():
    """The exact role, at the workspace's scope — never the group, the subscription, H0 — and the
    reader's principal named by that one assignment, nowhere else."""
    text = _reader_tf()
    assert 'bench_reader_role = "Log Analytics Reader"\n' in text
    role = _block(text, "resource", 'azurerm_role_assignment" "bench_reader')
    assert "scope                = azurerm_log_analytics_workspace.celebrimbor.id\n" in role
    assert "role_definition_name = local.bench_reader_role\n" in role
    assert "principal_id         = azuread_service_principal.bench_reader[0].object_id\n" in role
    assert 'principal_type       = "ServicePrincipal"' in role
    every = _every_tf()
    assert every.count("azuread_service_principal.bench_reader[0].object_id") == 1
    assert every.count("local.bench_reader_role") == 2      # the assignment, the output
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    for word in ("azuread_directory_role_assignment", "azuread_app_role_assignment", "required_resource_access",
                 "azuread_service_principal_delegated_permission_grant"):
        assert word not in code, word
    assert code.count('resource "azurerm_role_assignment"') == 1


def test_the_private_key_never_enters_terraform():
    """A public certificate, one CERTIFICATE block and nothing else, or the plan stops before the
    state; no password anywhere: a secret would sit in clear in the local state."""
    text = _reader_tf()
    every = _every_tf()
    assert 'resource "azuread_application_password"' not in every
    assert 'resource "azuread_service_principal_password"' not in every
    assert every.count('resource "azuread_application_certificate"') == 1
    cert = _block(text, "resource", 'azuread_application_certificate" "bench_reader')
    assert "application_id = azuread_application.bench_reader[0].id\n" in cert
    assert 'type           = "AsymmetricX509Cert"' in cert
    assert "value          = local.bench_reader_certificate\n" in cert
    pattern = re.search(r'can\(regex\("(.*)", local\.bench_reader_certificate\)\)', cert).group(1)
    regex = re.compile(pattern.encode().decode("unicode_escape"))
    one = (TF / "tests/fixtures/bench_reader.crt").read_text()
    assert regex.fullmatch(one)
    assert not regex.fullmatch((TF / "tests/fixtures/bench_reader_two_blocks.pem").read_text())
    key_header = "PRIVATE" + " KEY"     # no key-shaped text in the repository for scanners to flag
    assert not regex.fullmatch(f"-----BEGIN {key_header}-----\nAAAA\n-----END {key_header}-----\n" + one)
    assert not regex.fullmatch("")
    # The default: the reader's directory, never ~/.config/eregion/ nor ~/.config/eregion-agents/.
    assert 'default     = "~/.config/eregion-banc/reader.crt"' in text
    # The output: identifiers, never a key, a value or a thumbprint.
    out = _block(text, "output", "bench_reader")
    assert re.findall(r"(?m)^ {4}(\w+)\s+=", out) == ["tenant_id", "client_id", "workspace_id",
                                                     "workspace_resource_id", "role", "certificate_end_date"]


def test_the_reader_is_never_a_target():
    """No enrolment tag on the application, never named by eregion-identities (IDI1): the guard
    never takes it for a test identity; no permission asked, no owner."""
    app = _block(_reader_tf(), "resource", 'azuread_application" "bench_reader')
    for word in ("tags", "required_resource_access", "owners", "app_role ", "password"):
        assert word not in app, word
    assert 'sign_in_audience = "AzureADMyOrg"' in app
    identity = (TF / "entra_identity.tf").read_text(encoding="utf-8")
    assert "bench_reader" not in identity


def test_the_end_of_the_identifier_is_the_certificate_s_never_the_api_s():
    """Without end_date, the API picks one (« typically around 2 years », the azuread provider says):
    the end keygen wrote beside the certificate is posed, 91 days at most after the plan."""
    text = _reader_tf()
    assert 'default     = "~/.config/eregion-banc/reader.end"' in text
    assert ('bench_reader_certificate_end = local.bench_reader_enabled ? '
            'trimspace(try(file(pathexpand(var.bench_reader_certificate_end_file)), "")) : ""') in text
    cert = _block(text, "resource", 'azuread_application_certificate" "bench_reader')
    assert "end_date       = local.bench_reader_certificate_end\n" in cert
    assert 'timecmp(local.bench_reader_certificate_end, timeadd(plantimestamp(), "2184h")) <= 0' in cert
    assert "end_date_relative" not in cert


needs_tf = pytest.mark.skipif(shutil.which("terraform") is None or not (TF / ".terraform" / "providers").is_dir(),
                              reason="terraform absent, or infra/terraform not initialized (init -backend=false)")


@needs_tf
def test_a_private_key_beside_the_certificate_is_never_shown_by_the_plan(tmp_path):
    """The precondition stops the plan, and its diagnostic never shows the file (reproduced before the
    value was made sensitive: the whole file, in clear): the module copied to tmp (never the
    operator's tfvars nor state), its providers linked, a mock plan."""
    mod = tmp_path / "mod"
    shutil.copytree(TF, mod, ignore=shutil.ignore_patterns(".terraform", "tests", "*.tfvars", "*.tfstate*"))
    (mod / ".terraform").symlink_to(TF / ".terraform", target_is_directory=True)
    (mod / "tests").mkdir()
    marker = "bm90IGEga2V5LCBhIG1hcmtlciB0aGF0IG11c3QgbmV2ZXIgYmUgc2hvd24"
    crt = (TF / "tests/fixtures/bench_reader.crt").read_text()
    (mod / "tests" / "two_blocks.pem").write_text(crt + f"-----BEGIN EXAMPLE BLOCK-----\n{marker}\n"
                                                  "-----END EXAMPLE BLOCK-----\n")
    (mod / "tests" / "end").write_text("2026-12-06T00:00:00Z\n")
    head = (TF / "tests" / "bench_reader.tftest.hcl").read_text(encoding="utf-8").split('\nrun "')[0]
    (mod / "tests" / "leak.tftest.hcl").write_text(head + """
run "leak" {
  command = plan
  variables {
    bench_reader_enabled              = true
    bench_reader_certificate_file     = "tests/two_blocks.pem"
    bench_reader_certificate_end_file = "tests/end"
  }
}
""")
    home = tmp_path / "home"
    home.mkdir()
    env = {"PATH": os.environ["PATH"], "HOME": str(home), "CHECKPOINT_DISABLE": "1", "TF_IN_AUTOMATION": "1"}
    res = subprocess.run(["terraform", f"-chdir={mod}", "test", "-no-color", "-filter=tests/leak.tftest.hcl"],
                         env=env, capture_output=True, text=True, timeout=300)
    out = res.stdout + res.stderr
    assert res.returncode != 0 and "Resource precondition failed" in out, out
    assert "bench_reader_certificate_file : un seul bloc CERTIFICATE" in out, out
    assert marker not in out and "BEGIN CERTIFICATE-----\\n" not in out and crt.splitlines()[1] not in out, out


def test_every_terraform_test_keeps_it_off_and_its_own_covers_it():
    tftest = (TF / "tests" / "bench_reader.tftest.hcl").read_text(encoding="utf-8")
    for run in ("off_nothing_in_the_tenant_nothing_on_the_workspace", "on_the_exact_role_on_the_workspace_alone",
                "on_a_private_key_beside_the_certificate_stops_the_plan", "on_no_certificate_file_stops_the_plan",
                "on_no_end_date_file_stops_the_plan", "on_an_end_date_beyond_ninety_one_days_stops_the_plan"):
        assert f'run "{run}"' in tftest, run
    for path in (TF / "tests").glob("*.tftest.hcl"):
        text = path.read_text(encoding="utf-8")
        head = text.split("\nrun ")[0]
        assert re.search(r"(?m)^  bench_reader_enabled\s+= false$", head), path.name   # hermetic from the tfvars
        assert 'mock_provider "azuread"' in text and 'mock_provider "azurerm"' in text, path.name


def test_no_new_provider():
    lock = (TF / ".terraform.lock.hcl").read_text(encoding="utf-8")
    providers = set(re.findall(r'provider "registry\.terraform\.io/([^"]+)"', lock))
    assert providers == {"hashicorp/azurerm", "azure/azapi", "hashicorp/azuread", "hashicorp/null"}, providers


# ── the Make targets, against a fake terraform ───────────────────────────────

needs_make = pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
TARGETS = ["-target=azuread_application.bench_reader", "-target=azuread_service_principal.bench_reader",
           "-target=azuread_application_certificate.bench_reader", "-target=azurerm_role_assignment.bench_reader"]


def _make(tmp_path, target, *args, tf_out=""):
    """make, a fake terraform and a fake python3 first on the PATH: the script itself is tested
    below, run where a lot's worktree would refuse it."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log, py_log = tmp_path / "tf.log", tmp_path / "py.log"
    log.write_text("")
    py_log.write_text("")
    tf = bin_dir / "terraform"
    tf.write_text('#!/bin/sh\necho "$*" >> "$FAKE_TF_LOG"\nprintf "%s" "$FAKE_TF_OUT"\n')
    tf.chmod(0o755)
    py = bin_dir / "python3"
    py.write_text('#!/bin/sh\nprintf "%s|%s|%s|" "$1" "$2" "$EREGION_BANC_DAYS" >> "$FAKE_PY_LOG"\n'
                  'cat >> "$FAKE_PY_LOG"\necho >> "$FAKE_PY_LOG"\n')
    py.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "FAKE_TF_LOG": str(log),
           "FAKE_PY_LOG": str(py_log), "FAKE_TF_OUT": tf_out, "HOME": str(home)}
    for var in ("INSTANCE", "YES", "TOPO", "DAYS", "EREGION_AGENT_SESSION", "EREGION_BANC_DAYS"):
        env.pop(var, None)
    res = subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), target, *args],
                         env=env, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    _make.python = py_log.read_text().splitlines()
    return res.returncode, res.stdout + res.stderr, [c.split() for c in log.read_text().splitlines()]


@needs_make
def test_reader_plan_plans_its_four_resources_alone(tmp_path):
    code, out, calls = _make(tmp_path, "celebrimbor-reader-plan")
    assert code == 0, out
    chdir = "-chdir=infra/terraform"
    assert calls == [[chdir, "init"], [chdir, "workspace", "select", "default"], [chdir, "plan", *TARGETS]]


@needs_make
@pytest.mark.parametrize("args,approve", [((), []), (("YES=1",), ["-auto-approve"])])
def test_reader_up_applies_it_alone_confirmed_unless_yes(tmp_path, args, approve):
    code, out, calls = _make(tmp_path, "celebrimbor-reader-up", *args)
    assert code == 0, out
    assert calls[-1] == ["-chdir=infra/terraform", "apply", *approve, *TARGETS]
    assert not any(a.startswith("-var") for c in calls for a in c)


@needs_make
@pytest.mark.parametrize("target", ["celebrimbor-reader-plan", "celebrimbor-reader-up", "celebrimbor-reader-profile"])
def test_another_instance_is_refused_before_any_call(tmp_path, target):
    code, out, calls = _make(tmp_path, target, "INSTANCE=ci-1234", "YES=1")
    assert code != 0 and "instance 'ci-1234' refusée" in out and calls == [] and _make.python == []


@needs_make
def test_reader_profile_pipes_the_outputs_to_the_script(tmp_path):
    raw = json.dumps(OUTPUT)
    code, out, calls = _make(tmp_path, "celebrimbor-reader-profile", tf_out=raw)
    assert code == 0, out
    assert calls == [["-chdir=infra/terraform", "workspace", "select", "default"],
                     ["-chdir=infra/terraform", "output", "-json", "bench_reader"]]
    assert _make.python == [f"scripts/bench_reader.py|profile||{raw}"]


@needs_make
@pytest.mark.parametrize("value", ["", "7", "91", "$(shell touch MARKER)"])
def test_reader_key_passes_days_unexpanded_by_the_environment(tmp_path, value):
    """DAYS reaches the script as written — never expanded by make —, which checks it (below)."""
    marker = tmp_path / "ran"
    value = value.replace("MARKER", str(marker))
    code, out, calls = _make(tmp_path, "celebrimbor-reader-key", *([f"DAYS={value}"] if value else []))
    assert code == 0, out
    assert _make.python == [f"scripts/bench_reader.py|keygen|{value}|"]
    assert not marker.exists() and calls == []


def test_reader_key_passes_days_by_the_environment():
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "unexport DAYS\ncelebrimbor-reader-key: export EREGION_BANC_DAYS = $(value DAYS)\n" in text
    recipe = text.split("\ncelebrimbor-reader-key:\n")[1].split("\n\n")[0]
    assert "$(DAYS)" not in recipe


# ── the guard ────────────────────────────────────────────────────────────────

def test_a_code_session_is_refused(tmp_path):
    assert "session de code" in br.code_session_refusal({"EREGION_AGENT_SESSION": "1"}, str(tmp_path))
    lot = tmp_path / "eregion" / ".claude" / "worktrees" / "agent-x" / "scripts"
    lot.mkdir(parents=True)
    assert "worktree d'un lot" in br.code_session_refusal({}, str(lot))
    assert br.code_session_refusal({}, str(tmp_path)) == ""
    # A lot is refused even when it sets the Banc session's variable.
    assert br.banc_session_refusal({"EREGION_AGENT_SESSION": "1", "EREGION_BANC_SESSION": "1"}, str(tmp_path))
    assert br.banc_session_refusal({"EREGION_BANC_SESSION": "1"}, str(lot))


def _banc_env(tmp_path, **extra):
    d = tmp_path / "banc"
    return {"EREGION_BANC_SESSION": "1", "EREGION_BANC_DIR": str(d), "AZURE_CONFIG_DIR": str(d / "az"), **extra}


def test_only_the_banc_session_uses_it(tmp_path):
    assert "EREGION_BANC_SESSION" in br.banc_session_refusal({}, str(tmp_path))
    assert br.banc_session_refusal(_banc_env(tmp_path, EREGION_BANC_SESSION="yes"), str(tmp_path))
    assert br.banc_session_refusal(_banc_env(tmp_path), str(tmp_path)) == ""
    # The same directory, spelled otherwise: still the reader's.
    same = _banc_env(tmp_path, AZURE_CONFIG_DIR=str(tmp_path / "banc" / "x" / ".." / "az"))
    assert br.banc_session_refusal(same, str(tmp_path)) == ""


@pytest.mark.parametrize("cfg", [None, "", "~/.azure", "OTHER"])
def test_the_banc_session_without_the_reader_s_az_config_dir_is_refused(tmp_path, cfg):
    """Without the reader's AZURE_CONFIG_DIR in its settings, a bare `az` in the Banc session reads the
    operator's ~/.azure, his own sign-in: refused, said."""
    env = _banc_env(tmp_path)
    if cfg is None:
        del env["AZURE_CONFIG_DIR"]
    else:
        env["AZURE_CONFIG_DIR"] = str(tmp_path / "other") if cfg == "OTHER" else cfg
    said = br.banc_session_refusal(env, str(tmp_path))
    assert "AZURE_CONFIG_DIR" in said and str(tmp_path / "banc" / "az") in said


@pytest.mark.parametrize("raw,days", [(None, 30), ("", 30), ("1", 1), ("90", 90)])
def test_days_short_by_default_ninety_at_most(raw, days):
    assert br.parse_days(raw) == days


@pytest.mark.parametrize("raw", ["91", "0", "365", "-1", "30;", "1e2", " 30"])
def test_days_beyond_ninety_or_not_a_number_refused(raw):
    with pytest.raises(br.ReaderError):
        br.parse_days(raw)


# ── the script, as Jonathan and the Banc session run it ───────────────────────

FAKE_AZ = """#!{python}
import json, os, sys
with open(os.environ["FAKE_AZ_LOG"], "a") as f:
    f.write(json.dumps({{"args": sys.argv[1:], "config": os.environ.get("AZURE_CONFIG_DIR"),
                        "leaked": sorted(k for k in os.environ if k.startswith(("ARM_", "AZURE_"))
                                         and k not in ("AZURE_CONFIG_DIR", "AZURE_CORE_COLLECT_TELEMETRY"))}}) + "\\n")
if sys.argv[1:3] == ["tag", "update"] and "merge" in sys.argv:
    if os.environ.get("FAKE_AZ_WRITE") == "passes":
        sys.exit(0)
    sys.stderr.write("(AuthorizationFailed) The client does not have authorization to perform action\\n")
    sys.exit(1)
print(json.dumps([{{"ok": 1}}]))
"""


@pytest.fixture
def banc(tmp_path, monkeypatch):
    """A reader's directory with its profile and a key file, the Banc session's environment, a fake az."""
    d = tmp_path / "banc"
    d.mkdir(mode=0o700)
    (d / "profile.env").write_text(br.profile_from_output(json.dumps(OUTPUT)))
    (d / "profile.env").chmod(0o600)
    (d / "reader.pem").write_text("not a key: the fake az never reads it\n")
    (d / "reader.pem").chmod(0o600)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    az = bin_dir / "az"
    az.write_text(FAKE_AZ.format(python=sys.executable))
    az.chmod(0o755)
    log = tmp_path / "az.log"
    log.write_text("")
    home = tmp_path / "home"
    home.mkdir()
    work = tmp_path / "eregion-banc"
    work.mkdir()
    env = {k: v for k, v in os.environ.items() if k not in ("EREGION_AGENT_SESSION", "EREGION_BANC_DAYS")}
    env.update({"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(home), "EREGION_BANC_DIR": str(d),
                "EREGION_BANC_SESSION": "1", "AZURE_CONFIG_DIR": str(d / "az"), "FAKE_AZ_LOG": str(log),
                "AZURE_CLIENT_SECRET": "the-operator-s", "ARM_SUBSCRIPTION_ID": "00000000-0000-0000-0000-000000000000"})

    def run(*args, extra=None, cwd=work, stdin=""):
        res = subprocess.run([sys.executable, str(SCRIPT), *args], env={**env, **(extra or {})}, cwd=cwd,
                             capture_output=True, text=True, timeout=60, input=stdin)
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        return res.returncode, res.stdout + res.stderr, calls

    run.dir = d
    return run


def test_login_as_the_reader_in_its_own_config_dir(banc):
    code, out, calls = banc("login")
    assert code == 0, out
    assert calls == [{"args": ["login", "--service-principal", "--username", CLIENT, "--tenant", TENANT,
                               "--certificate", str(banc.dir / "reader.pem"), "--allow-no-subscriptions",
                               "--output", "none"],
                      "config": str(banc.dir / "az"), "leaked": []}]
    assert stat.S_IMODE((banc.dir / "az").stat().st_mode) == 0o700


def test_query_reads_the_profile_s_workspace_alone(banc):
    code, out, calls = banc("query", "Syslog | take 1", "--timespan", "P1D")
    assert code == 0, out
    assert json.loads(out) == [{"ok": 1}]
    assert calls[0]["args"] == ["monitor", "log-analytics", "query", "--workspace", WORKSPACE,
                                "--analytics-query", "Syslog | take 1", "--output", "json", "--timespan", "P1D"]
    assert calls[0]["config"] == str(banc.dir / "az") and calls[0]["leaked"] == []


@pytest.mark.parametrize("extra,cwd_lot,said", [
    ({"EREGION_AGENT_SESSION": "1"}, False, "session de code"),
    ({"EREGION_BANC_SESSION": ""}, False, "EREGION_BANC_SESSION"),
    ({}, True, "worktree d'un lot"),
    ({"AZURE_CONFIG_DIR": ""}, False, "AZURE_CONFIG_DIR"),
])
@pytest.mark.parametrize("cmd", [("login",), ("query", "Syslog"), ("verify",), ("logout",)])
def test_a_code_session_is_refused_before_any_call(banc, tmp_path, extra, cwd_lot, said, cmd):
    cwd = tmp_path / "eregion" / ".claude" / "worktrees" / "agent-x"
    cwd.mkdir(parents=True, exist_ok=True)
    code, out, calls = banc(*cmd, extra=extra, cwd=cwd if cwd_lot else tmp_path / "eregion-banc")
    assert code == 1 and said in out and calls == []


def test_profile_writes_identifiers_alone_private(banc):
    d = banc.dir / "new"
    code, out, calls = banc("profile", extra={"EREGION_BANC_DIR": str(d)}, stdin=json.dumps(OUTPUT))
    assert code == 0, out
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert stat.S_IMODE((d / "profile.env").stat().st_mode) == 0o600
    assert br.parse_profile((d / "profile.env").read_text()) == {
        "EREGION_BANC_TENANT_ID": TENANT, "EREGION_BANC_CLIENT_ID": CLIENT, "EREGION_BANC_WORKSPACE_ID": WORKSPACE,
        "EREGION_BANC_WORKSPACE_RESOURCE_ID": WS_ID}
    assert calls == []
    code, out, _ = banc("profile", extra={"EREGION_BANC_DIR": str(d / "off")}, stdin="null")
    assert code == 1 and "bench_reader est null" in out and not (d / "off").exists()


@pytest.mark.parametrize("days", ["91", "0", "abc", "30;rm"])
def test_keygen_refuses_days_beyond_ninety_before_openssl(banc, days):
    d = banc.dir / "new"
    code, out, _ = banc("keygen", extra={"EREGION_BANC_DIR": str(d), "EREGION_BANC_DAYS": days})
    assert code == 1 and "DAYS" in out and not d.exists()


def test_keygen_and_profile_refused_in_a_code_session(banc):
    for cmd in ("keygen", "profile"):
        code, out, _ = banc(cmd, extra={"EREGION_AGENT_SESSION": "1"})
        assert code == 1 and "session de code" in out, cmd


@pytest.mark.parametrize("victim,mode", [("", 0o750), ("profile.env", 0o640), ("reader.pem", 0o644)])
def test_a_file_others_can_read_is_refused(banc, victim, mode):
    (banc.dir / victim).chmod(mode)
    code, out, calls = banc("query", "Syslog")
    assert code == 1 and "lisible par d'autres" in out and calls == []


def test_verify_one_read_one_write_refused(banc):
    code, out, calls = banc("verify")
    assert code == 0, out
    assert "lecture : passée" in out and "écriture : refusée" in out
    assert calls[1]["args"][:2] == ["tag", "update"] and WS_ID in calls[1]["args"]


def test_verify_says_a_write_that_passes_and_takes_it_back(banc):
    code, out, calls = banc("verify", extra={"FAKE_AZ_WRITE": "passes"})
    assert code == 1 and "ÉCRITURE PASSÉE" in out
    assert calls[-1]["args"][:5] == ["tag", "update", "--resource-id", WS_ID, "--operation"]
    assert calls[-1]["args"][5] == "delete"


@pytest.mark.parametrize("raw,said", [
    ("null", "bench_reader est null"),
    (json.dumps({**OUTPUT, "role": "Log Analytics Contributor"}), "rôle"),
    (json.dumps({**OUTPUT, "client_id": "not-a-guid"}), "GUID"),
    (json.dumps({**OUTPUT, "workspace_resource_id": "/subscriptions/x"}), "workspace"),
    ("{", "JSON"),
])
def test_a_bad_output_writes_no_profile(raw, said):
    with pytest.raises(br.ReaderError, match=said):
        br.profile_from_output(raw)


def test_a_profile_with_another_line_is_refused():
    text = br.profile_from_output(json.dumps(OUTPUT))
    with pytest.raises(br.ReaderError):
        br.parse_profile(text + "AZURE_CLIENT_SECRET=x\n")
    with pytest.raises(br.ReaderError):
        br.parse_profile(text.replace(f"EREGION_BANC_TENANT_ID={TENANT}\n", ""))


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_keygen_a_short_pair_the_key_private_the_certificate_alone_for_terraform(banc):
    d = banc.dir / "new"
    code, out, _ = banc("keygen", extra={"EREGION_BANC_DIR": str(d), "EREGION_BANC_DAYS": "2"})
    assert code == 0, out
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    for name in ("reader.pem", "reader.crt"):
        assert stat.S_IMODE((d / name).stat().st_mode) == 0o600, name
    pem, crt = (d / "reader.pem").read_text(), (d / "reader.crt").read_text()
    assert "PRIVATE KEY" in pem and pem.endswith(crt)
    assert "PRIVATE" not in crt and crt.count("BEGIN CERTIFICATE") == 1
    end = subprocess.run(["openssl", "x509", "-noout", "-checkend", str(3 * 86400), "-in", str(d / "reader.crt")],
                         capture_output=True, text=True)
    assert end.returncode == 1           # expires within three days: two asked
    assert [p.name for p in d.iterdir() if p.name.startswith(".")] == []
    # The end Terraform poses on the identifier: the certificate's own, in RFC 3339.
    assert stat.S_IMODE((d / "reader.end").stat().st_mode) == 0o600
    enddate = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-in", str(d / "reader.crt")],
                             capture_output=True, text=True).stdout
    assert (d / "reader.end").read_text() == br.end_date(enddate) + "\n"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\n", (d / "reader.end").read_text())
    assert "reader.end" in out


@pytest.mark.parametrize("raw,rfc", [
    ("notAfter=Dec  6 12:00:00 2026 GMT\n", "2026-12-06T12:00:00Z"),
    ("notAfter=Feb 28 23:59:59 2027 GMT", "2027-02-28T23:59:59Z"),
])
def test_the_certificate_s_end_in_rfc_3339(raw, rfc):
    assert br.end_date(raw) == rfc


@pytest.mark.parametrize("raw", ["", "notAfter=Dec  6 12:00:00 2026", "notAfter=6/12/2026 GMT", "garbage GMT"])
def test_an_unreadable_end_is_refused(raw):
    with pytest.raises(br.ReaderError, match="illisible"):
        br.end_date(raw)
