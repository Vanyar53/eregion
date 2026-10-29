"""CI2 (#268): the advisories of the locked dependencies, one issue per advisory.

scripts/pip_audit_issues.py runs as the workflow runs it (.github/workflows/pip-audit.yml), against
a fake `pip-audit` (it reads the test's lock and answers from the test's advisories, in pip-audit's
JSON) and a fake `gh` (the repository's issues in a JSON file, every call recorded). No network,
nothing written in the repository: the locks are the test's, in tmp_path — `requests==2.19.1`, whose
advisory (CVE-2018-18074) is a real one, never in the real locks.
"""
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "pip_audit_issues.py"
WORKFLOW = ROOT / ".github" / "workflows" / "pip-audit.yml"
LOCKS = ("requirements/dev.txt", "requirements/glorfindel.txt", "requirements/annatar.txt",
         "requirements/audit.txt")   # pip-audit's own too: it runs in a job that writes issues

# requests 2.19.1: CVE-2018-18074, its credentials sent on a redirect to HTTP — fixed in 2.20.0.
REQUESTS = {"id": "PYSEC-2018-28", "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
            "fix_versions": ["2.20.0"], "description": "@everyone [click](https://example.invalid)"}
LOCK = """\
# a test lock, never the repository's
idna==2.7 \\
    --hash=sha256:{h}
requests==2.19.1 \\
    --hash=sha256:{h}
urllib3==1.23 ; python_version >= '3.8' \\
    --hash=sha256:{h}
""".format(h="0" * 64)

FAKE_GH = """\
import json, os, sys
path = os.environ["FAKE_GH_STATE"]
st = json.load(open(path))
args = sys.argv[1:]
st["calls"].append(args)
def save():
    json.dump(st, open(path, "w"))
def opt(name):
    return args[args.index(name) + 1]
def issue(n):
    return next(i for i in st["issues"] if i["number"] == int(n))
fail = json.loads(os.environ.get("FAKE_GH_FAIL") or "[]")
if fail and args[:len(fail)] == fail:
    save()
    print("HTTP 502: Bad Gateway", file=sys.stderr)
    sys.exit(1)
if args[0] == "api":
    if "--paginate" not in args:              # the issues API answers 100 a page: the rest unseen
        save()
        print("fake gh: the issues API read without --paginate", file=sys.stderr)
        sys.exit(3)
    state = "all" if "state=all" in args[2] else "open"
    for it in st["issues"] + st.get("pulls", []):
        if state == "all" or it["state"] == "open":   # the REST shape, as the --jq projects it
            print(json.dumps({**{k: it.get(k) for k in ("number", "title", "body", "state", "state_reason",
                                                        "pull_request")},
                              "user": {"login": it.get("user", "github-actions[bot]")}}, indent=1))
elif args[:2] == ["issue", "create"]:
    n = max([i["number"] for i in st["issues"] + st.get("pulls", [])], default=300) + 1
    st["issues"].append({"number": n, "title": opt("--title"), "body": sys.stdin.read(), "state": "open",
                         "state_reason": None, "labels": [opt("--label")], "comments": [],
                         "user": "github-actions[bot]"})
    print(f"https://github.com/owner/repo/issues/{n}")
elif args[:2] == ["issue", "edit"]:
    issue(args[2])["body"] = sys.stdin.read()
elif args[:2] == ["issue", "comment"]:
    issue(args[2])["comments"].append(sys.stdin.read())
elif args[:2] == ["issue", "reopen"]:
    issue(args[2]).update(state="open", state_reason="reopened")
elif args[:2] == ["issue", "close"]:
    issue(args[2]).update(state="closed", state_reason="completed")
else:
    print("unknown command", file=sys.stderr)
    save()
    sys.exit(2)
save()
"""

FAKE_PIP_AUDIT = """\
import json, os, re, sys
args = sys.argv[1:]
with open(os.environ["FAKE_PIP_AUDIT_LOG"], "a") as f:
    f.write(json.dumps(args) + "\\n")
lock = args[args.index("-r") + 1]
if os.path.basename(lock) in os.environ.get("FAKE_PIP_AUDIT_FAIL", "").split(","):
    print("ConnectionError: pypi.org unreachable", file=sys.stderr)
    sys.exit(1)
db = json.load(open(os.environ["FAKE_ADVISORIES"]))
deps = []
for line in open(lock):
    m = re.match(r"^([A-Za-z0-9._-]+)==([^\\s;\\\\]+)", line)
    if m:
        deps.append({"name": m.group(1), "version": m.group(2), "vulns": db.get(m.group(1), {}).get(m.group(2), [])})
print(json.dumps({"dependencies": deps, "fixes": []}))
sys.exit(1 if any(d["vulns"] for d in deps) else 0)
"""


class World:
    """The test's locks, advisories and repository issues, and a way to run the script on them."""

    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        for name, code in (("gh", FAKE_GH), ("pip-audit", FAKE_PIP_AUDIT)):
            exe = self.bin / name
            exe.write_text(f"#!{sys.executable}\n{code}", encoding="utf-8")
            exe.chmod(0o755)
        self.state = tmp_path / "gh.json"
        self.state.write_text(json.dumps({"issues": [], "calls": []}))
        self.advisories = tmp_path / "advisories.json"
        self.advisories.write_text("{}")
        self.audit_log = tmp_path / "pip-audit.log"
        self.audit_log.write_text("")
        (tmp_path / "requirements").mkdir()
        self.fail = ""
        self.gh_fail: list[str] = []

    def lock(self, name: str, text: str = LOCK) -> str:
        (self.tmp / "requirements" / name).write_text(text, encoding="utf-8")
        return f"requirements/{name}"

    def advise(self, db: dict):
        self.advisories.write_text(json.dumps(db))

    def issues(self) -> list[dict]:
        return json.loads(self.state.read_text())["issues"]

    def calls(self) -> list[list[str]]:
        return json.loads(self.state.read_text())["calls"]

    def seed(self, *issues: dict, pulls=()):
        st = json.loads(self.state.read_text())
        st["issues"] += [{"labels": ["security"], "comments": [], "state_reason": None, "state": "open",
                          "user": "github-actions[bot]", **i} for i in issues]
        st["pulls"] = st.get("pulls", []) + [{"state": "open", "state_reason": None, **p,
                                              "pull_request": {"url": "https://example.invalid/pr"}}
                                             for p in pulls]
        self.state.write_text(json.dumps(st))

    def forget_calls(self):
        st = json.loads(self.state.read_text())
        st["calls"] = []
        self.state.write_text(json.dumps(st))

    def run(self, mode: str, *locks: str) -> subprocess.CompletedProcess:
        env = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
               "FAKE_GH_STATE": str(self.state), "FAKE_ADVISORIES": str(self.advisories),
               "FAKE_PIP_AUDIT_LOG": str(self.audit_log), "FAKE_PIP_AUDIT_FAIL": self.fail,
               "FAKE_GH_FAIL": json.dumps(self.gh_fail),
               "GH_TOKEN": "test", "GH_REPO": "owner/repo"}
        env.pop("GITHUB_STEP_SUMMARY", None)
        env.pop("EREGION_GH", None)
        return subprocess.run([sys.executable, str(SCRIPT), mode, "--pip-audit", str(self.bin / "pip-audit"),
                               *locks], cwd=self.tmp, env=env, capture_output=True, text=True, timeout=120)


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def _key(body: str) -> dict:
    return json.loads(re.search(r"<!-- eregion-pip-audit: (\{.*?\}) -->", body).group(1))


def _made(calls, *verb):
    return [c for c in calls if tuple(c[:len(verb)]) == verb]


# ── one issue per advisory ─────────────────────────────────────────────────────────────

def test_a_known_advisory_opens_one_issue_then_none(world):
    dev = world.lock("dev.txt")
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    first = world.run("issues", dev)
    assert first.returncode == 1, first.stderr        # a new issue: the run is red, #ci says it
    (issue,) = world.issues()
    assert issue["title"] == "pip-audit · requests · GHSA-x84v-xcm2-53pg"
    assert issue["labels"] == ["security"]
    body = issue["body"]
    for said in ("**requests**", "| `requirements/dev.txt` | 2.19.1 |", "**Version corrigée** : 2.20.0.",
                 "GHSA-x84v-xcm2-53pg", "CVE-2018-18074", "PYSEC-2018-28", "make lock", "ATTEST=1",
                 "Pas de PR de montée automatique"):
        assert said in body, said
    assert _key(body) == {"package": "requests", "ids": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"],
                          "locks": ["requirements/dev.txt"], "present": True}

    world.forget_calls()
    second = world.run("issues", dev)
    assert second.returncode == 0, second.stderr
    assert len(world.issues()) == 1
    assert [c for c in world.calls() if c[0] != "api"] == []   # nothing created, edited, said


def test_pip_audit_reads_the_lock_as_it_is(world):
    """Nothing resolved outside the lock: the hashes required, pip not used to resolve."""
    dev = world.lock("dev.txt")
    world.run("report", dev)
    (args,) = [json.loads(line) for line in world.audit_log.read_text().splitlines()]
    assert args[args.index("-r") + 1] == dev
    assert "--require-hashes" in args and "--disable-pip" in args
    assert args[args.index("--format") + 1] == "json"


def test_the_same_advisory_in_three_locks_is_one_issue(world):
    locks = [world.lock(n) for n in ("dev.txt", "glorfindel.txt", "annatar.txt")]
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.run("issues", *locks)
    (issue,) = world.issues()
    assert _key(issue["body"])["locks"] == sorted(locks)
    for lock in locks:
        assert f"| `{lock}` | 2.19.1 |" in issue["body"]


def test_an_advisory_listed_twice_in_a_report_is_one(world):
    """pip-audit lists some advisories twice for one package (chromadb, 29/10): one issue."""
    dev = world.lock("dev.txt")
    twice = dict(REQUESTS, aliases=list(reversed(REQUESTS["aliases"])))
    world.advise({"requests": {"2.19.1": [REQUESTS, twice]}})
    world.run("issues", dev)
    assert len(world.issues()) == 1


def test_two_advisories_of_one_package_are_two_issues(world):
    dev = world.lock("dev.txt")
    other = {"id": "GHSA-9wx4-h78v-vm56", "aliases": ["CVE-2024-35195"], "fix_versions": ["2.32.0"]}
    world.advise({"requests": {"2.19.1": [REQUESTS, other]}})
    world.run("issues", dev)
    assert sorted(i["title"] for i in world.issues()) == [
        "pip-audit · requests · GHSA-9wx4-h78v-vm56", "pip-audit · requests · GHSA-x84v-xcm2-53pg"]


def test_an_alias_seen_later_finds_its_issue(world):
    """The service first gave the GHSA alone; now its PYSEC id with the GHSA as an alias: the same
    advisory, the same issue — its key grows."""
    dev = world.lock("dev.txt")
    world.advise({"requests": {"2.19.1": [{"id": "GHSA-x84v-xcm2-53pg", "aliases": [], "fix_versions": ["2.20.0"]}]}})
    world.run("issues", dev)
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.run("issues", dev)
    (issue,) = world.issues()
    assert _key(issue["body"])["ids"] == ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"]
    world.advise({"requests": {"2.19.1": [{"id": "CVE-2018-18074", "aliases": [], "fix_versions": ["2.20.0"]}]}})
    world.run("issues", dev)
    assert len(world.issues()) == 1
    assert _key(world.issues()[0]["body"])["ids"] == ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"]


def test_a_label_removed_or_a_title_changed_still_finds_the_issue(world):
    """The key is in the body: a human may retitle or relabel the issue."""
    dev = world.lock("dev.txt")
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.run("issues", dev)
    st = json.loads(world.state.read_text())
    st["issues"][0].update(title="requests: monter en 2.20", labels=[])
    world.state.write_text(json.dumps(st))
    world.run("issues", dev)
    assert len(world.issues()) == 1


def test_a_closed_issue_is_never_doubled(world):
    """Closed as done while the advisory is still there: reopened, said; closed as not planned:
    a human's decision, left alone. Never a second issue."""
    dev = world.lock("dev.txt")
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.run("issues", dev)
    st = json.loads(world.state.read_text())
    st["issues"][0].update(state="closed", state_reason="completed")
    world.state.write_text(json.dumps(st))
    res = world.run("issues", dev)
    assert res.returncode == 1
    (issue,) = world.issues()
    assert issue["state"] == "open"
    assert any("toujours là" in c for c in issue["comments"])

    for reason in ("not_planned", "duplicate"):
        st = json.loads(world.state.read_text())
        st["issues"][0].update(state="closed", state_reason=reason)
        world.state.write_text(json.dumps(st))
        world.forget_calls()
        res = world.run("issues", dev)
        assert res.returncode == 0, reason
        (issue,) = world.issues()
        assert issue["state"] == "closed", reason
        assert [c for c in world.calls() if c[0] != "api"] == [], reason


# ── who may hold a key ─────────────────────────────────────────────────────────────────

def _marker(key: dict) -> str:
    """A key as an outsider would write it: JSON may say `<` and `>` as \\u003c and \\u003e."""
    text = json.dumps(key, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e")
    return f"Une issue.\n\n<!-- eregion-pip-audit: {text} -->\n"


FORGED = {"package": "requests", "ids": ["CVE-2018-18074"], "locks": []}


@pytest.mark.parametrize("state, reason", [("open", None), ("closed", "not_planned"), ("closed", "duplicate")])
def test_an_outsiders_issue_carrying_the_key_changes_nothing(world, state, reason):
    """Anyone may open an issue whose body carries a key: it never silences the advisory, never
    gives its identifiers to the bot's issue, and is never edited nor commented."""
    dev = world.lock("dev.txt")
    forged = dict(FORGED, ids=["CVE-2018-18074", "GHSA-evil-link"], locks=["requirements/dev.txt"])
    world.seed({"number": 7, "title": "requests", "body": _marker(forged), "state": state,
                "state_reason": reason, "user": "someone", "labels": []})
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    res = world.run("issues", dev)
    assert res.returncode == 1, res.stderr
    (mine,) = [i for i in world.issues() if i["number"] != 7]
    assert "GHSA-evil-link" not in mine["body"] + mine["title"]
    assert [c for c in world.calls() if "7" in c[2:3]] == []
    (seven,) = [i for i in world.issues() if i["number"] == 7]
    assert seven["body"] == _marker(forged) and seven["comments"] == [] and seven["state"] == state

    world.advise({})                                   # gone: the outsider's issue is not told either
    world.run("issues", dev)
    assert [i for i in world.issues() if i["number"] == 7][0]["comments"] == []


@pytest.mark.parametrize("field, value", [
    ("ids", ["CVE-2018-18074", "--><img src=https://example.invalid/x.png>"]),
    ("ids", ["CVE-2018-18074", "[x](https://example.invalid)"]),
    ("ids", ["CVE-2018-18074", "@everyone"]),
    ("ids", []),
    ("package", "requests --> @everyone"),
    ("locks", ["requirements/dev.txt` @everyone `"]),
    ("present", "no"),
])
def test_a_bots_key_of_the_wrong_shape_is_ignored(world, field, value):
    """A key read back is checked field by field, as when it was written: one of the wrong shape is
    no key — its text never reaches a body, a title or a comment."""
    dev = world.lock("dev.txt")
    bad = {**FORGED, "locks": ["requirements/dev.txt"], field: value}
    world.seed({"number": 7, "title": "pip-audit · requests · GHSA-x84v-xcm2-53pg", "body": _marker(bad)})
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.run("issues", dev)
    (mine,) = [i for i in world.issues() if i["number"] != 7]
    written = mine["body"] + mine["title"] + "".join(mine["comments"])
    for word in ("<img", "example.invalid", "@everyone"):
        assert word not in written
    assert [c for c in world.calls() if "7" in c[2:3]] == []


def test_a_pull_request_carrying_the_key_is_never_read(world):
    """The issues API lists pull requests too: one whose body carries the key is not an issue."""
    dev = world.lock("dev.txt")
    world.seed(pulls=[{"number": 9, "title": "PR", "body": _marker(dict(FORGED, locks=["requirements/dev.txt"]))}])
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.run("issues", dev)
    assert len(world.issues()) == 1
    assert [c for c in world.calls() if "9" in c[2:3]] == []


def test_every_page_of_issues_is_read(world):
    dev = world.lock("dev.txt")
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.run("issues", dev)
    (api,) = _made(world.calls(), "api")
    assert "--paginate" in api and "state=all" in api[api.index("--paginate") + 1]


# ── a GitHub error ─────────────────────────────────────────────────────────────────────

def test_a_github_error_on_one_advisory_leaves_the_others_done(world):
    dev = world.lock("dev.txt")
    other = {"id": "GHSA-aaaa-bbbb-cccc", "aliases": [], "fix_versions": ["3.0"]}
    world.advise({"requests": {"2.19.1": [REQUESTS]}, "idna": {"2.7": [other]}})
    world.gh_fail = ["issue", "create", "--title", "pip-audit · idna · GHSA-aaaa-bbbb-cccc"]
    res = world.run("issues", dev)
    assert res.returncode == 2
    assert "idna · GHSA-aaaa-bbbb-cccc" in res.stderr and "HTTP 502" in res.stderr
    assert [i["title"] for i in world.issues()] == ["pip-audit · requests · GHSA-x84v-xcm2-53pg"]


def test_a_github_error_on_one_gone_issue_leaves_the_others_said(world):
    dev = world.lock("dev.txt")
    other = {"id": "GHSA-aaaa-bbbb-cccc", "aliases": [], "fix_versions": ["3.0"]}
    world.advise({"requests": {"2.19.1": [REQUESTS]}, "idna": {"2.7": [other]}})
    world.run("issues", dev)
    first, second = sorted(i["number"] for i in world.issues())
    world.advise({})
    world.gh_fail = ["issue", "comment", str(first)]
    res = world.run("issues", dev)
    assert res.returncode == 2
    assert f"#{first}" in res.stderr
    said = {i["number"]: i["comments"] for i in world.issues()}
    assert said[first] == [] and len(said[second]) == 1


def test_a_new_lock_touched_updates_the_issue(world):
    dev, image = world.lock("dev.txt"), world.lock("glorfindel.txt")
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.run("issues", dev)
    world.lock("glorfindel.txt")
    res = world.run("issues", dev, image)
    assert res.returncode == 0                      # said in the issue; nothing new to ping for
    (issue,) = world.issues()
    assert _key(issue["body"])["locks"] == [dev, image]
    assert f"| `{image}` | 2.19.1 |" in issue["body"]


def test_a_new_fixed_version_updates_the_issue(world):
    dev = world.lock("dev.txt")
    world.advise({"requests": {"2.19.1": [dict(REQUESTS, fix_versions=[])]}})
    world.run("issues", dev)
    assert "**Version corrigée** : aucune encore." in world.issues()[0]["body"]
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.run("issues", dev)
    assert "**Version corrigée** : 2.20.0." in world.issues()[0]["body"]


# ── an advisory gone ───────────────────────────────────────────────────────────────────

def test_an_advisory_gone_is_said_once_never_closed(world):
    dev = world.lock("dev.txt")
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.run("issues", dev)
    world.lock("dev.txt", LOCK.replace("requests==2.19.1", "requests==2.20.0"))   # the bump, made
    res = world.run("issues", dev)
    assert res.returncode == 0
    (issue,) = world.issues()
    assert issue["state"] == "open"
    assert not _made(world.calls(), "issue", "close")
    (said,) = issue["comments"]
    assert "n'est plus trouvé" in said and "requirements/dev.txt" in said and "humain" in said
    assert _key(issue["body"])["present"] is False

    world.run("issues", dev)
    world.run("issues", dev)
    assert len(world.issues()[0]["comments"]) == 1   # said once, not every week


def test_an_advisory_back_is_said(world):
    dev = world.lock("dev.txt")
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.run("issues", dev)
    world.advise({})
    world.run("issues", dev)
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    res = world.run("issues", dev)
    assert res.returncode == 1
    (issue,) = world.issues()
    assert "de nouveau trouvé" in issue["comments"][-1]
    assert _key(issue["body"])["present"] is True


def test_a_lock_whose_audit_failed_says_nothing_gone(world):
    """An audit that failed knows nothing: its advisories are not « gone », and the run is red."""
    dev, inj = world.lock("dev.txt"), world.lock("annatar.txt")
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.run("issues", dev)                        # the issue names dev.txt only
    world.fail = "dev.txt"
    res = world.run("issues", dev, inj)
    assert res.returncode == 1
    assert "échec" in res.stderr and "ConnectionError" in res.stderr
    (issue,) = world.issues()
    assert _key(issue["body"])["present"] is True
    # its advisory is found in the lock that answered: the issue is updated, nothing said gone
    assert issue["comments"] == []


def test_a_lock_whose_audit_failed_alone_says_nothing_gone(world):
    dev = world.lock("dev.txt")
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.run("issues", dev)
    world.fail = "dev.txt"
    res = world.run("issues", dev)
    assert res.returncode == 1
    assert world.issues()[0]["comments"] == []
    assert _key(world.issues()[0]["body"])["present"] is True


def test_another_lock_than_the_issues_says_nothing_gone(world):
    """A run on other locks than the issue's (by hand) knows nothing of its own."""
    dev, inj = world.lock("dev.txt"), world.lock("annatar.txt", "idna==2.7 \\\n    --hash=sha256:" + "0" * 64 + "\n")
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.run("issues", dev)
    world.run("issues", inj)
    assert world.issues()[0]["comments"] == []


# ── what reaches an issue ──────────────────────────────────────────────────────────────

def test_text_from_outside_is_checked_before_an_issue(world):
    """An identifier, a version, a package name of the wrong shape never reach the issue; the
    advisory's description is never written (a mention, a link)."""
    dev = world.lock("dev.txt", LOCK + "evil-pkg==1.0 \\\n    --hash=sha256:" + "0" * 64 + "\n")
    bad = {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-1 --> @everyone", "<b>x</b>", "GHSA-x"],
           "fix_versions": ["2.0 @here", "2.1"], "description": "@everyone"}
    world.advise({"requests": {"2.19.1": [REQUESTS]}, "evil-pkg": {"1.0": [bad]}})
    world.run("issues", dev)
    bodies = "\n".join(i["body"] + i["title"] for i in world.issues())
    assert "@everyone" not in bodies and "@here" not in bodies and "<b>" not in bodies
    assert "example.invalid" not in bodies
    (evil,) = [i for i in world.issues() if "evil-pkg" in i["title"]]
    assert _key(evil["body"])["ids"] == ["GHSA-aaaa-bbbb-cccc", "GHSA-x"]
    assert "**Version corrigée** : 2.1." in evil["body"]


def test_an_advisory_without_a_readable_identifier_opens_nothing(world):
    dev = world.lock("dev.txt")
    world.advise({"requests": {"2.19.1": [{"id": "<script>", "aliases": [], "fix_versions": []}]}})
    res = world.run("issues", dev)
    assert world.issues() == []
    assert "without a readable identifier" in res.stderr


def test_a_github_error_makes_the_run_red(world):
    dev = world.lock("dev.txt")
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    (world.bin / "gh").write_text("#!/bin/sh\necho 'HTTP 403: Resource not accessible' >&2\nexit 1\n")
    res = world.run("issues", dev)
    assert res.returncode == 2
    assert "HTTP 403" in res.stderr


def test_report_says_the_advisories_never_fails_and_never_calls_github(world):
    dev, inj = world.lock("dev.txt"), world.lock("annatar.txt")
    world.advise({"requests": {"2.19.1": [REQUESTS]}})
    world.fail = "annatar.txt"
    res = world.run("report", dev, inj)
    assert res.returncode == 0
    assert "requests · GHSA-x84v-xcm2-53pg (CVE-2018-18074, PYSEC-2018-28)" in res.stdout
    assert "requirements/dev.txt 2.19.1" in res.stdout and "corrigée : 2.20.0" in res.stdout
    assert "pip-audit requirements/annatar.txt : échec" in res.stderr
    assert world.calls() == []


def test_a_lock_path_of_another_shape_is_refused(world):
    res = world.run("report", "requirements/dev.txt;rm -rf /")
    assert res.returncode == 2
    assert world.audit_log.read_text() == ""


# ── the workflow, the lock of pip-audit, make lock ─────────────────────────────────────

def _workflow() -> dict:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    doc["on"] = doc.get("on", doc.pop(True, None))
    return doc


def test_the_workflow_is_weekly_and_by_hand_with_minimal_rights():
    doc = _workflow()
    assert set(doc["on"]) == {"schedule", "workflow_dispatch"}
    assert doc["permissions"] == {"contents": "read", "issues": "write"}
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "secrets." not in text
    (job,) = doc["jobs"].values()
    assert "permissions" not in job
    assert job["runs-on"] == "ubuntu-24.04"         # the markers follow the runner's Python: no drift
    runs = "\n".join(s.get("run") or "" for s in job["steps"])
    assert '/pip" install --require-hashes -r requirements/audit.txt' in runs
    assert "scripts/pip_audit_issues.py issues" in runs
    for lock in LOCKS:
        assert lock in runs
    (audit_step,) = [s for s in job["steps"] if "pip_audit_issues.py" in (s.get("run") or "")]
    assert set(audit_step["env"]) == {"GH_TOKEN", "GH_REPO"}
    assert audit_step["env"]["GH_TOKEN"] == "${{ github.token }}"
    checkout = [s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert checkout and checkout[0]["with"]["persist-credentials"] is False


def test_a_red_audit_is_announced_in_ci():
    """An issue the workflow's token opens triggers no workflow: the red run is what #ci sees."""
    notify = yaml.safe_load((ROOT / ".github" / "workflows" / "notify.yml").read_text(encoding="utf-8"))
    on = notify.get("on", notify.get(True))
    assert _workflow()["name"] in on["workflow_run"]["workflows"]


def test_pip_audit_has_a_lock_of_its_own_with_hashes():
    pinned = (ROOT / "requirements" / "audit.in").read_text(encoding="utf-8")
    (want,) = re.findall(r"^pip-audit==(\S+)$", pinned, re.M)
    lock = (ROOT / "requirements" / "audit.txt").read_text(encoding="utf-8")
    assert re.search(rf"^pip-audit=={re.escape(want)} \\$", lock, re.M)
    blocks = re.split(r"\n(?=[a-z0-9])", lock.split("\n", 2)[2])
    pins = [b for b in blocks if re.match(r"^[a-z0-9][a-z0-9._-]*==", b)]
    assert len(pins) > 10
    for b in pins:
        assert "--hash=sha256:" in b, b.splitlines()[0]
    # never in the images' locks, nor in dev.txt
    for name in ("dev.txt", "glorfindel.txt", "annatar.txt"):
        assert not re.search(r"^pip-audit==", (ROOT / "requirements" / name).read_text(encoding="utf-8"), re.M)


needs_make = pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")


def _make_lock(tmp_path, world, extra=(), venv_fails=False):
    """make lock with a fake uv (it writes nothing) and the fake pip-audit, on the real locks
    (read only); with `venv_fails`, the audit's venv cannot be made (no network)."""
    log = tmp_path / "uv.log"
    uv = world.bin / "uv"
    uv.write_text(f'#!/bin/sh\necho "$*" >> "{log}"\n')
    uv.chmod(0o755)
    if venv_fails:
        py = world.bin / "python3"
        py.write_text(f'#!/bin/sh\nif [ "$1" = "-m" ] && [ "$2" = "venv" ]; then echo "venv: no network" >&2; exit 1; fi\n'
                      f'exec "{sys.executable}" "$@"\n')
        py.chmod(0o755)
    env = {**os.environ, "PATH": f"{world.bin}{os.pathsep}{os.environ['PATH']}",
           "FAKE_ADVISORIES": str(world.advisories), "FAKE_PIP_AUDIT_LOG": str(world.audit_log)}
    for k in ("UPGRADE", "PIP_AUDIT", "AUDIT_VENV", "MAKEFLAGS"):
        env.pop(k, None)
    res = subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), "lock", f"UV={uv}", *extra],
                         env=env, capture_output=True, text=True, timeout=120)
    return res, log.read_text().splitlines()


@needs_make
def test_make_lock_says_the_advisories_of_what_it_wrote_without_failing(tmp_path, world):
    version = re.search(r"^litellm==(\S+) ", (ROOT / "requirements" / "dev.txt").read_text(), re.M).group(1)
    world.advise({"litellm": {version: [{"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2099-0001"],
                                         "fix_versions": ["99.0"]}]}})
    res, uv = _make_lock(tmp_path, world, (f"PIP_AUDIT={world.bin / 'pip-audit'}",))
    assert res.returncode == 0, res.stdout + res.stderr
    assert any("requirements/audit.in" in c and "-o requirements/audit.txt" in c for c in uv)
    assert "litellm · GHSA-aaaa-bbbb-cccc (CVE-2099-0001)" in res.stdout
    audited = [json.loads(line) for line in world.audit_log.read_text().splitlines()]
    assert sorted(a[a.index("-r") + 1] for a in audited) == sorted(LOCKS)


@needs_make
def test_make_lock_does_not_fail_when_the_audit_cannot_run(tmp_path, world):
    res, _ = _make_lock(tmp_path, world, (f"PIP_AUDIT={tmp_path / 'absent' / 'pip-audit'}",
                                          f"AUDIT_VENV={tmp_path / 'absent'}"), venv_fails=True)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "venv: no network" in res.stderr
