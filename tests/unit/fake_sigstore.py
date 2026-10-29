"""CI3: a fake cosign, for scripts/published_image.py and the CD of H0 — as cosign v3.1.3 answers
(measured on 29/10 against public images, no token): each certificate flag given must match the
signer's claims, a flag left out is not checked; `verify` prints the signed digests,
`verify-attestation` one DSSE envelope per attestation (its payload, the in-toto statement).

Its state, a JSON file ($FAKE_COSIGN_STATE): {"signed": {digest: claims}, "attested": {digest:
[{"claims": claims, "statement": statement}]}}; every call is appended to $FAKE_COSIGN_LOG.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

ISSUER = "https://token.actions.githubusercontent.com"
WORKFLOW = ".github/workflows/publish.yml"

FAKE_COSIGN = r'''#!PYTHON
import base64, json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_COSIGN_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
st = json.loads(open(os.environ["FAKE_COSIGN_STATE"]).read())
cmd, ref = args[0], args[-1]
digest = ref.rsplit("@", 1)[1] if "@" in ref else ""
flags = {"--certificate-identity": "identity", "--certificate-oidc-issuer": "issuer",
         "--certificate-github-workflow-repository": "repository", "--certificate-github-workflow-ref": "ref",
         "--certificate-github-workflow-trigger": "trigger", "--certificate-github-workflow-sha": "sha"}
want = {flags[a]: args[i + 1] for i, a in enumerate(args) if a in flags}
def match(claims):
    for k, v in want.items():
        if claims.get(k) != v:
            return f"expected {k} to be {v!r}, got {claims.get(k)!r}"
    return ""
if cmd == "verify":
    claims = st.get("signed", {}).get(digest)
    why = "no signatures found" if claims is None else match(claims)
    if why:
        sys.exit(f"Error: no matching signatures: {why}")
    print(json.dumps([{"critical": {"identity": {"docker-reference": ref.split("@")[0]},
                                    "image": {"docker-manifest-digest": st.get("signed_digest", {}).get(digest, digest)},
                                    "type": "https://sigstore.dev/cosign/sign/v1"}, "optional": {}}]))
elif cmd == "verify-attestation":
    kind = args[args.index("--type") + 1]
    atts = [a for a in st.get("attested", {}).get(digest, []) if a["statement"].get("predicateType") == kind]
    why = "no matching attestations" if not atts else ""
    good = [a for a in atts if not match(a["claims"])]
    if atts and not good:
        why = "no matching attestations: " + match(atts[0]["claims"])
    if why:
        sys.exit(f"Error: {why}")
    for a in good:
        print(json.dumps({"payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "x"}],
                          "payload": base64.b64encode(json.dumps(a["statement"]).encode()).decode()}))
else:
    sys.exit(f"unknown command {cmd}")
sys.stderr.write("Verification for " + ref + " --\n")
'''


def claims(slug, commit, *, workflow=WORKFLOW, ref="refs/heads/main", trigger="push"):
    return {"identity": f"https://github.com/{slug}/{workflow}@{ref}", "issuer": ISSUER,
            "repository": slug, "ref": ref, "trigger": trigger, "sha": commit}


def statement(name, digest, slug, commit, *, workflow=WORKFLOW, ref="refs/heads/main", event="push",
              runner="github-hosted", predicate_type="https://slsa.dev/provenance/v1"):
    return {"_type": "https://in-toto.io/Statement/v1", "predicateType": predicate_type,
            "subject": [{"name": name, "digest": {"sha256": digest.split(":", 1)[1]}}],
            "predicate": {"buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {"workflow": {"ref": ref, "repository": f"https://github.com/{slug}",
                                                    "path": workflow}},
                "internalParameters": {"github": {"event_name": event, "runner_environment": runner}},
                "resolvedDependencies": [{"uri": f"git+https://github.com/{slug}@{ref}",
                                          "digest": {"gitCommit": commit}}]}}}


class Sigstore:
    """The fake's state, and its binary installed at `path` (its sha256 in `.sha256`)."""

    def __init__(self, path: Path, state: Path, log: Path):
        self.path, self.state, self.log = path, state, log
        path.write_text(FAKE_COSIGN.replace("#!PYTHON", f"#!{sys.executable}"))
        path.chmod(0o755)
        self.sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        self.data = {"signed": {}, "attested": {}, "signed_digest": {}}
        self.save()
        log.write_text("")

    def save(self):
        self.state.write_text(json.dumps(self.data))

    def sign(self, digest, claims_):
        self.data["signed"][digest] = claims_
        self.save()

    def attest(self, digest, claims_, statement_):
        self.data["attested"].setdefault(digest, []).append({"claims": claims_, "statement": statement_})
        self.save()

    def publish(self, name, digest, slug, commit, **over):
        """Signed and attested as publish.yml does it; `over` changes the signer (workflow, ref, trigger)."""
        sig = {k: over[k] for k in ("workflow", "ref", "trigger") if k in over}
        c = claims(slug, over.get("sha", commit), **sig)
        self.sign(digest, c)
        st = {k: over[k] for k in ("workflow", "ref") if k in over}
        self.attest(digest, c, statement(name, digest, slug, over.get("sha", commit), **st))

    def env(self):
        return {"FAKE_COSIGN_STATE": str(self.state), "FAKE_COSIGN_LOG": str(self.log)}

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]


def envelope(statement_):
    return json.dumps({"payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "x"}],
                       "payload": base64.b64encode(json.dumps(statement_).encode()).decode()})
