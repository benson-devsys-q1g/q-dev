#!/usr/bin/env python3
"""devsys checkpoint tool (schema v1): writer, validator, stale-state checker, reader.

Stdlib only, offline. Storage is abstracted (class Storage); git commit/push is NOT done here.
Persistence states reported:
  LOCAL_VALIDATED  written to a working tree, read back, schema + hash verified
  REMOTE_PERSISTED only via confirm_remote(): pushed ref independently read back, bytes identical
  PARTIAL / BLOCKED anything less
Exit codes: 0 ok, 2 invalid, 3 stale/blocked, 4 storage error, 5 partial.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import PurePosixPath

SCHEMA = "devsys.checkpoint/1"
MAX_BYTES = 1_048_576


class CkptError(Exception):
    code = 1


class InvalidError(CkptError):
    code = 2


class StorageError(CkptError):
    code = 4


# ---------------------------------------------------------------- model helpers
SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
ID_RE = re.compile(r"^\d{8}T\d{6}Z-[a-z0-9-]{1,40}-[0-9a-f]{8}$")
COMP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
WS_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
PR_STATES = {"open", "draft", "closed", "merged"}
CI_STATES = {"pending", "success", "failure", "none", "unknown"}
LIST_STR = ["approved_scope", "changed_files", "decisions", "failed_attempts",
            "incomplete", "cleanup_ledger", "limitations"]
REQUIRED = ["schema", "id", "created_utc", "project", "observed", "evidence",
            "next_action", "rollback", "content_sha256"] + LIST_STR


def _need(cond, msg):
    if not cond:
        raise InvalidError(msg)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def body_hash(cp):
    return hashlib.sha256(canonical({k: v for k, v in cp.items() if k != "content_sha256"})).hexdigest()


def serialize(cp):
    return (json.dumps(cp, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def parse(data):
    if len(data) > MAX_BYTES:
        raise InvalidError("checkpoint too large")
    try:
        cp = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise InvalidError(f"not valid JSON/UTF-8: {e}")
    return cp


def slugify(s):
    s = re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")[:40].strip("-")
    return s or "none"


def _check_project(p):
    _need(isinstance(p, dict), "project: must be an object")
    kind = p.get("kind")
    if kind == "repo":
        for k in ("owner", "repo"):
            v = p.get(k)
            _need(isinstance(v, str) and COMP_RE.match(v) and "__" not in v and ".." not in v,
                  f"project.{k}: invalid")
    elif kind == "workspace":
        _need(isinstance(p.get("name"), str) and WS_RE.match(p["name"]) and "__" not in p["name"],
              "project.name: invalid")
    else:
        raise InvalidError("project.kind: must be 'repo' or 'workspace'")


def project_key(p):
    _check_project(p)
    return f"repo:{p['owner']}/{p['repo']}" if p["kind"] == "repo" else f"ws:{p['name']}"


def project_dirname(p):
    _check_project(p)
    return f"repo__{p['owner']}__{p['repo']}" if p["kind"] == "repo" else f"ws__{p['name']}"


def parse_project_arg(s):
    if s.startswith("repo:") and "/" in s:
        owner, repo = s[5:].split("/", 1)
        p = {"kind": "repo", "owner": owner, "repo": repo}
    elif s.startswith("ws:"):
        p = {"kind": "workspace", "name": s[3:]}
    else:
        raise InvalidError("project must be repo:<owner>/<repo> or ws:<name>")
    _check_project(p)
    return p


# ---------------------------------------------------------------- secret scan
_SECRET_PATTERNS = [
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("github-pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("aws-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("auth-header", re.compile(r"(?i)\bauthorization\s*:\s*\S+")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("cookie", re.compile(r"(?i)\b(?:set-cookie|cookie)\s*:\s*\S+")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")),
    ("api-key", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})")),
    ("assignment", re.compile(r"(?i)\b(?:password|passwd|secret|token|api[_-]?key)\b\s*[:=]\s*\S{8,}")),
]
_SENSITIVE_KEY = re.compile(r"(?i)^(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key)$")


def _hits_in_str(s):
    return [n for n, rx in _SECRET_PATTERNS if rx.search(s)]


def scan_secrets(obj):
    """Return [(path, pattern)] for secret-shaped content in all string keys/values. Never echoes values."""
    hits = []

    def walk(o, p):
        if isinstance(o, str):
            hits.extend((p, n) for n in _hits_in_str(o))
        elif isinstance(o, dict):
            for k, v in o.items():
                ks = k if isinstance(k, str) else str(k)
                kh = _hits_in_str(ks)
                kp = p + ".<redacted-key>" if (kh or len(ks) > 64) else f"{p}.{ks}"
                hits.extend((kp, n) for n in kh)
                if _SENSITIVE_KEY.match(ks) and isinstance(v, str) and len(v) >= 8:
                    hits.append((kp, "sensitive-key"))
                walk(v, kp)
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{p}[{i}]")

    walk(obj, "$")
    return hits


# ---------------------------------------------------------------- validation
def _check_observed(o, kind):
    _need(isinstance(o, dict), "observed: must be an object")
    for k in ("head_sha", "remote_sha", "default_sha"):
        v = o.get(k)
        _need(v is None or (isinstance(v, str) and SHA_RE.match(v)), f"observed.{k}: must be 40/64 hex or null")
    if kind == "repo":
        _need(o.get("head_sha") or o.get("remote_sha"), "observed: repo checkpoint needs head_sha or remote_sha")
    ws = o.get("workspace_state")
    _need(ws is None or (isinstance(ws, str) and len(ws) <= 200), "observed.workspace_state: string <=200 or null")
    pr = o.get("pr")
    if pr is not None:
        _need(isinstance(pr, dict) and isinstance(pr.get("number"), int) and not isinstance(pr.get("number"), bool),
              "observed.pr.number: int")
        _need(pr.get("state") in PR_STATES, "observed.pr.state: invalid")
        _need(pr.get("head_sha") is None or (isinstance(pr.get("head_sha"), str) and SHA_RE.match(pr["head_sha"])),
              "observed.pr.head_sha: invalid")
    ci = o.get("ci")
    if ci is not None:
        _need(isinstance(ci, dict) and ci.get("state") in CI_STATES, "observed.ci.state: invalid")


def validate(cp):
    _need(isinstance(cp, dict), "checkpoint must be an object")
    m = re.match(r"^devsys\.checkpoint/(\d+)(?:\.\d+)?$", cp["schema"] if isinstance(cp.get("schema"), str) else "")
    _need(m, "schema: missing or malformed")
    _need(int(m.group(1)) == 1, f"schema: unsupported major version {m.group(1)}")
    for k in REQUIRED:
        _need(k in cp, f"{k}: missing")
    _need(isinstance(cp["id"], str) and ID_RE.match(cp["id"]), "id: malformed")
    _need(isinstance(cp["created_utc"], str) and TS_RE.match(cp["created_utc"]), "created_utc: malformed")
    _check_project(cp["project"])
    kind = cp["project"]["kind"]
    br = cp.get("branch")
    if kind == "repo":
        _need(isinstance(br, str) and br, "branch: required string for repo checkpoints")
    _need(br is None or (isinstance(br, str) and len(br) <= 255 and not re.search(r"[\x00-\x1f\x7f]", br)),
          "branch: invalid")
    wo = cp.get("work_order")
    _need(wo is None or isinstance(wo, str), "work_order: string or null")
    _check_observed(cp["observed"], kind)
    for k in LIST_STR:
        _need(isinstance(cp[k], list) and all(isinstance(x, str) for x in cp[k]), f"{k}: must be a list of strings")
    _need(isinstance(cp["evidence"], list) and all(
        isinstance(e, dict) and all(isinstance(e.get(f), str) and e.get(f) for f in ("id", "kind", "result"))
        for e in cp["evidence"]), "evidence: list of {id,kind,result} strings")
    _need(isinstance(cp["next_action"], str) and cp["next_action"].strip(), "next_action: non-empty string")
    _need(isinstance(cp["rollback"], str), "rollback: string")
    _need(isinstance(cp["content_sha256"], str) and cp["content_sha256"] == body_hash(cp),
          "content_sha256: mismatch (tampered or corrupt)")
    hits = scan_secrets(cp)
    _need(not hits, "secret-like content rejected at " + ", ".join(f"{p} ({n})" for p, n in hits[:5]))
    return cp


def build(inp, now=None, rand=None):
    """Add id, created_utc, content_sha256 to caller input. now: datetime, rand: callable -> 8 hex."""
    _need(isinstance(inp, dict), "input must be an object")
    cp = dict(inp)
    cp.setdefault("schema", SCHEMA)
    _check_project(cp.get("project"))
    now = now or datetime.now(timezone.utc)
    rnd = rand() if rand else secrets.token_hex(4)
    p = cp["project"]
    cp["created_utc"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    cp["id"] = f"{now.strftime('%Y%m%dT%H%M%SZ')}-{slugify(cp.get('branch') or p.get('name') or p.get('repo'))}-{rnd}"
    cp.pop("content_sha256", None)
    cp["content_sha256"] = body_hash(cp)
    return cp


# ---------------------------------------------------------------- storage
class Storage:
    def put(self, project, cid, data):  # -> ref (str)
        raise NotImplementedError

    def get(self, ref):  # -> bytes
        raise NotImplementedError

    def list(self, project):  # -> sorted refs
        raise NotImplementedError


class DirStorage(Storage):
    """Directory-backed. layout tier_a: docs/dev/checkpoints/<id>.json ; tier_b: by-project/<dir>/<id>.json.
    Tier B = a clone of a private checkpoint repo passed as root with layout tier_b; no other code changes."""
    LAYOUTS = ("tier_a", "tier_b")

    def __init__(self, root, layout="tier_a"):
        if layout not in self.LAYOUTS:
            raise StorageError(f"unknown layout: {layout}")
        self.layout = layout
        self.root = os.path.realpath(root)
        if not os.path.isdir(self.root):
            raise StorageError(f"root is not a directory: {root}")

    def _parts(self, project):
        return ("docs", "dev", "checkpoints") if self.layout == "tier_a" else ("by-project", project_dirname(project))

    def _inside(self, path):
        real = os.path.realpath(path)
        if real != self.root and not real.startswith(self.root + os.sep):
            raise StorageError("path escapes storage root")
        return real

    def put(self, project, cid, data):
        _need(ID_RE.match(cid or ""), "id: malformed")
        d = os.path.join(self.root, *self._parts(project))
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as e:
            raise StorageError(f"cannot create directory: {e}")
        self._inside(d)
        final = os.path.join(d, cid + ".json")
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.link(tmp, final)  # atomic, never overwrites
            except FileExistsError:
                raise StorageError(f"checkpoint already exists: {cid}")
            except OSError:  # filesystem without hard links
                try:
                    with open(final, "xb") as f:
                        f.write(data)
                except FileExistsError:
                    raise StorageError(f"checkpoint already exists: {cid}")
        except OSError as e:
            raise StorageError(f"write failed: {e}")
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        return PurePosixPath(*self._parts(project), cid + ".json").as_posix()

    def _path(self, ref):
        pp = PurePosixPath(ref or "")
        if not ref or pp.is_absolute() or ".." in pp.parts or "\x00" in ref:
            raise StorageError("invalid ref")
        return self._inside(os.path.join(self.root, *pp.parts))

    def get(self, ref):
        try:
            with open(self._path(ref), "rb") as f:
                return f.read(MAX_BYTES + 1)
        except OSError as e:
            raise StorageError(f"read failed: {e}")

    def list(self, project):
        d = os.path.join(self.root, *self._parts(project))
        if not os.path.isdir(d):
            return []
        try:
            names = sorted(n for n in os.listdir(d) if n.endswith(".json") and not n.startswith("."))
        except OSError as e:
            raise StorageError(f"list failed: {e}")
        return [PurePosixPath(*self._parts(project), n).as_posix() for n in names]


# ---------------------------------------------------------------- operations
def load(storage, ref):
    data = storage.get(ref)
    cp = parse(data)
    validate(cp)
    return cp, data


def write_checkpoint(storage, inp, now=None, rand=None):
    cp = build(inp, now, rand)
    validate(cp)  # before any file is created
    data = serialize(cp)
    ref = storage.put(cp["project"], cp["id"], data)
    back = storage.get(ref)
    if back != data:
        raise StorageError("readback mismatch after write")
    validate(parse(back))
    return {"status": "LOCAL_VALIDATED", "persistence": "LOCAL_VALIDATED", "ref": ref,
            "id": cp["id"], "content_sha256": cp["content_sha256"]}


def confirm_remote(storage, ref, remote_sha, readback):
    """Promote to REMOTE_PERSISTED only if an independently fetched copy of the pushed file is byte-identical."""
    reasons = []
    if not (isinstance(remote_sha, str) and SHA_RE.match(remote_sha)):
        reasons.append("remote sha malformed")
    local = storage.get(ref)
    if readback != local:
        reasons.append("remote readback differs from local file")
    try:
        validate(parse(readback))
    except InvalidError as e:
        reasons.append(f"readback invalid: {e}")
    if reasons:
        return {"status": "PARTIAL", "persistence": "LOCAL_VALIDATED", "ref": ref, "reasons": reasons}
    return {"status": "REMOTE_PERSISTED", "persistence": "REMOTE_PERSISTED", "ref": ref, "remote_sha": remote_sha}


def _flat(o):
    f = {}
    for k in ("head_sha", "remote_sha", "default_sha", "workspace_state"):
        if o.get(k) is not None:
            f[k] = o[k]
    if "pr" in o:
        pr = o["pr"]
        f["pr"] = "none" if pr is None else "present"
        if pr:
            for k in ("number", "state", "head_sha"):
                if pr.get(k) is not None:
                    f["pr." + k] = pr[k]
    if "ci" in o:
        ci = o["ci"]
        f["ci"] = "none" if ci is None else "present"
        if ci:
            f["ci.state"] = ci.get("state")
    return f


def check_stale(cp, now):
    """Compare stored observed state with caller-supplied current state. Returns dict verdict CURRENT|STALE|BLOCKED."""
    if not isinstance(now, dict):
        return {"verdict": "BLOCKED", "reason": "current state must be an object", "fields": []}
    if now.get("branch_exists") is False:
        return {"verdict": "BLOCKED", "reason": "branch no longer exists", "fields": []}
    stored, cur = _flat(cp["observed"]), _flat(now)
    common = [k for k in stored if k in cur]
    if not common:
        return {"verdict": "BLOCKED", "reason": "no comparable observed fields", "fields": []}
    diffs = [{"field": k, "stored": stored[k], "now": cur[k]} for k in common if stored[k] != cur[k]]
    return {"verdict": "STALE" if diffs else "CURRENT", "reason": "", "fields": diffs}


def render_resume(cp, st):
    def lst(title, items):
        return [f"{title}:"] + [f"  - {x}" for x in items] if items else [f"{title}: (none)"]

    out = [f"CHECKPOINT {cp['id']}  project={project_key(cp['project'])}  branch={cp.get('branch')}",
           f"created={cp['created_utc']}  state-check={st['verdict']}" + (f" ({st['reason']})" if st["reason"] else "")]
    out += [f"  STALE {d['field']}: stored={d['stored']} now={d['now']}" for d in st["fields"]]
    out += [f"NEXT ACTION: {cp['next_action']}", f"ROLLBACK: {cp['rollback']}"]
    for t, k in (("Approved scope", "approved_scope"), ("Changed files", "changed_files"),
                 ("Incomplete", "incomplete"), ("Failed attempts", "failed_attempts"),
                 ("Decisions", "decisions"), ("Cleanup ledger", "cleanup_ledger"), ("Limitations", "limitations")):
        out += lst(t, cp[k])
    out += lst("Evidence", [f"{e['id']} [{e['kind']}] {e['result']}" for e in cp["evidence"]])
    return "\n".join(out)


def recover(storage, project, which, now):
    refs = list(reversed(storage.list(project)))
    if which != "latest":
        refs = [r for r in refs if r.endswith("/" + which + ".json")]
    key = project_key(project)
    for ref in refs:  # a corrupt file raises (never silently fall back to an older checkpoint)
        cp, _ = load(storage, ref)
        if project_key(cp["project"]) == key:
            st = check_stale(cp, now)
            return cp, st, render_resume(cp, st)
    raise StorageError("no checkpoint found for project")


# ---------------------------------------------------------------- CLI
def _read_json_arg(path):
    try:
        raw = sys.stdin.buffer.read() if path == "-" else open(path, "rb").read()
    except OSError as e:
        raise StorageError(f"cannot read {path}: {e}")
    return parse(raw)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ckpt")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("write", "recover", "confirm-remote"):
        p = sub.add_parser(name)
        p.add_argument("--root", required=True)
        p.add_argument("--layout", default="tier_a", choices=DirStorage.LAYOUTS)
    sub.choices["write"].add_argument("--in", dest="inp", required=True)
    r = sub.choices["recover"]
    r.add_argument("--project", required=True)
    r.add_argument("--id", default="latest")
    r.add_argument("--observed", required=True, help="JSON file with current observed state")
    c = sub.choices["confirm-remote"]
    c.add_argument("--ref", required=True)
    c.add_argument("--remote-sha", required=True)
    c.add_argument("--readback", required=True, help="file fetched independently from the remote")
    v = sub.add_parser("validate")
    v.add_argument("file")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "validate":
            validate(_read_json_arg(a.file))
            print("VALID")
            return 0
        st = DirStorage(a.root, a.layout)
        if a.cmd == "write":
            rep = write_checkpoint(st, _read_json_arg(a.inp))
            print(f"CHECKPOINT {rep['status']} {rep['ref']} sha256={rep['content_sha256']}")
            print("NOTE: local only; remote durability requires push + confirm-remote")
            return 0
        if a.cmd == "confirm-remote":
            try:
                rb = open(a.readback, "rb").read(MAX_BYTES + 1)
            except OSError as e:
                raise StorageError(f"cannot read readback: {e}")
            rep = confirm_remote(st, a.ref, a.remote_sha, rb)
            print(f"CHECKPOINT {rep['status']} {rep['ref']}" + (" " + "; ".join(rep["reasons"]) if "reasons" in rep else ""))
            return 0 if rep["status"] == "REMOTE_PERSISTED" else 5
        cp, stl, text = recover(st, parse_project_arg(a.project), a.id, _read_json_arg(a.observed))
        print(text)
        return 0 if stl["verdict"] == "CURRENT" else 3
    except CkptError as e:
        print(f"ERROR[{type(e).__name__}]: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(main())
