import copy
import errno
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ckpt  # noqa: E402

SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_256 = "c" * 64
T0 = datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)


def repo_input():
    return {
        "project": {"kind": "repo", "owner": "example-org", "repo": "example-app"},
        "branch": "feature/demo",
        "work_order": "example-issue-1",
        "observed": {"head_sha": SHA_A, "remote_sha": SHA_A, "default_sha": SHA_B,
                     "pr": {"number": 7, "state": "draft", "head_sha": SHA_A},
                     "ci": {"state": "success", "run_id": "1"}},
        "approved_scope": ["edit src/demo.txt"], "changed_files": ["src/demo.txt"],
        "evidence": [{"id": "E1", "kind": "test", "result": "PASS synthetic"}],
        "decisions": ["use synthetic data"], "failed_attempts": [], "incomplete": ["write docs"],
        "cleanup_ledger": [], "next_action": "finish docs", "rollback": "delete branch",
        "limitations": ["synthetic"],
    }


def ws_input():
    d = repo_input()
    d["project"] = {"kind": "workspace", "name": "scratch-ws"}
    d["branch"] = None
    d["observed"] = {"workspace_state": "manifest-sha256:" + SHA_256}
    return d


def rand_fixed():
    return "deadbeef"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ckpt-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.st = ckpt.DirStorage(self.tmp, "tier_a")


class T1RoundTrip(Base):
    def test_roundtrip_repo_and_workspace(self):
        for inp in (repo_input(), ws_input()):
            rep = ckpt.write_checkpoint(self.st, inp, now=T0)
            self.assertEqual(rep["status"], "LOCAL_VALIDATED")
            cp, _ = ckpt.load(self.st, rep["ref"])
            self.assertEqual(cp["content_sha256"], rep["content_sha256"])
            self.assertEqual(cp["next_action"], "finish docs")


class T2Schema(Base):
    def built(self, inp=None):
        return ckpt.build(inp or repo_input(), now=T0)

    def test_missing_required_fields(self):
        for k in ckpt.REQUIRED:
            if k in ("id", "created_utc", "content_sha256", "schema", "project", "observed"):
                continue
            inp = repo_input()
            inp.pop(k)
            with self.assertRaises(ckpt.InvalidError, msg=k) as cm:
                ckpt.write_checkpoint(self.st, inp, now=T0)
            self.assertIn(k, str(cm.exception))

    def test_wrong_types_and_enums(self):
        for mut in (lambda d: d.update(next_action=""), lambda d: d.update(changed_files="x"),
                    lambda d: d["observed"].update(head_sha="zz"),
                    lambda d: d["observed"]["pr"].update(state="weird"),
                    lambda d: d["observed"].update(ci={"state": "bogus"}),
                    lambda d: d.update(evidence=[{"id": "E"}]),
                    lambda d: d["project"].update(owner="../x"),
                    lambda d: d.update(branch=None)):
            inp = repo_input()
            mut(inp)
            with self.assertRaises(ckpt.InvalidError):
                ckpt.write_checkpoint(self.st, inp, now=T0)

    def test_unknown_major_rejected_and_extra_fields_ok(self):
        cp = self.built()
        cp["schema"] = "devsys.checkpoint/2"
        cp["content_sha256"] = ckpt.body_hash(cp)
        with self.assertRaises(ckpt.InvalidError):
            ckpt.validate(cp)
        cp = self.built(dict(repo_input(), future_field={"x": 1}))
        ckpt.validate(cp)  # unknown extra field tolerated

    def test_workspace_without_comparable_state_is_valid(self):
        inp = ws_input()
        inp["observed"] = {}
        ckpt.validate(ckpt.build(inp, now=T0))

    def test_repo_needs_head_or_remote(self):
        inp = repo_input()
        inp["observed"] = {"default_sha": SHA_B}
        with self.assertRaises(ckpt.InvalidError):
            ckpt.write_checkpoint(self.st, inp, now=T0)


class T3Secrets(Base):
    def samples(self):
        return {
            "github-token": "ghp_" + "A" * 36,
            "github-pat": "github_pat_" + "B" * 30,
            "aws": "AK" + "IA" + "C" * 16,
            "private-key": "-----BEGIN " + "RSA PRIVATE KEY-----",
            "auth-header": "Authorization: " + "Basic abcdef",
            "bearer": "Bearer " + "x" * 20,
            "cookie": "Cookie: " + "sid=abcdef",
            "jwt": ".".join(["eyJ" + "a" * 10, "b" * 10, "c" * 10]),
            "api-key": "sk-" + "d" * 30,
            "assignment": "pass" + "word = " + "hunter2hunter2",
        }

    def test_value_rejected_before_any_file(self):
        for name, s in self.samples().items():
            inp = repo_input()
            inp["decisions"] = ["note " + s]
            with self.assertRaises(ckpt.InvalidError, msg=name) as cm:
                ckpt.write_checkpoint(self.st, inp, now=T0)
            self.assertNotIn(s, str(cm.exception))  # never echoes the secret
        self.assertEqual(self.st.list(repo_input()["project"]), [])

    def test_key_and_nested_rejected(self):
        s = "ghp_" + "A" * 36
        inp = repo_input()
        inp["future"] = {s: 1}
        with self.assertRaises(ckpt.InvalidError):
            ckpt.write_checkpoint(self.st, inp, now=T0)
        inp = repo_input()
        inp["future"] = [{"deep": [{"x": "tok" + "en: " + "z" * 12}]}]
        with self.assertRaises(ckpt.InvalidError):
            ckpt.write_checkpoint(self.st, inp, now=T0)
        inp = repo_input()
        inp["future"] = {"to" + "ken": "z" * 12}
        with self.assertRaises(ckpt.InvalidError):
            ckpt.write_checkpoint(self.st, inp, now=T0)

    def test_shas_not_flagged(self):
        inp = repo_input()
        inp["observed"]["head_sha"] = SHA_256
        inp["decisions"] = ["token budget discussed", "no secrets stored"]
        ckpt.write_checkpoint(self.st, inp, now=T0)


class T4PathSafety(Base):
    def test_bad_project_and_branch_components(self):
        for owner in ("..", "a/b", "a\\b", "a__b", "/abs", "a\x00b", ""):
            inp = repo_input()
            inp["project"]["owner"] = owner
            with self.assertRaises(ckpt.InvalidError, msg=repr(owner)):
                ckpt.write_checkpoint(self.st, inp, now=T0)
        inp = repo_input()
        inp["branch"] = "../../etc/passwd"  # allowed as data, slugged in id, never used as a path
        rep = ckpt.write_checkpoint(self.st, inp, now=T0)
        self.assertNotIn("..", rep["id"])
        inp["branch"] = "bad\x00branch"
        with self.assertRaises(ckpt.InvalidError):
            ckpt.write_checkpoint(self.st, inp, now=T0)

    def test_ref_escape_and_symlink(self):
        for ref in ("../x.json", "/etc/passwd", "a/../../x", ""):
            with self.assertRaises(ckpt.StorageError):
                self.st.get(ref)
        outside = tempfile.mkdtemp(prefix="ckpt-out-")
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        os.makedirs(os.path.join(self.tmp, "docs", "dev"))
        os.symlink(outside, os.path.join(self.tmp, "docs", "dev", "checkpoints"))
        with self.assertRaises(ckpt.StorageError):
            ckpt.write_checkpoint(self.st, repo_input(), now=T0)
        self.assertEqual(os.listdir(outside), [])


class T5Identity(Base):
    def test_unique_ids(self):
        ids = {ckpt.build(repo_input(), now=T0)["id"] for _ in range(1000)}
        self.assertEqual(len(ids), 1000)

    def test_no_clobber(self):
        r1 = ckpt.write_checkpoint(self.st, repo_input(), now=T0, rand=rand_fixed)
        path = os.path.join(self.tmp, *r1["ref"].split("/"))
        before = open(path, "rb").read()
        other = repo_input()
        other["next_action"] = "different"
        with self.assertRaises(ckpt.StorageError):
            ckpt.write_checkpoint(self.st, other, now=T0, rand=rand_fixed)
        self.assertEqual(open(path, "rb").read(), before)
        self.assertEqual([n for n in os.listdir(os.path.dirname(path)) if n.startswith(".tmp-")], [])


class T6StorageErrors(Base):
    def test_missing_or_file_root(self):
        with self.assertRaises(ckpt.StorageError):
            ckpt.DirStorage(os.path.join(self.tmp, "nope"), "tier_a")
        f = os.path.join(self.tmp, "f")
        open(f, "w").close()
        with self.assertRaises(ckpt.StorageError):
            ckpt.DirStorage(f, "tier_a")
        with self.assertRaises(ckpt.StorageError):
            ckpt.DirStorage(self.tmp, "tier_z")

    def test_permission_and_disk_full(self):
        with mock.patch("tempfile.mkstemp", side_effect=PermissionError(errno.EACCES, "ro")):
            with self.assertRaises(ckpt.StorageError):
                ckpt.write_checkpoint(self.st, repo_input(), now=T0)
        real = os.fdopen

        def full(fd, mode):
            f = real(fd, mode)
            f.write = mock.Mock(side_effect=OSError(errno.ENOSPC, "no space"))
            return f
        with mock.patch("os.fdopen", side_effect=full):
            with self.assertRaises(ckpt.StorageError):
                ckpt.write_checkpoint(self.st, repo_input(), now=T0)
        self.assertEqual(self.st.list(repo_input()["project"]), [])

    def test_corrupt_truncated_tampered_missing(self):
        rep = ckpt.write_checkpoint(self.st, repo_input(), now=T0)
        path = os.path.join(self.tmp, *rep["ref"].split("/"))
        good = open(path, "rb").read()
        open(path, "wb").write(good[: len(good) // 2])
        with self.assertRaises(ckpt.InvalidError):
            ckpt.load(self.st, rep["ref"])
        open(path, "wb").write(good.replace(b"finish docs", b"do evil"))
        with self.assertRaises(ckpt.InvalidError) as cm:
            ckpt.load(self.st, rep["ref"])
        self.assertIn("content_sha256", str(cm.exception))
        open(path, "wb").write(b"\xff\xfe")
        with self.assertRaises(ckpt.InvalidError):
            ckpt.load(self.st, rep["ref"])
        os.unlink(path)
        with self.assertRaises(ckpt.StorageError):
            ckpt.load(self.st, rep["ref"])

    def test_corrupt_latest_does_not_fall_back(self):
        a = ckpt.write_checkpoint(self.st, repo_input(), now=T0)
        b = ckpt.write_checkpoint(self.st, repo_input(), now=datetime(2026, 11, 10, 13, 0, 0, tzinfo=timezone.utc))
        open(os.path.join(self.tmp, *b["ref"].split("/")), "wb").write(b"{")
        with self.assertRaises(ckpt.InvalidError):
            ckpt.recover(self.st, repo_input()["project"], "latest", repo_input()["observed"])
        self.assertTrue(a["ref"])


class T7Stale(Base):
    def cp(self, inp=None):
        return ckpt.build(inp or repo_input(), now=T0)

    def test_current(self):
        self.assertEqual(ckpt.check_stale(self.cp(), repo_input()["observed"])["verdict"], "CURRENT")

    def test_each_change_is_stale(self):
        muts = {
            "head_sha": lambda o: o.update(head_sha=SHA_B),
            "remote_sha": lambda o: o.update(remote_sha=SHA_B),
            "pr.state": lambda o: o["pr"].update(state="merged"),
            "ci.state": lambda o: o["ci"].update(state="failure"),
            "pr": lambda o: o.update(pr=None),
        }
        for field, mut in muts.items():
            now = copy.deepcopy(repo_input()["observed"])
            mut(now)
            r = ckpt.check_stale(self.cp(), now)
            self.assertEqual(r["verdict"], "STALE", field)
            self.assertIn(field, [d["field"] for d in r["fields"]])

    def test_new_pr_since_checkpoint(self):
        inp = repo_input()
        inp["observed"]["pr"] = None
        now = copy.deepcopy(inp["observed"])
        now["pr"] = {"number": 9, "state": "open", "head_sha": SHA_A}
        self.assertEqual(ckpt.check_stale(self.cp(inp), now)["verdict"], "STALE")

    def test_blocked(self):
        now = copy.deepcopy(repo_input()["observed"])
        now["branch_exists"] = False
        self.assertEqual(ckpt.check_stale(self.cp(), now)["verdict"], "BLOCKED")
        self.assertEqual(ckpt.check_stale(self.cp(), {})["verdict"], "BLOCKED")
        self.assertEqual(ckpt.check_stale(self.cp(), "x")["verdict"], "BLOCKED")

    def test_workspace(self):
        cp = self.cp(ws_input())
        self.assertEqual(ckpt.check_stale(cp, ws_input()["observed"])["verdict"], "CURRENT")
        self.assertEqual(ckpt.check_stale(cp, {"workspace_state": "other"})["verdict"], "STALE")
        self.assertEqual(ckpt.check_stale(cp, {"head_sha": SHA_A})["verdict"], "BLOCKED")


class T8TierB(unittest.TestCase):
    def test_layout_swap_isolation_and_recover(self):
        tmp = tempfile.mkdtemp(prefix="ckpt-b-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        st = ckpt.DirStorage(tmp, "tier_b")
        r1 = ckpt.write_checkpoint(st, repo_input(), now=T0)
        other = repo_input()
        other["project"]["repo"] = "other-app"
        r2 = ckpt.write_checkpoint(st, other, now=T0)
        w = ckpt.write_checkpoint(st, ws_input(), now=T0)
        self.assertEqual(len({os.path.dirname(r["ref"]) for r in (r1, r2, w)}), 3)
        self.assertTrue(r1["ref"].startswith("by-project/repo__example-org__example-app/"))
        self.assertTrue(w["ref"].startswith("by-project/ws__scratch-ws/"))
        cp, stl, text = ckpt.recover(st, other["project"], "latest", other["observed"])
        self.assertEqual(cp["project"]["repo"], "other-app")
        self.assertEqual(stl["verdict"], "CURRENT")
        cp, stl, _ = ckpt.recover(st, ws_input()["project"], "latest", ws_input()["observed"])
        self.assertEqual(cp["project"]["kind"], "workspace")
        with self.assertRaises(ckpt.StorageError):
            ckpt.recover(st, {"kind": "workspace", "name": "unknown"}, "latest", {})

    def test_tier_a_filters_by_project(self):
        tmp = tempfile.mkdtemp(prefix="ckpt-a-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        st = ckpt.DirStorage(tmp, "tier_a")
        ckpt.write_checkpoint(st, repo_input(), now=T0)
        other = repo_input()
        other["project"]["repo"] = "other-app"
        ckpt.write_checkpoint(st, other, now=datetime(2026, 11, 10, 14, 0, 0, tzinfo=timezone.utc))
        cp, _, _ = ckpt.recover(st, repo_input()["project"], "latest", repo_input()["observed"])
        self.assertEqual(cp["project"]["repo"], "example-app")


class T11Persistence(Base):
    def test_state_machine(self):
        rep = ckpt.write_checkpoint(self.st, repo_input(), now=T0)
        self.assertEqual(rep["persistence"], "LOCAL_VALIDATED")  # never remote from write
        good = self.st.get(rep["ref"])
        ok = ckpt.confirm_remote(self.st, rep["ref"], SHA_A, good)
        self.assertEqual(ok["status"], "REMOTE_PERSISTED")
        bad = ckpt.confirm_remote(self.st, rep["ref"], SHA_A, good.replace(b"finish", b"FINISH"))
        self.assertEqual(bad["status"], "PARTIAL")
        self.assertEqual(ckpt.confirm_remote(self.st, rep["ref"], "nothex", good)["status"], "PARTIAL")
        self.assertEqual(ckpt.confirm_remote(self.st, rep["ref"], SHA_A, b"")["status"], "PARTIAL")


class CLI(Base):
    def run_cli(self, *args):
        with mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            return ckpt.main(list(args))

    def test_exit_codes(self):
        inp = os.path.join(self.tmp, "in.json")
        json.dump(repo_input(), open(inp, "w"))
        self.assertEqual(self.run_cli("write", "--root", self.tmp, "--in", inp), 0)
        now = os.path.join(self.tmp, "now.json")
        json.dump(repo_input()["observed"], open(now, "w"))
        proj = "repo:example-org/example-app"
        self.assertEqual(self.run_cli("recover", "--root", self.tmp, "--project", proj, "--observed", now), 0)
        json.dump(dict(repo_input()["observed"], head_sha=SHA_B), open(now, "w"))
        self.assertEqual(self.run_cli("recover", "--root", self.tmp, "--project", proj, "--observed", now), 3)
        self.assertEqual(self.run_cli("write", "--root", os.path.join(self.tmp, "none"), "--in", inp), 4)
        open(inp, "w").write("{bad")
        self.assertEqual(self.run_cli("write", "--root", self.tmp, "--in", inp), 2)


if __name__ == "__main__":
    unittest.main()
