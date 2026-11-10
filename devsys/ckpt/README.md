# ckpt — devsys checkpoint tool (schema v1) — SYNTHETIC DATA ONLY

Stdlib-only Python 3, offline. This repository is public: never put real project data or credentials in checkpoints. The writer rejects secret-shaped content (fail closed, never echoes the value).

## Operations (kept separate)
| Operation | Command | Result |
|---|---|---|
| Generate | caller builds input JSON (all fields except `id`, `created_utc`, `content_sha256`) | — |
| Validate | `ckpt.py validate FILE` | `VALID` / exit 2 |
| Store (local) | `ckpt.py write --root R --layout tier_a\|tier_b --in cp.json` | `CHECKPOINT LOCAL_VALIDATED <ref>` after write + readback + hash check |
| Confirm remote | `ckpt.py confirm-remote --root R --layout L --ref REF --remote-sha SHA --readback FILE` | `REMOTE_PERSISTED` only if a copy fetched independently from the remote after push is byte-identical; else `PARTIAL` (exit 5) |
| Recover | `ckpt.py recover --root R --layout L --project repo:<owner>/<repo>\|ws:<name> [--id ID] --observed now.json` | resume brief + `CURRENT`/`STALE`/`BLOCKED` (exit 0/3) |

Git commit/push is done by the session, not by the tool. `write` never reports remote durability.
Exit codes: 0 ok, 2 invalid, 3 stale/blocked, 4 storage error, 5 partial.

## Schema v1 (`"schema": "devsys.checkpoint/1"`; unknown major rejected, extra fields tolerated)
`id` (`<UTC>-<branch-slug>-<8 hex>`), `created_utc`, `project` (`{kind:"repo",owner,repo}` or `{kind:"workspace",name}`), `branch` (required for repo, optional for workspace), `work_order`, `observed` (`head_sha`, `remote_sha`, `default_sha`, `pr{number,state,head_sha}|null`, `ci{state,run_id}|null`, `workspace_state`), `approved_scope[]`, `changed_files[]`, `evidence[{id,kind,result}]`, `decisions[]`, `failed_attempts[]`, `incomplete[]`, `cleanup_ledger[]`, `next_action`, `rollback`, `limitations[]`, `content_sha256` (sha256 of canonical JSON of all other fields).

## Stale-state check
`--observed` is a JSON object of the *current* state gathered by the session (git/GitHub). Only fields present in both are compared; none comparable, or `"branch_exists": false`, gives `BLOCKED`.

## Storage / Tier B
`Storage` interface: `put` (atomic, no-clobber), `get`, `list`. `DirStorage` layouts: `tier_a` = `docs/dev/checkpoints/<id>.json`; `tier_b` = `by-project/<repo__owner__repo | ws__name>/<id>.json`. Tier B reuses everything by passing a clone of the private checkpoint repo as `--root` with `--layout tier_b`.

## Tests
`python3 -I devsys/ckpt/test_ckpt.py` (offline, temp dirs only).
