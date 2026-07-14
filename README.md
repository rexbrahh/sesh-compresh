# sesh-compresh

`sesh-compresh` is a local, dry-run-first CLI for three jobs:

- verified zstd archiving and restoration of inactive Claude and Codex sessions;
- reference-aware containment of runaway claude-mem observer transcripts;
- deletion of narrowly allowlisted build and test caches after an immutable plan is reviewed.

It never uploads data. See [docs/product.md](docs/product.md) for the safety and data-format contract.

```sh
PYTHONPATH=src python3 -m sesh_compresh audit
PYTHONPATH=src python3 -m sesh_compresh archive plan
PYTHONPATH=src python3 -m sesh_compresh observer plan
PYTHONPATH=src python3 -m sesh_compresh clean plan --profile practical
```

## Claude-mem observer containment

Observer maintenance finds Claude's project directory by applying the Agent SDK's path sanitization to claude-mem's `observer-sessions` working directory. It does not contain a username-specific path.

`CLAUDE_CONFIG_DIR` follows claude-mem's actual precedence: CLI override, process environment, then `~/.claude`. `CLAUDE_MEM_DATA_DIR` additionally supports the fallback stored in the default claude-mem settings file.

The plan accepts only UUID-shaped top-level JSONL names. It keeps every referenced, recent, or open bundle. A bundle includes the primary JSONL and safe regular files under its exact sibling `<uuid>/` directory; unsafe companion content protects the whole candidate. Arbitrary JSONL names are counted and preserved. Missing or incompatible SQLite state, malformed corpus JSON, and failed open-file enumeration abort without touching transcripts.

```sh
# Read-only: write an immutable two-hour plan.
PYTHONPATH=src python3 -m sesh_compresh observer plan

# Review the printed plan, then archive exact identity-pinned candidates.
PYTHONPATH=src python3 -m sesh_compresh observer apply /path/to/observer-gc-PLAN.json --yes

# One scheduler cycle. Omitting --yes remains read-only.
PYTHONPATH=src python3 -m sesh_compresh --json maintain --yes
```

`maintain --yes` creates and applies an observer plan, then creates a fresh observer-only expiry plan from the resulting archive graph. Defaults retain observer archives for at most seven days and cap their unique compressed objects at 5 GiB. Ordinary Claude/Codex manifests are outside expiry scope, and a CAS object is removed only after every provider manifest stops referencing it.

Generic `archive plan` excludes the observer directory entirely. Apply operations share an advisory lock. Observer apply uses bounded path-filtered `lsof` batches, then repeats a targeted open check and fresh targeted reference check immediately before moving source data. Expiry updates CAS reference counts under the same lock and checks reachability immediately before unlink.

Observer liveness enumeration targets macOS and Linux because it requires `lsof`. The lock backend also supports Windows; observer commands fail closed there unless an `lsof`-compatible executable is installed. Claude-mem and other same-user publishers should cooperate with the maintenance window because processes that ignore the advisory lock can still race a final check.

Use `--claude-config-dir` and `--claude-mem-data-dir` for isolated accounts or tests. See [docs/scheduling.md](docs/scheduling.md) for launchd, cron, and systemd examples.
