# Sesh Compresh Product Contract

## Problem

Developer build outputs and AI session histories grow quickly on this Mac. Build products are disposable, while transcripts, agent ledgers, QA evidence, and temporary worktrees may be irreplaceable. Sesh Compresh must recover space without conflating those classes.

## Product principles

1. Discovery is read-only. Mutation requires a short-lived plan generated from the current filesystem.
2. Cleanup uses positive allowlists and required build markers. Age, filename extension, and location under `/private/tmp` never establish disposability by themselves.
3. Session archives are locally content-addressed and byte-verified before source files move.
4. Interrupted archive runs are recoverable from a same-filesystem quarantine journal.
5. Unknown, malformed, changing, open, symlinked, or special files remain untouched.
6. Transcript content never appears in logs. Archive and state directories are private to the user.
7. Observer garbage collection derives its source root from runtime configuration and the Agent SDK path mapping. It never scans for similarly named project directories.
8. Generic age-based archiving excludes claude-mem observer sessions. Their mutation authority belongs exclusively to reference-aware observer maintenance.

## Retention policy

- unreferenced claude-mem observer sessions: archive after a one-hour creation/modification grace period.
- observer archives: expire after seven days and remain below a 5 GiB unique-compressed-object cap by removing oldest manifests first.
- ordinary Claude and Codex sessions: archive after 30 complete days of inactivity.
- activity comes from the greatest valid top-level JSONL `timestamp` in the complete session bundle.
- `~/.claude-mem` databases, vector indexes, logs, corpora, and runtime state are outside archive scope.

## Observer liveness contract

The observer keep-set is the normalized union of every non-null `sdk_sessions.memory_session_id` in the claude-mem SQLite database and every `session_id` present in `*.corpus.json` below the corpora root. Planning accepts only canonical UUID-shaped top-level JSONL names and counts all other names as protected. A candidate bundle includes its primary JSONL and safe regular files under the exact sibling `<uuid>/` directory. Unsafe companion content protects the whole candidate; age, identity, reference, and open-file checks cover every member.

`CLAUDE_CONFIG_DIR` resolves from an explicit CLI argument, the process environment, then `~/.claude`. `CLAUDE_MEM_DATA_DIR` resolves from CLI, environment, its default settings-file fallback, then `~/.claude-mem`. The observer working directory is `<data-dir>/observer-sessions`; Claude's project directory is computed over UTF-16 code units with the SDK's ASCII-alphanumeric sanitization, 200-unit threshold, and signed hash rule.

Plans pin the observer directory's device and inode. Apply validates that directory and every ancestor without following symlinks. It performs one reusable keep-set read and bounded path-filtered `lsof` pass. Immediately before the first source move it repeats a targeted open check followed by a fresh targeted database/corpus reference check. Liveness-source failures abort the remaining run; an individual candidate that becomes referenced, recent, open, missing, or identity-changed is preserved while independent candidates continue.

Observer liveness enumeration requires `lsof`, which targets macOS and Linux by default. Same-user processes can ignore advisory locks, so claude-mem publishers should cooperate with the maintenance window; writes after the final checks remain a residual race.

## Archive format

Raw content is stored as zstd frames in a content-addressed object store. Each manifest member is compressed with exactly one recipe, chosen by role and size: bundle companions compress against the bundle's primary member (`--patch-from`); members above 1 MiB split into newline-aligned chunks of roughly 1 MiB, each stored as its own object (zstd level 12, or level 19 with a 128 MiB long-range window for chunks at or above 8 MiB); remaining whole-file members use level 6, optionally with a trained provider dictionary (`-D`). Chunks never split a record: an oversized single line becomes its own chunk. A versioned JSON manifest records the provider, session identifier, source root, relative paths, raw SHA-256, compressed SHA-256, byte size, mode, nanosecond mtime, last activity, zstd version, per-member recipe (reference relative, dictionary object, or an ordered chunk list), and bundle directory metadata (relative path, mode, nanosecond mtime). Manifests carrying recipes are schema version 2; plain manifests remain version 1, and both are accepted on read. Objects are written to temporary files, fsynced, tested with `zstd -t`, decompressed through SHA-256, and atomically renamed.

An existing object is reused only after proving which recipe reproduces the raw bytes, and the manifest records the recipe that actually verified, so deduplication never invalidates another manifest's decode path. Provider dictionaries are trained from live session sources, stored as raw `.dict` objects in the CAS, and referenced from manifests; reachability keeps a dictionary alive while any manifest references it. A missing or unverifiable dictionary only falls back to plain compression and never blocks archiving.

Manifests live under `~/.local/share/sesh-compresh/archives/manifests`; objects live under the adjacent `objects/sha256` tree. Runtime plans and quarantine journals live under `~/.local/state/sesh-compresh`.

Observer expiry plans select manifests only from the `claude-observer` provider. Archive publication, observer GC, and expiry apply share an app-wide advisory lock backed by POSIX `flock` or Windows kernel byte-range locking. The operating system releases either lock when a process exits or crashes.

CAS validation rejects a symlink or non-directory at the archive objects anchor, CAS root, and every shard parent. Every target is canonicalized, proven to remain under the canonical archive and shard, required to be a regular non-symlink file, and identity-pinned before mutation. Apply precomputes cross-provider reference counts under the app lock, updates them after removed manifests, and checks the count immediately before each object unlink. Shared objects and objects whose identity changed remain untouched.

Plan creation preserves every unexpired plan and retains the newest 32 expired plans. Malformed or externally changed plan files remain untouched.

## Restore contract

Restore recreates every manifest member through a temporary file, verifies the raw digest (per chunk and whole-file for chunked members), restores mode and mtime, fsyncs, and atomically renames it into place. Recorded bundle directories are then recreated with their recorded mode and mtime. Existing destinations cause a hard failure. A caller may restore to the original root or an isolated destination.

## Cleanup contract

The practical profile recognizes only configured cache families with structural evidence: SwiftPM scratch roots, Rust target roots, CMake build trees, named Go caches, and a short set of generated user-temporary outputs. Plans record device, inode, type, size, mtime, marker evidence, and action. Apply revalidates all fields, rejects Git repositories and open files, and preserves metadata in mixed WSMS cache roots.

Standalone files, agent artifacts, session/runtime directories, dirty worktrees, browser state, application support, OrbStack, the Nix store, and unclassified paths stay outside cleanup scope.

## Failure model

The implementation must fail closed for source mutation, insufficient space, zstd failure, digest mismatch, open files, expired plans, identity drift, restore collisions, malformed JSONL or corpus state, incompatible liveness databases, failed open-file enumeration, and interrupted moves. Quarantine recovery restores any moved source whose destination remains absent. A CAS object that fails verification on a deduplication hit is moved aside as a forensic `.corrupt-*` file and rebuilt from its verified source; crash-remnant compression temps in the CAS are collected by observer expiry.

## Acceptance criteria

- Synthetic and copied-session canaries restore byte-for-byte with original metadata.
- Injected failures at each archive transaction state preserve either the source or a verified recoverable archive.
- Cleanup fixtures prove that dirty Git trees, unknown artifact formats, and protected runtime paths survive.
- Observer fixtures prove path portability, reference union, grace/open-file protection, apply-time races, provider-isolated expiry, shared-CAS reachability, and cap enforcement.
- The first live run performs an archive/restore canary before any source removal.
- Final verification reports archive integrity, protected-path checks, reclaimed bytes, and physical free space.
