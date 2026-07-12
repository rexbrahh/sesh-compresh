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

## Retention policy

- claude-mem observer sessions: archive after 7 complete days of inactivity.
- ordinary Claude and Codex sessions: archive after 30 complete days of inactivity.
- activity comes from the greatest valid top-level JSONL `timestamp` in the complete session bundle.
- `~/.claude-mem` databases, vector indexes, logs, corpora, and runtime state are outside archive scope.

## Archive format

Raw files are stored as zstd frames in a content-addressed object store. A versioned JSON manifest records the provider, session identifier, source root, relative paths, raw SHA-256, compressed SHA-256, byte size, mode, nanosecond mtime, last activity, and zstd version. Objects are written to temporary files, fsynced, tested with `zstd -t`, decompressed through SHA-256, and atomically renamed.

Manifests live under `~/.local/share/sesh-compresh/archives/manifests`; objects live under the adjacent `objects/sha256` tree. Runtime plans and quarantine journals live under `~/.local/state/sesh-compresh`.

## Restore contract

Restore recreates every manifest member through a temporary file, verifies the raw digest, restores mode and mtime, and atomically renames it into place. Existing destinations cause a hard failure. A caller may restore to the original root or an isolated destination.

## Cleanup contract

The practical profile recognizes only configured cache families with structural evidence: SwiftPM scratch roots, Rust target roots, CMake build trees, named Go caches, and a short set of generated user-temporary outputs. Plans record device, inode, type, size, mtime, marker evidence, and action. Apply revalidates all fields, rejects Git repositories and open files, and preserves metadata in mixed WSMS cache roots.

Standalone files, agent artifacts, session/runtime directories, dirty worktrees, browser state, application support, OrbStack, the Nix store, and unclassified paths stay outside cleanup scope.

## Failure model

The implementation must fail closed for source mutation, insufficient space, zstd failure, digest mismatch, open files, expired plans, identity drift, restore collisions, malformed JSONL, and interrupted moves. Quarantine recovery restores any moved source whose destination remains absent.

## Acceptance criteria

- Synthetic and copied-session canaries restore byte-for-byte with original metadata.
- Injected failures at each archive transaction state preserve either the source or a verified recoverable archive.
- Cleanup fixtures prove that dirty Git trees, unknown artifact formats, and protected runtime paths survive.
- The first live run performs an archive/restore canary before any source removal.
- Final verification reports archive integrity, protected-path checks, reclaimed bytes, and physical free space.
