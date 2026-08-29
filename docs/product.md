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

All four session providers use one fail-closed bundle scanner. A bundle contains one primary JSONL file and the exact sibling directory with the same stem. The scanner records each nested regular file and each directory, including an empty directory, with its metadata.

Generic archive planning aborts on a symlink, special file, unreadable bundle, or unsafe directory in the source chain. Observer planning protects only the unsafe candidate. Codex date directories organize discovery. The archive does not claim them as bundle members.

## Observer liveness contract

The observer keep-set is the normalized union of every non-null `sdk_sessions.memory_session_id` in the claude-mem SQLite database and every `session_id` present in `*.corpus.json` below the corpora root. Planning accepts only canonical UUID-shaped top-level JSONL names and counts all other names as protected. A candidate bundle includes its primary JSONL and safe regular files under the exact sibling `<uuid>/` directory. Unsafe companion content protects the whole candidate; age, identity, reference, and open-file checks cover every member.

`CLAUDE_CONFIG_DIR` resolves from an explicit CLI argument, the process environment, then `~/.claude`. `CLAUDE_MEM_DATA_DIR` resolves from CLI, environment, its default settings-file fallback, then `~/.claude-mem`. The observer working directory is `<data-dir>/observer-sessions`; Claude's project directory is computed over UTF-16 code units with the SDK's ASCII-alphanumeric sanitization, 200-unit threshold, and signed hash rule.

Plans pin the observer directory's device and inode. Apply validates that directory and every ancestor without following symlinks. It performs one reusable keep-set read and bounded path-filtered `lsof` pass. Immediately before the first source move it repeats a targeted open check followed by a fresh targeted database/corpus reference check. Liveness-source failures abort the remaining run; an individual candidate that becomes referenced, recent, open, missing, or identity-changed is preserved while independent candidates continue.

Local retention holds live in the private state file `holds.json`. The observer API exposes `pin_live_session`, `pin_archive_version`, `list_holds`, and `remove_hold`. A live-session hold binds the `claude-observer` provider to one canonical session UUID. An archive-version hold binds the provider, session identifier, stable session key, version, archive identifier, and manifest path. Each hold stores a required local reason.

Observer planning excludes held live sessions. Apply reads the holds again under the application lock and checks them immediately before the first source move. Archive expiry excludes each held manifest from time-to-live and capacity selection. Objects that a held manifest references remain reachable. If a hold appears after expiry planning, apply rejects the stale selection before deletion.

The hold file has an exact schema and sorted unique hold identifiers. The application accepts only a private, single-link regular file. On POSIX systems, the current user must own the file and its mode must be `0600`. Invalid hold state stops cleanup or retention instead of disabling protection. Removing a hold changes only local policy. It does not delete live or archived data.

Observer liveness enumeration requires `lsof`, which targets macOS and Linux by default. Open-file enumeration uses NUL-terminated fields and decodes documented pathname escapes. Newlines and literal backslashes remain distinct. Containment compares canonical, NFC-normalized, case-folded path components. Same-user processes can ignore advisory locks, so claude-mem publishers should cooperate with the maintenance window; writes after the final checks remain a residual race.

## Archive format

Raw content is stored as zstd frames in a content-addressed object store. Each manifest member is compressed with exactly one recipe, chosen by role and size: bundle companions compress against the bundle's primary member (`--patch-from`); members above 1 MiB split into newline-aligned chunks of roughly 1 MiB, each stored as its own object (zstd level 12, or level 19 with a 128 MiB long-range window for chunks at or above 8 MiB); remaining whole-file members use level 6, optionally with a trained provider dictionary (`-D`). Chunks never split a record: an oversized single line becomes its own chunk. A versioned JSON manifest records the provider, session identifier, source root, relative paths, raw SHA-256, compressed SHA-256, byte size, mode, nanosecond mtime, last activity, zstd version, per-member recipe (reference relative, dictionary object, or an ordered chunk list), and bundle directory metadata (relative path, mode, nanosecond mtime). Manifests carrying recipes are schema version 2; plain manifests remain version 1, and both are accepted on read. Writers create objects in temporary files, fsync them, test them with `zstd -t`, decompress them through SHA-256, and publish them atomically.

Re-archiving an established chunked JSONL primary reuses the authoritative latest version's immutable chunk prefix. Before it creates an object or moves a source, the writer proves the live prefix SHA-256 and newline boundary. It also decodes and rehashes the inherited chunk sequence.

The appended suffix must contain complete UTF-8 JSON values with newline terminators. The writer compresses only the accepted suffix. Truncation, prefix rewrite, an incomplete or malformed record, and inherited-object corruption stop the transaction. Restore concatenates the inherited and new chunks in manifest order. It then verifies the full raw SHA-256. Whole-file versions and both supported manifest schemas retain their existing behavior.

Whole-file object names contain the raw and compressed SHA-256 values. This layout permits independent frames for different recipes. A writer tests only the legacy raw-hash object with the requested recipe. Otherwise, the writer compresses the requested recipe and publishes or reuses the exact two-hash object. The writer does not scan other variants.

## Optional archive encryption

Install the `encryption` extra to add the `keyring` dependency. The `age` and
`age-keygen` executables must also be installed. Enable encryption only on an
empty archive:

```text
sesh-compresh archive encryption enable --recovery-file /offline/path/sesh-compresh.age --yes
```

`age` asks for the recovery-file passphrase on its controlling terminal. The
passphrase and private identity do not appear in command arguments. The
recovery file is mandatory. The command creates it with mode `0600`, writes the
private age identity to an approved operating-system keyring backend, and then
publishes the nonsecret `encryption.json` config. A durable enable intent makes
this sequence resumable after interruption. Run the same enable command with
the same recovery path to finish an interrupted enable.

Encrypted mode binds the archive root to one immutable X25519 recipient.
F16 does not provide key rotation, disable, or migration. Enabling fails when
the archive contains a manifest, CAS entry, dictionary, latest pointer,
quarantine item, restore canary, or portable-import staging item. Dictionaries
and portable export/import remain unavailable in encrypted mode.

Every zstd CAS payload is stored as an authenticated age envelope at its
existing logical CAS path. Before zstd reads a frame, the application decrypts
it to a private state temporary file and verifies the plaintext compressed
SHA-256. A missing key, wrong key, modified envelope, or digest mismatch stops
verify, restore, extraction, and archival. Archival resolves the key before it
creates CAS or quarantine data or moves a source.

Encryption covers CAS payload bytes only. Manifests, indexes, state, filenames,
sizes, timestamps, provider names, archive identifiers, and short-lived
quarantine files remain plaintext. File permissions remain part of the privacy
boundary.

Check key availability with `archive encryption status`. To perform an offline
recovery drill:

1. Copy the recovery file and archive to an offline test account.
2. Install the encryption extra, `age`, and `age-keygen`.
3. Run `archive encryption restore-key --recovery-file PATH --yes` and enter the
   recovery passphrase.
4. Run `archive verify`.
5. Restore one selected manifest to an empty test destination and compare its
   expected raw SHA-256.

Keep the recovery file offline and separate from the archive. Losing both the
keyring entry and this file makes encrypted CAS payloads unrecoverable.

Each archive operation publishes a new immutable point-in-time manifest. A stable session key and monotonic version ordinal identify related versions. The latest pointer lives in private state under `latest`. It resolves the highest retained ordinal. Recovery repairs the pointer after a partial publication, and expiry repoints or removes it after deleting versions. Immutable manifests remain authoritative if the derived pointer is missing or invalid. The narrow exception is `archive repack`: after proving byte-exact identity, it may atomically replace only a whole-file member's `object` and `compressed_sha256` storage fields. Archive identity, manifest path, timestamps, schema, and every logical metadata field remain unchanged.

`archive list` filters by provider, session identifier, `archived_at` UTC date, and version ordinal. It sorts by activity, archive time, raw bytes, compression ratio, or version. Results use descending order by default. Every order has deterministic identity tie-breakers, and `--reverse` selects ascending order.

Each result includes both timestamps, both byte counts, and the compression ratio. It also includes the stable session key, version ordinal, and archive identifier. Compressed member bytes count each exact zstd object once and exclude shared dictionary bytes.

JSON output retains the `manifests` path list and adds structured `archives` records.

Listing holds the application lock while it validates owned manifest locations and CAS frames. It validates each shared CAS object once per command.

`archive extract MANIFEST --member RELATIVE --output FILE` extracts an exact
byte selection. The command requires either `--offset N --length N` or
`--tail-bytes N`. It rejects incomplete or mixed selectors. The manifest path,
member name, and output path are exact values. The command does not search or
infer these values.

For schema 2 chunked members, the ordered chunk sizes form a seek index. The
extractor decodes only frames that intersect the selection. It verifies the
complete decoded size and raw SHA-256 of each selected frame. A small
whole-file member requires one full-frame decode. A non-empty selection from a
reference-compressed member or large whole-file member fails. An empty
selection decodes no frame.

Extraction holds the application lock from manifest validation through output
publication. It never replaces an output path. POSIX publication pins a
canonical, non-symlink parent directory descriptor and uses a no-follow,
no-replace hard link. A parent swap stops publication and removes the output
from the displaced directory. File and directory sync failures stop successful
completion.

Verify, restore, statistics, and expiry use one strict manifest validator. It validates the supported schema, exact object shape, timestamps, paths, metadata types, hashes, recipes, chunks, and directory records before a reader uses them. Malformed input returns a controlled validation error.

`archive schema check` is read-only. It reports schema counts, malformed or
unsupported entries, and exact latest-index currentness. A latest index is
current only when it names the highest retained version for its provider and
stable session key. The check does not create missing roots.

`archive schema rebuild-index --yes` is the only schema repair command. It
holds the application lock. It validates all manifests and indexes before its
first mutation. It atomically publishes current-schema indexes. It removes
only valid derived indexes that have no retained manifest. It then validates
the complete result.

A malformed, unsupported, unknown, or unsafe entry stops the rebuild before
mutation. The command never rewrites supported schema 1 or schema 2 manifests.
It also leaves CAS objects and source data unchanged. You can retry an
interrupted rebuild. Every successful retry syncs the latest-index directory,
even when all index payloads are already current.

`archive verify` stops at the first invalid manifest. `archive verify
--continue` first selects every manifest. It then verifies each selected
manifest and reports all expected operational failures in one result. The
result includes selected, verified, failed-manifest, and verified-file counts.
The command returns status 1 when a manifest fails.

Archive reports logical source bytes separately from unique compressed member bytes. A CAS inventory reports all new durable objects and the allocated-block change. This count includes canary and protected-at-final-check frames. The report also includes the signed free-space change on the archive filesystem. Reused member-object counts and dictionary object bytes remain separate. `reclaimed_bytes` names logical compression savings for compatibility. It does not measure physical space.

## Maintenance history

Successful primitive mutations append one immutable event under the private
state directory. Archive apply, direct archive, archive repack, observer
garbage collection, dictionary promotion, archive expiry, cleanup apply,
cleanup undo, and cleanup expiry produce events. The `maintain` command does not produce another event.
It uses the events from the primitive operations that it calls.

Each event keeps logical archive bytes, logical reclamation, allocated-byte
change, and observed free-space change in separate signed fields. History
deduplicates content-addressed objects by their stable identity before it
computes unique bytes saved. It reports UTC provider trends and ranks source
growth from the first and latest archived sizes.

History stores domain-separated SHA-256 identifiers for sources and objects.
It does not store their paths. The strict reader accepts only current-user,
single-link regular event files. POSIX event files must have mode `0600`.
The event identifier must match its canonical UTC timestamp.

Run `sesh-compresh history` to show the local aggregate. Use `--top N` to set
the number of ranked growth sources. A history append failure does not change a
completed mutation into a failed mutation. The operation result includes
`history_recorded: false` and a warning in that case.

Directory-open and directory-sync failures stop successful completion. The writer syncs both parents of a source-to-quarantine rename. If manifest publication succeeds but its directory sync fails, the journal keeps the archive recoverable. Only `EINVAL`, `ENOTSUP`, or `EOPNOTSUPP` from a directory `fsync` indicate an unsupported filesystem operation and permit the operation to continue.

A two-hash object's compressed hash suffix must match its bytes. A mismatch stops the operation without moving or replacing the object. Manifests record the exact object path and verified recipe. Readers continue to accept legacy raw-hash object names.

Dictionary benchmarking snapshots complete primary JSONL files. It uses a
deterministic content-unique train and holdout split. It compares a temporary
candidate with the current compression recipe. The measurement charges the
candidate dictionary bytes and verifies each holdout decode. `archive
benchmark` changes no archive data.

Training publishes only when the measured benefit exceeds the configured
threshold. A rejected training run leaves the CAS and provider pointer
unchanged. The application lock covers benchmarking, dictionary publication,
and pointer publication. The CAS stores each dictionary as a raw `.dict`
object.

Training retains the prior object. Expiry removes it only when no valid active
provider pointer or retained immutable manifest references it. A missing or
unverifiable dictionary only falls back to plain compression. It never blocks
archiving.

Manifests live under `~/.local/share/sesh-compresh/archives/manifests`; objects live under the adjacent `objects/sha256` tree. Runtime plans, quarantine journals, and the independent repack journal live under `~/.local/state/sesh-compresh`.

Configured roots must be absolute. Discovery stores canonical paths. Before a command writes, it validates every tool-owned anchor as a real directory with no symlinked ancestor. This check covers archive, state, manifest, provider, CAS, plan, and quarantine anchors. It checks every existing dynamic provider, shard, and quarantine-run anchor in one read-only pass. After structural validation, it creates missing anchors and sets each tool-owned anchor to `0700` on POSIX systems.

`doctor` checks `zstd`, `lsof`, private directory anchors, application-lock acquisition, all manifests, and archive and cleanup quarantine journals. It also reports the user scheduler state. An absent scheduler is informational. An installed scheduler must have a valid maintenance command and interval and must be active. The command reports all results and exits with status 1 when a required check fails.

`scheduled-maintain` uses the same observer maintenance primitive as
`maintain --yes`. It publishes one private, bounded event with fixed counts and
reason codes. The event omits paths, session identifiers, plan identifiers, and
exception text. Optional native notifications use the same sanitized event and
do not invoke a shell. Their result uses a separate immutable record. The
complete schedule and failure contract is in
[Schedule observer maintenance](scheduling.md).

Expiry plans select one provider at a time. `archive expire plan` supports Claude, Codex, and archived Codex manifests. `observer expire plan` remains isolated to `claude-observer`. Plan creation is dry-run only. The plan filename binds the exact reviewed JSON.

Apply rejects edited policy or selection data and recomputes current eligibility before deletion. It removes a CAS object only when no retained manifest or valid dictionary pointer references it. Archive publication, observer GC, and expiry apply share an app-wide advisory lock backed by POSIX `flock` or Windows kernel byte-range locking. The operating system releases either lock when a process exits or crashes.

Quarantine recovery requires POSIX fd-relative directory operations and `O_NOFOLLOW`. Recovery canonicalizes the recorded source root once and then holds the target directory descriptor. New journals bind that target's path, device, and inode.

An exact published manifest causes recovery to sync its parent and finish quarantine cleanup only when no destination conflict exists. Recovery does not restore source files in this state. The app lock coordinates cooperating Sesh Compresh processes only. Another same-user process can ignore the lock and change tool-owned state.

CAS validation rejects a symlink or non-directory at the archive objects anchor, CAS root, and every shard parent. Every target is canonicalized, proven to remain under the canonical archive and shard, required to be a regular non-symlink file, and identity-pinned before mutation. Apply precomputes cross-provider reference counts under the app lock, updates them after removed manifests, and checks the count immediately before each object unlink. Shared objects and objects whose identity changed remain untouched.

Plan creation uses a timestamp and random identifier, then publishes each plan atomically without replacement. Concurrent runs preserve distinct plans. Pruning preserves every unexpired plan and retains the newest 32 expired plans. Malformed or externally changed plan files remain untouched.

`pressure plan` measures free space on the filesystem that contains the
configured home directory. At or above the trigger threshold, it creates no
plan. Below the trigger, it creates independent archive and cleanup plans. Each
plan contains only complete source trees on the measured filesystem. The command reports the
target deficit but does not predict reclaimed space.

`pressure` has no apply command. Users must review and apply each child plan
through its existing command and explicit `--yes` option. Cleanup apply moves
data to same-filesystem quarantine and does not reclaim physical space. The
complete procedure is in [Plan work during low disk space](pressure.md).

Pressure planning preallocates an unguessable identifier for each child plan.
It publishes the cleanup plan first. A failure result reports each child file
that became visible before the failure. The command accepts only the exact
preallocated path with the expected kind and identifier. It returns status 1
and sets `partial: true` when at least one child exists. Each disclosed child
remains independently reviewable and applicable.

`plan show` normalizes archive, cleanup, observer, and expiry plans. Text and JSON output list each candidate's path, reason, marker, action, and bytes. It also lists skipped or protected items and gives a concise apply summary. Missing or malformed plan fields produce a controlled error.

## Restore contract

Restore opens the selected manifest without following a final symlink and verifies that exact snapshot. A store-owned manifest must match its `manifests/<provider>/<archive_id>.json` location. An explicit external regular-file manifest path remains supported. Restore rechecks every selected snapshot after complete namespace preflight. A manifest change stops the restore before its first destination write.

Restore opens the destination from the filesystem root through no-follow directory file descriptors. It keeps the verified temporary-file descriptor through no-clobber publication. Immediately before publication, the temporary path must identify that open regular file. Immediately after publication, the target must identify the same file.

Restore rereads the retained descriptor and proves its exact size and raw SHA-256. It then applies metadata and syncs the file. Before temp-path cleanup, restore repeats the no-follow identity check. A foreign replacement remains untouched, and restore syncs the parent for the verified target. Restore never removes a mismatched target.

A replacement symlink cannot redirect a restore into its target. Restore checks that each open directory remains reachable through its original parent before and after publication. A directory rename during publication stops the operation. The displaced original directory can retain the verified no-clobber output. A concurrent foreign replacement remains untouched. A same-user rename after restore returns is outside the operation boundary.

Restore verifies raw digests, preserves mode and mtime, and syncs every file and changed directory. Existing destinations cause a hard failure. A caller may restore to the original root or an isolated destination.

`archive restore MANIFEST` accepts an exact manifest path or archive identifier. `--member RELATIVE` restores only that exact member and its recorded parent directories. A reference-compressed member decodes its dependency in private temporary state but does not restore that dependency.

Batch restore requires `--provider`, `--from-date`, `--to-date`, and `--destination`. It selects `archived_at` UTC dates and includes both boundary dates. Each batch version restores below `<destination>/<provider>/<archive_id>`. Before the first destination write, batch restore verifies every selected manifest snapshot and preflights the complete target namespace. A concurrent collision or directory-binding change stops the affected write without following a replacement symlink.

Before the first live source move, the shared archive transaction tests a synthetic file. It uses the real CAS writer, manifest verifier, and restore path. It compares the restored bytes, mode, and modification time. It then records a versioned success marker atomically in private state. The marker binds the proof to the current archive implementation and codec path, digest, and version. The transaction trusts only an exact-typed, regular, single-link marker that the current user owns and that has mode `0600`.

An absent or invalid marker reruns the proof. A failed proof leaves the marker invalid and blocks source removal.

## Portable archive contract

`portable export` writes one deterministic `ZIP_STORED` artifact without
replacing its destination. Its canonical index binds every selected manifest
and its exact reachable whole-file, chunk, and dictionary objects. Export
keeps the verified temporary-file descriptor through publication. It checks
the temporary path before the link and the destination after the link. It then
checks the retained size, SHA-256, and ZIP graph. It does not remove a foreign
replacement.

`portable import plan` rejects extra, missing, reordered, compressed,
non-canonical, duplicated, colliding, or unsafe ZIP entries. It extracts the
complete graph into private staging and uses the normal manifest verifier
before it publishes the two-hour plan. The plan binds the artifact identity,
artifact SHA-256, canonical index digest, bundle identity, and graph counts.

`portable import apply PLAN --yes` verifies that binding again. It refuses a
staging directory that belongs to a different plan, even when both plans have
the same run identifier. Publication never replaces a target. An exact target
is reusable. A different target stops the import. The publisher retains each
temporary-file descriptor and verifies its no-follow identity and content
before and after linking.

Import publishes all objects before its manifests. A durable publishing intent
hides the complete selected manifest set from archive enumeration until every
manifest exists. The same rule protects direct paths inside the owned manifest
store. External manifest paths remain supported. Readers compare a monotonic
visibility generation before and after their check and retry a concurrent
transition.

The intent then changes to committed in one atomic write.
Latest-index updates follow that commit. Recovery syncs the live parent of an
exact reused object or manifest before it commits the intent.

`portable import recover --yes` retries publishing, latest-index updates, and
cleanup under the application lock. Cleanup removes staged trees before it
removes the cleanup intent. A failure therefore retains enough durable state
for the next recovery. A process that ignores the application lock can still
cause a safe conflict or denial of service.

## Cleanup contract

The practical profile recognizes only configured cache families with structural evidence: SwiftPM scratch roots, Rust target roots, CMake build trees, named Go caches, and a short set of generated user-temporary outputs. Plans record device, inode, type, allocated size, mtime, marker evidence, action, and a no-follow tree fingerprint. The fingerprint binds path metadata and descendant ctime. It also binds the content of a root-level file. Apply repeats positive-allowlist discovery after its final open-file check. A marker or descendant change preserves the candidate.

An optional strict JSON policy can add exact direct-child cache detectors to the practical profile. Each rule binds a canonical source root and one literal child name. It also binds a day-based retention period, literal direct-file markers, and one existing cleanup action. Policies cannot remove or override built-in detectors. Unknown fields, duplicate keys, unsafe paths, patterns, hooks, and incorrect types fail closed before open-file enumeration. Eligibility uses the newest modification time in the complete no-follow candidate tree.

The plan records the canonical policy path and SHA-256 digest of its exact bytes. Apply reloads and verifies that binding before and after its plan-wide open-file check, then again during final candidate discovery. Policy drift aborts before cleanup starts. Candidate drift preserves the affected candidate. The complete file format and safety constraints are in [Cleanup policy files](cleanup-policy.md).

Cleanup renames approved data into a private hidden sibling quarantine on the same filesystem. Before any move, it publishes an immutable intent and a content-bound journal. `clean undo` restores only identity-matching entries whose destinations remain safe. It preserves planned entries that apply skipped after a later drift. Apply reports quarantined bytes as recoverable, not reclaimed space.

`clean expire plan` selects journals older than the retention period without deleting them. Only an explicit `clean expire apply --yes` removes quarantined data and reports reclaimed bytes. Expiry uses identity-bound deletion staging and durable completion records, so an interrupted recursive delete can resume without accepting replacement data. The expiry filename binds the reviewed policy and selection.

Git metadata at any depth protects the candidate. The Git-name check is case-insensitive. The scan does not follow symlink directories. Apply preserves metadata in mixed WSMS cache roots.

A SwiftPM candidate requires regular, non-symlink `workspace-state.json` and `build.db` files. A Rust candidate requires regular, non-symlink `.rustc_info.json` and `CACHEDIR.TAG` files. Final positive-allowlist discovery rechecks each pair after the open-file check.

Cleanup uses absolute `TMPDIR` or Python's current platform selection for its temporary root. It uses absolute `DARWIN_USER_CACHE_DIR` or `getconf` for the Darwin cache root. It has no account-specific fallback path.

Standalone files, agent artifacts, session/runtime directories, dirty worktrees, browser state, application support, OrbStack, the Nix store, and unclassified paths stay outside cleanup scope.

## Failure model

The implementation must fail closed for source mutation, insufficient space, zstd failure, digest mismatch, open files, expired plans, identity drift, restore collisions, malformed JSONL or corpus state, incompatible liveness databases, failed open-file enumeration, and interrupted moves. Before manifest publication, quarantine recovery restores a moved source only when its destination remains absent. If recovery finds an exact published manifest and no destination conflict, it removes the quarantine state without restoring the source. A two-hash object whose bytes do not match its compressed hash suffix remains unchanged and stops the operation. A legacy frame that the current recipe cannot decode also remains unchanged. Observer expiry collects crash-remnant compression temporary files in the CAS.

## Acceptance criteria

- Synthetic and copied-session canaries restore byte-for-byte with original metadata.
- Injected failures at each archive transaction state preserve either the source or a verified recoverable archive.
- Cleanup fixtures prove that dirty Git trees, unknown artifact formats, and protected runtime paths survive.
- Observer fixtures prove path portability, reference union, grace/open-file protection, apply-time races, provider-isolated expiry, shared-CAS reachability, and cap enforcement.
- The first live run performs an archive/restore canary before any source removal.
- Final verification reports archive integrity, protected-path checks, reclaimed bytes, and physical free space.
