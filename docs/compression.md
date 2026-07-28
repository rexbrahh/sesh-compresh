# Log-Structured Compression Roadmap

This document describes how sesh-compresh adopts stronger compression for
append-only JSONL transcripts without weakening the byte-exact restoration
contract in [product.md](product.md). It is a design contract for future
implementation, ordered by return on investment.

## Invariants

These rules bind every compression path, present and future:

1. **Byte-exact restoration is non-negotiable.** The archive is the system of
   record for possibly irreplaceable transcripts. Any transform that cannot
   reproduce the original bytes belongs in a derived layer above the archive,
   never inside it.
2. **Verification is codec-agnostic.** The existing pipeline proves
   losslessness per object before any source mutation: raw SHA-256, compress,
   fsync, `zstd -t`, full decode rehashed against the raw digest, atomic
   rename, then quarantined source move. New codec paths must reuse this
   proof; they may not weaken it.
3. **Readers tolerate unknown manifest fields.** Objects written by older
   versions remain restorable forever. New per-object codec parameters are
   recorded in the manifest; `compressed_sha256` already pins exact frame
   bytes, so mixed-format object stores are valid.
4. **Auxiliary inputs are content-addressed.** Any artifact a decompressor
   needs (dictionaries, side tables) is stored as a CAS object and referenced
   from the manifest, so reachability GC treats it as a root-held reference
   and restore can fetch it deterministically.
5. **Fail closed.** A transform that errors, a dictionary that is missing, or
   a digest that mismatches aborts before source mutation, exactly as zstd
   failures do today.

## Data profile

Session transcripts are append-only JSONL with timestamp-monotonic records.
Their redundancy has three scales:

- **Intra-record:** identical key scaffolding (`sessionId`, `parentUuid`,
  `cwd`, `version`, `type`, ...) on every line.
- **Intra-file:** repeated system prompts, tool schemas, and context blocks,
  often megabytes apart within one large transcript.
- **Cross-file:** near-identical scaffolding and prompts across all sessions;
  resumed or copied sessions share long byte prefixes.

zstd at level 6 with its default window captures the first scale and part of
the second. The roadmap below captures the rest.

## Tier 1 — codec parameters (no format change)

### 1.1 Higher effort and long mode for large inputs

**Status: implemented.** Compression effort adapts to unit size. Note that
Tier 2.1 redefined the units: whole-file members are all sub-1 MiB and use
`-6`; chunked members compress each ~1 MiB chunk at `-12`; an oversized
single-record chunk at or above 8 MiB uses `-19 --long=27`. Window log 27
stays within the zstd CLI's default decode memory limit, so restore and
verify need no extra flags for long-mode frames.

### 1.2 Shared trained dictionary

**Status: implemented.** `archive train-dictionary --provider P` samples the
provider's live source roots and stores the dictionary as a raw `.dict` CAS
object plus a `dictionaries/<provider>.json` pointer. Members below 1 MiB
that have no reference compress with `-D`; the manifest records the
dictionary object per member, and reachability GC keeps it alive while any
manifest references it (the orphan sweep accepts both `.zst` and `.dict`).
A missing or unverifiable dictionary falls back to plain frames — fail-open
on ratio, never on integrity.

- Expected gain: 2–5x better ratio on files under ~50 KiB (short sessions,
  observer transcripts, small companions); modest on large files whose window
  already covers their redundancy.
- Prerequisite: measure the real corpus file-size distribution first. If the
  bytes are dominated by multi-MB sessions, the win is small.

### 1.3 Bundle reference compression (`--patch-from`)

**Status: implemented.** Every bundle member after the primary compresses
with the primary as its reference; the manifest records the reference
relative per member. Restore and verify decode in manifest order and fail
closed on forward references.

**Design discovery:** because the CAS names objects by raw content hash, the
same bytes could be requested under different recipes at different times. The
resolution: an existing object is reused only after probing which recipe
reproduces the raw bytes (plain, then reference, then every known provider
dictionary), the reused object keeps its original recipe, and the manifest
records the recipe that actually verified. Only an object no known recipe
can decode is quarantined as `.corrupt-*` and rebuilt, since every manifest
referencing it was already failing verification.

## Tier 2 — structure (new object granularity)

### 2.1 Record-aligned chunking and incremental archival

**Status: implemented (chunking and prefix dedup; incremental archival remains
out of scope).** Members above 1 MiB split at newline boundaries into record
groups of roughly 1 MiB. Each chunk is a CAS object streamed through zstd
stdin; the manifest records an ordered `{sha256, size}` list per member, and
the whole-member raw SHA-256 is retained for the final restore check.
Division of labor, exactly one recipe per member: chunks for large members,
`--patch-from` for companions, dictionaries for small members.

Why record-aligned instead of content-defined chunking: a log already
declares its boundaries. For append-mostly data, newline-aligned grouping
captures nearly all of CDC's dedup benefit with no rolling-hash machinery.

- Wins: resumed or restored-then-continued sessions dedup their entire
  prefix; chunk CAS objects dedup even within a single repetitive transcript.
- Manifests using chunks (or any recipe) are schema version 2; plain
  manifests stay version 1 and both are accepted on read.
- Deferred follow-up: partial-session incremental archival (appending new
  record groups to an existing archive) is the natural consumer of this
  structure.

### 2.2 Seekable frame format

The zstd seekable format (independent frames plus a seek table) gives random
access into a transcript, so tooling can read the tail of a session without
decoding the whole object. Orthogonal to 2.1; optional; slight overhead.

### 2.3 Solid bundles

Archive each bundle as one solid stream (tar of members, single frame).
Captures cross-member redundancy without per-member reference bookkeeping.

- Expected gain: +10–30% when companions are numerous and small.
- Cost: per-file CAS granularity is lost; per-member digests in the manifest
  still prove byte-exactness after decode-and-split, so the trust model
  holds.
- Status: deferred unless companion overhead is measured to matter.

## Tier 3 — bijective transcodes (deferred)

A *bijective* pre-transform preserves byte-exactness: transcode, compress,
verify; on restore, decompress, inverse-transcode, then verify against the
original raw digest. The constraint is severe: JSON parse-and-reserialize is
not byte-stable (whitespace, key order, number formatting, escapes), so every
transform must operate at tokenizer level, rewriting only targeted tokens and
preserving all other bytes.

- **UUID dictionary:** map each distinct 36-byte UUID to a varint index into
  a per-object side table; `parentUuid` chains usually reference the previous
  record's `uuid` and code as back-references. Maybe +10–20% on chat-dense
  transcripts.
- **Timestamp deltas:** monotonic ISO-8601 strings become base plus varint
  deltas with a format template. Low single-digit percent; zstd already eats
  the static prefix.
- **Canonical base64 decode:** decode embedded base64 blobs to binary before
  compression (flat 25% on that content), reversible only when the original
  encoding is canonical; per-blob check with passthrough fallback.

Every transcode is a new bug class and a new inverse to maintain. The
verify-then-mutate pipeline fails closed on transform bugs, but at
single-workstation scale the marginal ratio does not pay for the complexity.
These are documented so the design space is explicit, not because they are
recommended.

## Non-goals

Semantic or lossy transforms inside the store: columnar transposition,
canonical JSON reserialization, record-level delta against schema inference,
payload deduplication by meaning. All are legitimate as derived, rebuildable
artifacts above the archive (claude-mem's own corpora are an existence
proof). None may touch the system of record.

## Adoption order

1. ~~Tier 1.1~~ — implemented (adaptive per-unit effort).
2. ~~Tier 1.2~~ / ~~1.3~~ — both implemented; every member carries exactly
   one recipe (chunks, reference, dictionary, or plain).
3. ~~Tier 2.1~~ — implemented, minus incremental archival.
4. Remaining: Tier 2.2/2.3 opportunistically; incremental archival as the
   Tier 2.1 follow-up; Tier 3 only with a demonstrated need and a dedicated
   inverse-transform test suite.

Every adopted item shipped with: round-trip canaries (byte-for-byte plus
metadata), mixed-store tests (old objects beside new), and an expiry test
proving auxiliary objects stay reachable while referenced.
