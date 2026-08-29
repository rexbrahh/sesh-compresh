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
6. **At-rest encryption preserves logical frame identity.** In encrypted mode,
   the CAS file contains an age envelope. The `compressed_sha256` field and the
   two-hash object suffix continue to identify the plaintext zstd frame. A
   reader decrypts first and then verifies that digest before it invokes zstd.
   The root has one immutable encryption recipient, and encrypted mode disables
   dictionaries.

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

Legacy whole-file objects can be upgraded in place with `archive repack`.
Planning validates the complete archive graph and selects raw-hash-only frames
at or above 8 MiB by default. Apply streams decode into
`zstd -19 --long=27 --check -T0`, adopts only smaller frames, and fully decodes
and rehashes each candidate before changing its manifest storage reference.
The digest-bound plan expires after two hours. `archive repack recover` handles
its journal independently of archive-publication recovery. Encrypted archives,
schema conversion, chunking conversion, dictionaries, and reference recipes
are outside this repack path.

### 1.2 Shared trained dictionary

**Status: implemented.** `archive benchmark --provider P` snapshots complete
primary JSONL records and makes a deterministic content-unique train and
holdout split. It compares a temporary candidate with the active dictionary,
or with plain zstd when no dictionary is active. The report charges the full
candidate dictionary size and verifies every holdout decode. It does not
change the CAS or provider pointer.

`archive train-dictionary --provider P` runs the same benchmark. It publishes
the candidate only when its measured byte benefit is greater than
`--minimum-benefit-kib`. It stores the dictionary as a raw `.dict` CAS object
and updates `dictionaries/<provider>.json`. A rejected run leaves the CAS and
pointer unchanged. Training does not delete the prior dictionary. Expiry can
remove that object only after no valid active pointer or immutable manifest
references it.

Members below 1 MiB that have no reference compress with `-D`. The manifest
records the dictionary object per member. A missing or unverifiable dictionary
falls back to plain frames. This fallback can reduce compression but cannot
weaken integrity.

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

**Design discovery:** the same raw bytes can use different references or
dictionaries. Whole-file object names contain both the raw SHA-256 and the
compressed SHA-256, so each frame is independently addressable. A writer tests
only the legacy raw-hash object with the requested recipe. Otherwise, it
compresses the requested recipe and publishes or reuses the exact two-hash
object. It does not scan other variants. Readers continue to accept legacy
raw-hash object names. The manifest records the exact object path, compressed
hash, and recipe.

## Tier 2 — structure (new object granularity)

### 2.1 Record-aligned chunking and incremental archival

**Status: implemented.** Members above 1 MiB split at newline boundaries into
record groups of roughly 1 MiB. Each chunk is a CAS object streamed through
zstd stdin. The manifest records an ordered `{sha256, size}` list per member.
It also records the whole-member raw SHA-256 for the final restore check.

The primary member of an append-only JSONL session can reuse an established
chunk lineage. The writer selects the authoritative latest immutable version.
It proves that the live prefix has the previous size and raw SHA-256. It also
requires the prefix to end at a newline. The writer decodes every inherited
chunk and checks the complete inherited stream against the previous raw
SHA-256.

The appended suffix can contain only complete UTF-8 JSON values. A newline
must terminate each value. The writer compresses only that suffix and copies
the previous ordered chunk descriptors into the new manifest.

A shorter source or a changed prefix stops the archive before quarantine.
An incomplete record, malformed UTF-8, malformed JSON, or a corrupt inherited
object also stops the archive. An unchanged source publishes a new immutable
manifest without publishing a new member object. The first version that
crosses the 1 MiB threshold creates the initial chunk lineage. Prior whole-file
versions retain their existing recipe. Schema 1 and schema 2 readers remain
compatible.

Each member uses exactly one recipe. Large primary members use chunks.
Companions use `--patch-from`. Small primary members can use dictionaries.

Why record-aligned instead of content-defined chunking: a log already
declares its boundaries. For append-mostly data, newline-aligned grouping
captures nearly all of CDC's dedup benefit with no rolling-hash machinery.

- Wins: resumed or restored-then-continued sessions reuse their complete
  verified chunk prefix. Chunk CAS objects also deduplicate repeated content
  within one transcript.
- Manifests using chunks or another recipe use schema version 2. Plain
  manifests use version 1. Readers accept both versions.

`archive schema check` reports manifest and latest-index schema counts. It
also compares each derived latest index with the highest retained version.
The check is read-only and does not create archive or state directories.

`archive schema rebuild-index --yes` rebuilds only the derived latest indexes.
It validates all manifests and existing indexes before the first write. An
unsupported, malformed, or unsafe entry stops the rebuild without mutation.
The rebuild does not rewrite a schema 1 or schema 2 manifest or any CAS object.
It validates the complete index set after publication.

### 2.2 Bounded extraction from independent frames

**Status: implemented.** The schema 2 ordered chunk list is the seek index.
The extractor adds chunk sizes to locate the requested byte range. It decodes
only frames that intersect that range. It verifies each decoded frame's size
and raw SHA-256 before it publishes the selected bytes.

`archive extract MANIFEST --member RELATIVE --output FILE` accepts either
`--offset N --length N` or `--tail-bytes N`. Empty selections publish an empty
file without a frame decode. Small whole-file members support bounded output
through one full-frame decode. Reference-compressed members and large
whole-file members do not support non-empty bounded extraction.

Extraction never replaces an existing output. On POSIX systems, it pins the
output parent with a no-follow directory descriptor and publishes with a
descriptor-relative hard link. The application lock prevents archive expiry
from deleting a selected manifest or object during extraction.

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
3. ~~Tier 2.1~~ — implemented, including incremental JSONL archival.
4. Remaining: Tier 2.2/2.3 opportunistically. Adopt Tier 3 only with a
   demonstrated need and a dedicated inverse-transform test suite.

Every adopted item shipped with: round-trip canaries (byte-for-byte plus
metadata), mixed-store tests (old objects beside new), and an expiry test
proving auxiliary objects stay reachable while referenced.
