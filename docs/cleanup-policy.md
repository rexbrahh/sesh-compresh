# Cleanup policy files

A cleanup policy adds exact cache locations to the built-in practical cleanup
profile. It cannot remove, replace, or weaken a built-in detector. If a policy
rule names a path that the practical profile already detects, the built-in
detector remains authoritative.

Pass the canonical absolute policy path when you create a cleanup plan:

```console
$ sesh-compresh clean plan --policy /private/var/tmp/cleanup-policy.json
```

The policy is a UTF-8 JSON object with this exact shape:

```json
{
  "schema_version": 1,
  "kind": "clean-policy",
  "rules": [
    {
      "root": "/private/var/tmp/build-caches",
      "name": "custom-cache",
      "retention_days": 14,
      "markers": ["CACHEDIR.TAG"],
      "action": "delete-tree"
    }
  ]
}
```

Each rule examines only the direct child `root/name`. `root`, `name`, and each
marker are literal values. Patterns, regular expressions, environment-variable
expansion, and hooks are not supported. Each marker must be a direct, regular,
non-symlink file in the candidate. List marker names in sorted, unique order.

`retention_days` is an integer from 0 through 36500. A candidate becomes
eligible only when the newest modification time in its complete no-follow tree
is at least that old. A symlink entry contributes its own modification time.
The scanner does not inspect or age-test the symlink target.

`action` must be `delete-tree` or `prune-mixed-cache`. The mixed-cache action
requires a directory and preserves the practical profile's fixed metadata
names. Git metadata at any depth protects a directory under either action.

## Validation and binding

The application rejects unknown, missing, duplicate, or incorrectly typed JSON
fields. It accepts at most 128 rules and a 64 KiB policy file. The policy must
be a canonical absolute path to a regular, non-symlink, single-link file that
the current user owns. On POSIX systems, another user must not be able to write
the file.

Every root must be an existing canonical directory with the same
ownership and write protections. A rule cannot target a path that contains the
application home, archive, state, or policy file. It also cannot target a path
inside the archive or state directory. Detector targets cannot overlap.

Planning records the canonical policy path and the SHA-256 digest of the exact
file bytes. Apply reloads the policy and verifies both values before open-file
enumeration, after the plan-wide enumeration, and during final candidate
discovery. A policy change aborts before cleanup starts. A candidate marker,
identity, retention time, Git state, or tree-content change during final checks
preserves that candidate.

An exact schema 2 cleanup plan created before policy support has no `policy`
field. Apply treats that legacy shape as built-in-only. Other missing or extra
plan fields remain invalid.
