# storage-safeguard

`storage-safeguard` is a local, dry-run-first CLI for two jobs:

- verified zstd archiving and restoration of inactive Claude and Codex sessions;
- deletion of narrowly allowlisted build and test caches after an immutable plan is reviewed.

It never uploads data. See [docs/product.md](docs/product.md) for the safety and data-format contract.

```sh
PYTHONPATH=src python3 -m storage_safeguard audit
PYTHONPATH=src python3 -m storage_safeguard archive plan
PYTHONPATH=src python3 -m storage_safeguard clean plan --profile practical
```

