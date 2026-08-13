# Plan work during low disk space

Use `pressure plan` to measure the filesystem that contains the configured home
directory. Set a trigger threshold and a target threshold:

```sh
sesh-compresh pressure plan \
  --trigger-free-gib 10 \
  --target-free-gib 20
```

The target must be greater than or equal to the trigger. Each GiB value must
resolve to a non-negative whole byte count. The command rejects negative,
infinite, inexact, and nonnumeric values.

The command does not create a plan when free space is equal to or greater than
the trigger. Below the trigger, it creates one archive plan and one cleanup
plan. Both plans include only complete source trees on the measured filesystem. Use
`--policy ABSOLUTE_PATH` to add the validated cleanup policy to the cleanup
plan.

The result reports the measured free space and the deficit from the target. It
also reports both plan paths and their candidate counts. Archive logical bytes
and cleanup quarantine candidate bytes are not a free-space forecast.

`pressure` has no apply command. Review each result with `plan show`. Apply an
archive or cleanup plan only through its existing command and required `--yes`
option. Remeasure free space after each apply. Cleanup apply moves data to a
same-filesystem quarantine, so it does not reclaim physical space. Only a later
explicit cleanup-expiry apply can reclaim those bytes.

The command preallocates an unguessable identifier for each child plan. It
creates the cleanup plan first. A failure result reports every child file that
the creator published before it failed. The command accepts only the exact
preallocated path with the expected plan kind and identifier. It returns status
1 and sets `partial: true` when at least one child exists. Each disclosed plan
remains valid and reviewable.
