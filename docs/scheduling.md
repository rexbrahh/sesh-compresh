# Schedule observer maintenance

Run a dry maintenance cycle before you install a schedule:

```sh
sesh-compresh maintain
```

Review the returned observer and expiry plans. Installation schedules this command:

```sh
/absolute/path/to/sesh-compresh --json scheduled-maintain
```

The scheduled command applies the same maintenance cycle as `maintain --yes`.
It also verifies retained archives and publishes one sanitized event.

## Install

Install the user schedule with a one-hour interval:

```sh
sesh-compresh schedule install
```

Add `--notify` to send a local notification after each scheduled run:

```sh
sesh-compresh schedule install --notify
```

Use `--interval-seconds` to select a different positive interval. Use
`--executable` if `sesh-compresh` is not available on `PATH`:

```sh
sesh-compresh schedule install \
  --interval-seconds 1800 \
  --executable /absolute/path/to/sesh-compresh
```

The executable must be an absolute, normalized executable file. The systemd
backend accepts only ASCII letters, digits, slashes, periods, underscores, plus
signs, and hyphens in the unquoted executable path. An interval must be from 1
to 2147483647 seconds.

On macOS, installation writes
`~/Library/LaunchAgents/com.local.sesh-compresh.plist` and bootstraps the
`com.local.sesh-compresh` user agent. On Linux, installation writes
`~/.config/systemd/user/sesh-compresh.service` and
`~/.config/systemd/user/sesh-compresh.timer`. It reloads the user manager,
enables the timer, and starts it.

Definitions use mode `0600`. Their final directory uses mode `0700`. Writes are
atomic and sync the definition directory. Installation rejects a symlink,
non-regular definition, wrong owner, non-private mode, or non-canonical
definition. It repairs a partial systemd installation only when each existing
definition is canonical.

Repeated installation with the same command and interval does not rewrite a
definition. It repairs an inactive launchd agent or a disabled or inactive
systemd timer. A changed definition stops the old schedule before it publishes
and loads the replacement.

## Status

Show the backend, installed command, command availability, interval,
definitions, and live state:

```sh
sesh-compresh schedule status
sesh-compresh --json schedule status
```

Status does not change state. It validates the exact owned definition. It
rejects a partial or edited installation. An absent definition reports
`installed: false`.

The status includes `active`, `enabled`, and
`command_available`. It also includes `event_mode` and `notify`. The first two
fields report the current user-manager state. `command_available` becomes false
after the executable moves, disappears, or loses executable permission.

An exact legacy definition for `maintain --yes` remains valid for status and
uninstall. The next install replaces it with the event-mode command.

## Events and notifications

Each scheduled run writes one JSON event below
`~/.local/state/sesh-compresh/events`. A notification-enabled run writes one
separate notification-result record. The directory uses mode `0700`. Its files
use mode `0600`. Sesh Compresh keeps the newest 100 recognized events and their
result records.

An event contains fixed counts for archived sessions, protected skips, removed
manifests, and removed objects. Its reason codes are `success`, `protected`,
`corruption`, `low_space`, and `failure`. The low-space signal means that the
configured home filesystem has less than 5 GiB free after maintenance.

The default event does not contain source paths, archive paths, quarantine
paths, plan paths, session identifiers, or exception text. The same event data
creates the notification summary.

On macOS, notification mode runs `osascript` with an argument list. On Linux,
it runs `notify-send` with an argument list. It never starts a shell. An
unsupported platform or missing notifier records `unavailable`. A notifier
execution failure records `failed`. The maintenance operation does not run a
second time.

## Uninstall

Stop and remove the user schedule:

```sh
sesh-compresh schedule uninstall
```

Uninstall validates an existing definition before it changes scheduler state.
It unloads or disables the schedule. It removes only the two documented systemd
files or the one documented launchd file. It then syncs the parent directory.
The executable does not need to remain present. Repeated uninstall is safe and
reports `installed: false`.

## Failure behavior

A scheduler command failure returns a nonzero CLI status and keeps its error
text. A failed atomic replacement preserves the previous definition. If a
scheduler load fails after publication, a later install command repairs the
definition.

Scheduled maintenance publishes its immutable base event before it invokes a
notifier. It then publishes an immutable notification-result record. It prunes
old events only after both records are durable. A base publication failure does
not send a notification or remove old event history. A notification-result
publication failure leaves the base event at `notification: pending`. It does
not prune old history or rerun maintenance.

Live-state queries accept only the backend's documented absent, disabled, or
inactive results. A permission error, execution error, or unexpected diagnostic
stops status, installation, or removal. The command preserves every definition.

The application lock serializes maintenance operations for one state root. A
same-user process can ignore this advisory lock. Coordinate other writers with
the maintenance window.
