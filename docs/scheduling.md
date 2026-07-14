# Scheduling observer maintenance

Run `sesh-compresh maintain` manually first. It creates immutable plans and reports candidates without mutation. Once the paths and policy look correct, schedule `sesh-compresh --json maintain --yes`; any failed liveness input or integrity check produces a non-zero exit.

Use an absolute executable path in schedulers. A pipx installation is convenient:

```sh
pipx install /path/to/sesh-compresh
command -v sesh-compresh
```

## macOS launchd

Save this as `~/Library/LaunchAgents/com.local.sesh-compresh.plist`, replacing the executable and log paths, then load it with `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.local.sesh-compresh.plist`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.local.sesh-compresh</string>
  <key>ProgramArguments</key><array>
    <string>/absolute/path/to/sesh-compresh</string>
    <string>--json</string><string>maintain</string><string>--yes</string>
  </array>
  <key>StartInterval</key><integer>3600</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>/absolute/path/to/sesh-compresh.log</string>
  <key>StandardErrorPath</key><string>/absolute/path/to/sesh-compresh.log</string>
</dict></plist>
```

## cron or systemd

An hourly cron entry is sufficient because the default grace window is one hour:

```cron
17 * * * * /absolute/path/to/sesh-compresh --json maintain --yes >>/absolute/path/to/sesh-compresh.log 2>&1
```

For systemd, use the same command in a user service and pair it with an hourly `OnCalendar=` timer. Apply cycles for one state root serialize through a kernel-owned advisory lock (`flock` on POSIX and a one-byte `msvcrt` lock on Windows). Process termination releases the lock automatically; a single configured scheduler remains easier to operate and audit.

Observer maintenance uses path-filtered `lsof` and targets macOS and Linux by default. Windows locking remains supported, while observer commands fail closed unless an `lsof`-compatible executable is available. Coordinate claude-mem publication with this maintenance window; a same-user process that ignores the advisory lock can race the final checks.
