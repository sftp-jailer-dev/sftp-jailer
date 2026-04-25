# packaging/systemd

Static systemd unit files that drive the weekly observation pipeline (`OBS-01`).
Phase 5 / `DIST-04` ships the `.deb` postinst that installs and enables them.

## Files

- **`sftp-jailer-observer.service`** — `Type=oneshot` unit invoking
  `/usr/bin/sftp-jailer observe-run` as `root`. Sends stdout/stderr to journald
  and caps the run at 10 minutes (`TimeoutStartSec=600`).
- **`sftp-jailer-observer.timer`** — fires the service `weekly` with
  `Persistent=true` (so a powered-off box catches up on next boot) and a
  `RandomizedDelaySec=1h` jitter.

The unit file contents themselves are the source of truth — see the files
directly. This README documents only the install + enable contract that
Phase 5 implements.

## Install paths (Phase 5)

The `.deb` package installs both files into `/lib/systemd/system/`. End users
do **not** copy them by hand; `dpkg`/`apt` does it.

| Source path                                            | Installed path                                     |
|--------------------------------------------------------|----------------------------------------------------|
| `packaging/systemd/sftp-jailer-observer.service`       | `/lib/systemd/system/sftp-jailer-observer.service` |
| `packaging/systemd/sftp-jailer-observer.timer`         | `/lib/systemd/system/sftp-jailer-observer.timer`   |

## OBS-v2-02 deferral note

In v1 the service runs as `User=root`. A dedicated `_sftp-jailer-observer`
system user is deferred to v1.1 (`OBS-v2-02`). When that lands, the service
file gains `User=_sftp-jailer-observer` plus matching `chown` of the cursor
file in postinst — no other directives change.

## Phase 5 postinst contract (DIST-04)

The `.deb` postinst — shipped by `nfpm`/`goreleaser` in Phase 5 — must:

1. `daemon-reload` so systemd notices the new unit files.
2. Enable the timer (lintian-clean idiom uses `deb-systemd-helper`).
3. Start the timer (NOT the service — the timer fires the service).
4. Pre-create an empty `/var/lib/sftp-jailer/observer.cursor` (mode `0600`,
   owned `root:root`) so the first `observe-run` doesn't slurp the entire
   journal history (Pitfall 1; runner detects the empty file and falls back
   to a 7-day `--since` for the first run).

Reference postinst body (Phase 5 inherits this verbatim):

```sh
#!/bin/sh
# postinst — Phase 5 nfpm
set -e

case "$1" in
    configure)
        systemctl daemon-reload || true
        if [ -x /usr/bin/deb-systemd-helper ]; then
            deb-systemd-helper unmask sftp-jailer-observer.timer || true
            deb-systemd-helper enable sftp-jailer-observer.timer || true
        else
            systemctl enable sftp-jailer-observer.timer || true
        fi
        if [ -x /usr/bin/deb-systemd-invoke ]; then
            deb-systemd-invoke start sftp-jailer-observer.timer || true
        else
            systemctl start sftp-jailer-observer.timer || true
        fi
        install -d -m 0755 /var/lib/sftp-jailer
        : > /var/lib/sftp-jailer/observer.cursor
        chmod 0600 /var/lib/sftp-jailer/observer.cursor
    ;;
esac

exit 0
```

The matching `prerm` runs `deb-systemd-invoke stop` + `deb-systemd-helper
disable` on package removal, and `purge` removes `/var/lib/sftp-jailer/`
(including `observe-run.lock` and `observer.cursor`).

`deb-systemd-helper` and `deb-systemd-invoke` are part of
`init-system-helpers` — an essential package on Ubuntu 24.04. Phase 5 should
declare `Depends: init-system-helpers` (or accept it as a transitive of
`essential`).

## Verification

These unit files are validated on Ubuntu via:

```sh
systemd-analyze verify packaging/systemd/sftp-jailer-observer.service
systemd-analyze verify packaging/systemd/sftp-jailer-observer.timer
```

Local macOS development cannot run `systemd-analyze`. Verification is
performed by Phase 5's CI pipeline on `ubuntu-latest`.
