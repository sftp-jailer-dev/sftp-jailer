<p align="center">
  <img src="./sftp-jailer-logo.png" width="256" alt="sftp-jailer logo">
</p>

<h1 align="center">sftp-jailer</h1>

<p align="center">
  <em>Chrooted SFTP administration for Ubuntu 24.04 and Debian 13 (trixie), in one TUI.</em>
  <br>
  <a href="https://sftp-jailer.com">sftp-jailer.com</a>
</p>

---

> **Status:** Pre-alpha. Phase 1 (foundation + diagnostic + TUI shell) in progress.

## Install

Download the latest `.deb` from the [GitHub Releases](https://github.com/sftp-jailer-dev/sftp-jailer/releases)
page for your architecture (`amd64` or `arm64`), then:

```bash
sudo apt install ./sftp-jailer_<version>_<arch>.deb
```

Verify the download using the `SHA256SUMS.txt` artifact attached to the same release:

```bash
cd <download-dir>
sha256sum -c SHA256SUMS.txt --ignore-missing
```

**Building from source (developer setup):**

```bash
# Requires Go 1.25+.
# DO NOT `apt install golang-go` on Ubuntu 24.04 (ships Go 1.22.2) — it cannot build this project.
# Use either:
#   • the longsleep PPA: sudo add-apt-repository ppa:longsleep/golang-backports && sudo apt install golang-1.25
#   • or the official tarball from https://go.dev/dl/ (works on Ubuntu and Debian)

git clone https://github.com/sftp-jailer-dev/sftp-jailer
cd sftp-jailer
goreleaser release --snapshot --clean --config packaging/goreleaser.yml
sudo apt install ./dist/sftp-jailer_<version>_<arch>.deb
```

## Recovery

`apt purge sftp-jailer` removes everything — including the observation database at
`/var/lib/sftp-jailer/observations.db`. To preserve the database before purging:

```bash
sudo cp /var/lib/sftp-jailer/observations.db \
    ~/sftp-jailer-observations-backup-$(date +%F).db
```

After reinstalling, restore the backup:

```bash
sudo cp ~/sftp-jailer-observations-backup-<DATE>.db \
    /var/lib/sftp-jailer/observations.db
sudo chown root:root /var/lib/sftp-jailer/observations.db
sudo chmod 0600 /var/lib/sftp-jailer/observations.db
```

`sftp-jailer doctor` surfaces a hint when `/var/lib/sftp-jailer/` exceeds the
warning threshold, so admins are notified as data accumulates.

## Releases & Tagging Convention

Releases are triggered by pushing a tag matching one of these patterns:

```
vMAJOR.MINOR.PATCH       e.g., v1.2.0   → .deb version 1.2.0
vMAJOR.MINOR.PATCH-rcN   e.g., v1.2.0-rc1 → .deb version 1.2.0~rc1
```

Any other tag form (e.g., `v1.2`, `v1.2.0+build.1`, `v1.2.0-beta`) does NOT match
the release workflow's tag filter and the workflow will not fire.

The Debian-ordered prerelease form (`1.2.0~rc1` sorts BEFORE `1.2.0` per Debian
version comparison), so `apt upgrade` on a host running `1.2.0~rc1` picks up `1.2.0`
when it lands.

**Cutting a release:**

```bash
git tag v1.2.0
git push --tags
```

GitHub Actions handles the rest: full CI gate → goreleaser release → lintian
`--pedantic` → `SHA256SUMS.txt` generation → upload to GitHub Release. No manual steps.

## Platform

Ubuntu 24.04 LTS and Debian 13 (trixie) for v1. `apt`, `systemd` (journald + timers), `ufw` (nftables backend) assumed present on both.

## License

GPL-3.0. See [LICENSE](./LICENSE).
