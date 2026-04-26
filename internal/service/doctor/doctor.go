// Package doctor composes six read-only detectors into a single
// model.DoctorReport (SETUP-01). Every read goes through sysops.SystemOps —
// this package must NOT import os or os/exec (the check-no-exec-outside-sysops
// guard enforces it). Detectors degrade gracefully: a missing binary or
// unparseable output sets `Available: false` on its sub-report rather than
// errorring the whole run.
//
// Pitfalls retired by the detectors:
//   - A2: Subsystem detection flags /usr/lib/openssh/sftp-server as WARN.
//   - A5: AppArmor enforce-mode on sshd is flagged as WARN.
//   - A6: Chroot ownership chain walks / -> root and flags symlinks.
//   - C4: ufw IPV6=no (or unset) is flagged as WARN.
//   - C5: Docker or Tailscale nft chains detected as WARN.
package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/model"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sshdcfg"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// Service orchestrates the six Phase 1 detectors. Construct via New; the
// service is stateless beyond the SystemOps handle and the chroot root path.
type Service struct {
	ops        sysops.SystemOps
	chrootRoot string
}

// New returns a Service wired to the given SystemOps. Production code passes
// sysops.NewReal(); tests pass sysops.NewFake().
func New(ops sysops.SystemOps) *Service {
	return &Service{ops: ops, chrootRoot: "/srv/sftp-jailer"}
}

// Ops exposes the SystemOps handle so the TUI doctor screen can pass it to
// action modals (e.g. M-APPLY-SETUP) without re-plumbing the bootstrap.
// Phase 3 / D-06 — the screen-level [A] action constructor needs ops to
// build the modal that runs txn.CanonicalApplySetupSteps + Tx.Apply.
//
// Phase 1/2 callers should NOT use this accessor; the doctor service owns
// the SystemOps instance and the screen indirects through here precisely so
// only one Service.Ops handle is in flight per screen lifetime.
func (s *Service) Ops() sysops.SystemOps { return s.ops }

// ChrootRoot returns the configured chroot root (defaults to /srv/sftp-jailer).
// Phase 3: M-APPLY-SETUP seeds its proposed-root textinput from this value
// when no ChrootDirectory directive is found in any drop-in. Once the modal
// re-runs preflight against the real filesystem (D-08), the textinput value
// reflects the parsed sshd_config rather than this default.
func (s *Service) ChrootRoot() string { return s.chrootRoot }

// NeedsCanonicalApply returns true iff the report indicates a SETUP-02..06
// gap that the M-APPLY-SETUP modal can address. The doctor screen consults
// this to decide whether to render the [A] action footer entry.
//
// True conditions (any one):
//   - SshdDropIns.ContainsChrootMatch is false (no drop-in with the
//     sftp-jailer Match Group → SETUP-02 / D-07 gap).
//   - ChrootChain has any non-Missing link that fails the root:root +
//     no-group-write + no-symlink invariant (SETUP-04 / pitfall A6 gap).
//   - Subsystem.Warning is set (external sftp-server detected → pitfall A2 /
//     SETUP-06 advisory; the modal shows the advisory note even though
//     auto-fix is deferred per RESEARCH OQ-5).
//
// False otherwise — including when ChrootChain is entirely Missing (no
// chroot root exists yet to walk; first-launch flow takes the SETUP-02
// branch via SshdDropIns instead).
func NeedsCanonicalApply(rep model.DoctorReport) bool {
	if !rep.SshdDropIns.ContainsChrootMatch {
		return true
	}
	for _, link := range rep.ChrootChain.Links {
		if link.Missing {
			continue
		}
		if !link.RootOwned || !link.NoGroupWrite || link.IsSymlink {
			return true
		}
	}
	return rep.Subsystem.Warning
}

// Run executes all six detectors sequentially and returns the aggregated
// report. Phase 1 never errors the whole report — each detector reports its
// own availability via its sub-report. The returned error is reserved for
// future extensions (e.g. strict mode that stops on first detector failure).
func (s *Service) Run(ctx context.Context) (model.DoctorReport, error) {
	rep := model.DoctorReport{}
	rep.SshdDropIns, _ = s.detectSshdDropIns(ctx)
	rep.ChrootChain, _ = s.detectChrootChain(ctx, s.chrootRoot)
	rep.UfwIPv6, _ = s.detectUfwIPv6(ctx)
	rep.AppArmor, _ = s.detectAppArmor(ctx)
	rep.NftConsumers, _ = s.detectNftConsumers(ctx)
	rep.Subsystem, _ = s.detectSubsystem(ctx)
	return rep, nil
}

// detectSshdDropIns enumerates /etc/ssh/sshd_config.d/*.conf and parses each
// via internal/sshdcfg. A drop-in with a "Match Group sftp-jailer" block sets
// ContainsChrootMatch=true.
func (s *Service) detectSshdDropIns(ctx context.Context) (model.SshdDropInReport, error) {
	rep := model.SshdDropInReport{}
	paths, err := s.ops.Glob(ctx, "/etc/ssh/sshd_config.d/*.conf")
	if err != nil {
		rep.Error = err.Error()
		return rep, nil
	}
	for _, p := range paths {
		b, err := s.ops.ReadFile(ctx, p)
		if err != nil {
			// Skip unreadable files — a single bad drop-in should not hide
			// the others from the report.
			continue
		}
		parsed, _ := sshdcfg.ParseDropIn(b)
		f := model.SshdDropInFile{
			Path:          p,
			Size:          len(b),
			HasMatchGroup: parsed.HasMatchGroup("sftp-jailer"),
		}
		rep.Files = append(rep.Files, f)
		if f.HasMatchGroup {
			rep.ContainsChrootMatch = true
		}
	}
	return rep, nil
}

// detectChrootChain walks / -> root and records ownership / mode / symlink
// status for each link. OpenSSH requires every link in the chain to be
// root-owned, non-group-writable, and not a symlink (pitfall A6).
func (s *Service) detectChrootChain(ctx context.Context, root string) (model.ChrootChainReport, error) {
	if root == "" {
		root = "/srv/sftp-jailer"
	}
	paths := []string{"/"}
	cleaned := filepath.Clean(root)
	if cleaned != "/" {
		parts := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
		acc := ""
		for _, p := range parts {
			acc = acc + "/" + p
			paths = append(paths, acc)
		}
	}

	links := make([]model.ChrootChainLink, 0, len(paths))
	for _, p := range paths {
		fi, err := s.ops.Lstat(ctx, p)
		if err != nil {
			links = append(links, model.ChrootChainLink{Path: p, Missing: true})
			// Stop at the first missing link — nothing below it exists.
			break
		}
		links = append(links, model.ChrootChainLink{
			Path:         p,
			UID:          fi.UID,
			GID:          fi.GID,
			Mode:         fi.Mode,
			IsSymlink:    fi.IsLink,
			RootOwned:    fi.UID == 0 && fi.GID == 0,
			NoGroupWrite: fi.Mode&0o020 == 0,
			NoOtherWrite: fi.Mode&0o002 == 0,
		})
	}
	return model.ChrootChainReport{Root: root, Links: links}, nil
}

// detectUfwIPv6 reads /etc/default/ufw and reports the IPV6= setting.
// IPV6=no (pitfall C4, Launchpad #251355) is flagged Warning.
// A missing file is flagged Missing (ufw may simply not be installed).
func (s *Service) detectUfwIPv6(ctx context.Context) (model.UfwIPv6Report, error) {
	b, err := s.ops.ReadFile(ctx, "/etc/default/ufw")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || strings.Contains(err.Error(), "no such") {
			return model.UfwIPv6Report{Missing: true}, nil
		}
		// Unknown error reading the file — treat as missing for Phase 1.
		return model.UfwIPv6Report{Missing: true}, nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(k) != "IPV6" {
			continue
		}
		val := strings.Trim(strings.TrimSpace(v), `"'`)
		return model.UfwIPv6Report{Value: val, Warning: val != "yes"}, nil
	}
	return model.UfwIPv6Report{Value: "unset", Warning: true}, nil
}

// detectAppArmor runs `aa-status --json` and checks the mode of the sshd
// profile. Enforce mode is flagged Warning (pitfall A5).
func (s *Service) detectAppArmor(ctx context.Context) (model.AppArmorReport, error) {
	r, err := s.ops.Exec(ctx, "aa-status", "--json")
	if err != nil || r.ExitCode != 0 {
		return model.AppArmorReport{Available: false}, nil
	}
	var out struct {
		Profiles map[string]string `json:"profiles"`
	}
	if err := json.Unmarshal(r.Stdout, &out); err != nil {
		return model.AppArmorReport{Available: false}, nil
	}
	mode, loaded := out.Profiles["/usr/sbin/sshd"]
	return model.AppArmorReport{
		Available:  true,
		SshdLoaded: loaded,
		SshdMode:   mode,
		Warning:    mode == "enforce",
	}, nil
}

// detectNftConsumers runs `nft -j list ruleset` and scans table/chain names
// for "docker" (Docker installed its own nftables chains) or the ts-* prefix
// (Tailscale). Either detection is flagged (pitfall C5: co-existing nft
// consumers can desync with ufw).
func (s *Service) detectNftConsumers(ctx context.Context) (model.NftConsumersReport, error) {
	r, err := s.ops.Exec(ctx, "nft", "-j", "list", "ruleset")
	if err != nil || r.ExitCode != 0 {
		return model.NftConsumersReport{Available: false}, nil
	}
	var out struct {
		Nftables []map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(r.Stdout, &out); err != nil {
		return model.NftConsumersReport{Available: false}, nil
	}
	rep := model.NftConsumersReport{Available: true}
	for _, entry := range out.Nftables {
		for kind, v := range entry {
			if kind == "metainfo" {
				continue
			}
			m, _ := v.(map[string]any)
			name, _ := m["name"].(string)
			lower := strings.ToLower(name)
			if strings.Contains(lower, "docker") {
				rep.DockerDetected = true
			}
			if strings.HasPrefix(lower, "ts-") || lower == "tailscale" {
				rep.TailscaleDetected = true
			}
		}
	}
	return rep, nil
}

// detectSubsystem parses `sshd -T` output (via SystemOps.SshdDumpConfig) to
// find the `Subsystem sftp <target>` line. The internal-sftp target is the
// required value (pitfall A2: shelling to an external sftp-server binary
// that does not exist inside the chroot silently breaks SFTP).
func (s *Service) detectSubsystem(ctx context.Context) (model.SubsystemReport, error) {
	dump, err := s.ops.SshdDumpConfig(ctx)
	if err != nil {
		return model.SubsystemReport{Error: err.Error()}, nil
	}
	for _, v := range dump["subsystem"] {
		// Example value: "sftp internal-sftp -f AUTHPRIV -l INFO"
		if strings.HasPrefix(v, "sftp ") {
			target := strings.TrimPrefix(v, "sftp ")
			return model.SubsystemReport{
				Target:     target,
				IsInternal: strings.HasPrefix(target, "internal-sftp"),
				Warning:    !strings.HasPrefix(target, "internal-sftp"),
			}, nil
		}
	}
	return model.SubsystemReport{Missing: true}, nil
}
