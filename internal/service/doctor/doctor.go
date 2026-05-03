// Package doctor composes six read-only detectors into a single
// model.DoctorReport (SETUP-01). Every read goes through sysops.SystemOps -
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

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
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
// Phase 3 / D-06 - the screen-level [A] action constructor needs ops to
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
//   - Subsystem.Warning is set AND no jailed-Match ForceCommand override
//     is present (external sftp-server detected → pitfall A2 / SETUP-06
//     advisory; the modal shows the advisory note even though auto-fix
//     is deferred per RESEARCH OQ-5). The override check prevents a
//     false-positive [A] prompt on boxes where the canonical drop-in is
//     correctly installed but `sshd -T` still reports the base Subsystem
//     (v1.2.1 fix).
//
// False otherwise - including when ChrootChain is entirely Missing (no
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
	return rep.Subsystem.Warning && !rep.Subsystem.JailedOverrideForceInternal
}

// NeedsUfwEnable returns true iff the report indicates ufw is inactive
// AND the operator has a path to fix it (binary present). Returns
// false when ufw is unavailable (binary not installed) - that case
// shows [INFO] in the doctor row and has no actionable [A].
//
// The doctor screen consults this AFTER NeedsCanonicalApply to decide
// whether to fire the [A] Enable ufw dispatch (FW-11 / D-14
// precedence: canonical-apply > ufw-enable). Pure function so the TUI
// dispatcher can call it in View() AND in Update() without re-running
// the detector chain.
//
// D-17 boundary: this precedence-based dispatch is for the doctor
// screen only (read-only diagnostic with a small finite action set).
// Phase 13's unified console will use a cursor-row-based pattern.
func NeedsUfwEnable(rep model.DoctorReport) bool {
	return rep.Ufw.Available && rep.Ufw.Inactive
}

// IsHealthy returns true when the doctor report has zero [FAIL] rows -
// the strict precondition for the startup-doctor gate to advance to the
// home screen. Implemented as a substring check on RenderText so it
// stays in lockstep with whatever the operator literally sees on the
// screen: any future row that renders a [FAIL] automatically blocks
// the gate without needing a code change here.
//
// Note: [WARN] rows do NOT block the gate. The user-stated rule is
// "everything green," but warnings are advisory (e.g. sshd_config.d
// drop-ins absent before any apply) and would block fresh installs
// indefinitely. If we later decide warnings should also gate, swap
// the substring check accordingly.
func IsHealthy(rep model.DoctorReport) bool {
	return !strings.Contains(RenderText(rep), "[FAIL]")
}

// Run executes all six detectors sequentially and returns the aggregated
// report. Phase 1 never errors the whole report - each detector reports its
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

	// v1.2.2: ufw active/inactive signal. Reuses firewall.Enumerate's
	// existing `ufw status numbered` exec + ErrUFWInactive sentinel so
	// there is a single source of truth for the parse. The IPV6
	// sub-signal (rep.UfwIPv6) remains independent; the renderer
	// composes both via renderUfwRow.
	rep.Ufw, _ = s.detectUfwStatus(ctx)

	// v1.2.1 fix: when the base Subsystem points at an external sftp-server
	// binary, also check whether the canonical drop-in installs a
	// `Match Group sftp-jailer + ForceCommand internal-sftp` override.
	// If yes, jailed users never invoke the external binary and the
	// [FAIL] row in render.go is downgraded to [OK]. Non-jailed users
	// still use the base directive, which is the documented OpenSSH
	// default and not in scope for this tool's chroot story.
	if rep.Subsystem.Warning {
		rep.Subsystem.JailedOverrideForceInternal = s.detectJailedForceCommandOverride(ctx)
	}

	return rep, nil
}

// detectUfwStatus calls firewall.Enumerate to get the active/inactive
// signal. The rules slice is intentionally discarded - this detector
// only consumes the active/inactive bit (the per-rule IP-allowlist
// enrichment is the S-USERS / S-FIREWALL responsibility, not the
// doctor screen's). Reusing firewall.Enumerate keeps a single source
// of truth for the `ufw status numbered` parse and the ErrUFWInactive
// sentinel rather than duplicating the parser here.
//
// Why a separate detector rather than folding it into detectUfwIPv6:
// the IPV6 setting reads /etc/default/ufw, which is present even when
// ufw is disabled (it's a static config file). The active/inactive
// signal requires a live `ufw status` query. Two detectors, two
// independently-degradable signals, composed in renderUfwRow.
func (s *Service) detectUfwStatus(ctx context.Context) (model.UfwReport, error) {
	_, err := firewall.Enumerate(ctx, s.ops)
	switch {
	case err == nil:
		return model.UfwReport{Available: true, Inactive: false}, nil
	case errors.Is(err, firewall.ErrUFWInactive):
		return model.UfwReport{Available: true, Inactive: true}, nil
	default:
		// Exec failure (ufw not installed / not allowlisted) or non-zero
		// exit. Degrade to [INFO] - mirrors AppArmor/nft conventions.
		return model.UfwReport{Available: false, Error: err.Error()}, nil
	}
}

// detectJailedForceCommandOverride scans /etc/ssh/sshd_config.d/*.conf for
// a `Match Group sftp-jailer` block whose body contains a `ForceCommand
// internal-sftp ...` directive. Returns true on first match. Used by Run
// to refine the SubsystemReport after detectSubsystem reports the base
// directive (which `sshd -T` returns regardless of Match-block overrides
// when invoked without -C user=...,group=...).
//
// Why a separate scan instead of reusing detectSshdDropIns: that detector
// only records HasMatchGroup, not the body directives. We need the
// ForceCommand value to verify the override is actually present and
// points at internal-sftp (not an admin-overridden custom command).
func (s *Service) detectJailedForceCommandOverride(ctx context.Context) bool {
	paths, err := s.ops.Glob(ctx, "/etc/ssh/sshd_config.d/*.conf")
	if err != nil {
		return false
	}
	for _, p := range paths {
		b, err := s.ops.ReadFile(ctx, p)
		if err != nil {
			continue
		}
		parsed, _ := sshdcfg.ParseDropIn(b)
		for _, m := range parsed.Matches {
			// Match Condition format: "Group sftp-jailer" (after the
			// "Match " prefix is stripped by the parser).
			fields := strings.Fields(m.Condition)
			if len(fields) < 2 {
				continue
			}
			if !strings.EqualFold(fields[0], "Group") || fields[1] != "sftp-jailer" {
				continue
			}
			// Found the Match block; look for ForceCommand internal-sftp ...
			for _, dir := range m.Body {
				if dir.Keyword != "forcecommand" {
					continue
				}
				value := strings.TrimSpace(dir.Value)
				if strings.HasPrefix(value, "internal-sftp") {
					// Either bare `internal-sftp` or
					// `internal-sftp -f AUTHPRIV -l INFO` etc.
					return true
				}
			}
		}
	}
	return false
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
			// Skip unreadable files - a single bad drop-in should not hide
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
			// Stop at the first missing link - nothing below it exists.
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
		// Unknown error reading the file - treat as missing for Phase 1.
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
