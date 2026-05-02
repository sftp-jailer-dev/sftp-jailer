package doctor

import (
	"fmt"
	"strings"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/model"
)

// RenderText returns the human-readable doctor report as a six-row text
// report with [OK] / [WARN] / [FAIL] / [INFO] tags. No ANSI escapes - safe
// for pipes, logs, clipboard. The TUI doctor screen layers Lip Gloss colors
// on top per prefix (see internal/tui/screens/doctor/doctor.go).
//
// Row tags:
//
//	[OK]   - detector ran successfully and the state is acceptable
//	[WARN] - detector ran but flags a pitfall (A5/C4/C5 etc.)
//	[FAIL] - actively broken state (e.g. sftp subsystem points outside chroot)
//	[INFO] - detector could not run (binary not installed); not a failure
func RenderText(rep model.DoctorReport) string {
	var sb strings.Builder
	sb.WriteString("sftp-jailer doctor\n\n")

	sb.WriteString(renderSshdDropIns(rep.SshdDropIns))
	sb.WriteString(renderChrootChain(rep.ChrootChain))
	sb.WriteString(renderUfwRow(rep.Ufw, rep.UfwIPv6))
	sb.WriteString(renderAppArmor(rep.AppArmor))
	sb.WriteString(renderNftConsumers(rep.NftConsumers))
	sb.WriteString(renderSubsystem(rep.Subsystem))

	// Phase 3 / D-06: when the canonical-config gap is detected, append the
	// [A] action prompt so CLI consumers see the same prescription surface
	// the TUI doctor screen renders. The TUI binds 'a' to push M-APPLY-SETUP;
	// the CLI text rendering shows the prompt for parity (a future `doctor
	// --apply` flag could consume this signal directly).
	if NeedsCanonicalApply(rep) {
		sb.WriteString("\n[A] Apply SFTP jail configuration - addresses missing drop-in, broken chain, or external sftp-server\n")
	}

	return sb.String()
}

func renderSshdDropIns(r model.SshdDropInReport) string {
	if r.Error != "" {
		return fmt.Sprintf("[INFO] sshd drop-ins: could not enumerate (%s)\n", r.Error)
	}
	if r.ContainsChrootMatch {
		return fmt.Sprintf("[OK]   sshd drop-ins: %d file(s), contains chroot Match block\n", len(r.Files))
	}
	return fmt.Sprintf("[WARN] sshd drop-ins: %d file(s), no chroot Match group found\n", len(r.Files))
}

func renderChrootChain(r model.ChrootChainReport) string {
	if len(r.Links) == 0 {
		return fmt.Sprintf("[WARN] chroot chain %s: not inspected (no links)\n", r.Root)
	}
	allGood := true
	var firstBad string
	for _, l := range r.Links {
		switch {
		case l.Missing:
			allGood = false
			if firstBad == "" {
				firstBad = fmt.Sprintf("%s missing", l.Path)
			}
		case !l.RootOwned:
			allGood = false
			if firstBad == "" {
				firstBad = fmt.Sprintf("%s not root-owned (uid=%d gid=%d)", l.Path, l.UID, l.GID)
			}
		case !l.NoGroupWrite:
			allGood = false
			if firstBad == "" {
				firstBad = fmt.Sprintf("%s has group-write (mode=%04o)", l.Path, l.Mode)
			}
		case l.IsSymlink:
			allGood = false
			if firstBad == "" {
				firstBad = fmt.Sprintf("%s is a symlink", l.Path)
			}
		}
	}
	if allGood {
		return fmt.Sprintf("[OK]   chroot chain %s: root:root + no-group-write all the way down\n", r.Root)
	}
	return fmt.Sprintf("[WARN] chroot chain %s: %s\n", r.Root, firstBad)
}

// renderUfwRow composes the ufw active/inactive signal with the IPV6
// sub-signal. When ufw is inactive, the IPV6 setting is moot - render
// only the [FAIL] row + [A] action label so operators see one clear
// prescription. When ufw is active, fall through to the existing
// renderUfwIPv6 logic (preserves the v1.2.1 FW-06 row byte-for-byte).
//
// v1.2.2 decision (operator-locked): the `[A] Enable ufw` is a LABEL
// only. The actual `ufw --force enable` mutation belongs in v1.3
// where it can land alongside other ufw mutations under proper
// SAFE-04 timer coverage. Surfacing the label here without the
// handler is the documented v1.2.2 scope - it tells operators what
// the fix is without us shipping an unsupervised mutation path.
func renderUfwRow(r model.UfwReport, ipv6 model.UfwIPv6Report) string {
	switch {
	case !r.Available:
		if r.Error != "" {
			return fmt.Sprintf("[INFO] ufw: status unavailable (%s)\n", r.Error)
		}
		return "[INFO] ufw: status unavailable (binary may not be installed)\n"
	case r.Inactive:
		// [FAIL] + [A] label pair. The IPV6 row is suppressed because
		// the setting is moot when ufw is down (no rules of any kind
		// are enforced). When the operator runs `ufw enable` the row
		// collapses back to the existing renderUfwIPv6 output.
		return "[FAIL] ufw: inactive (no firewall enforcement; lockdown will fail)\n" +
			"[A] Enable ufw - run `ufw enable` (apply flow lands in v1.3)\n"
	default:
		// Active: delegate to the existing renderer. Byte-for-byte
		// identical output to the v1.2.1 path.
		return renderUfwIPv6(ipv6)
	}
}

func renderUfwIPv6(r model.UfwIPv6Report) string {
	switch {
	case r.Missing:
		return "[INFO] ufw IPV6: /etc/default/ufw not found (ufw may not be installed)\n"
	case r.Warning:
		return fmt.Sprintf("[WARN] ufw IPV6=%s (Launchpad #251355 - rules will leak v6)\n", r.Value)
	default:
		return fmt.Sprintf("[OK]   ufw IPV6=%s\n", r.Value)
	}
}

func renderAppArmor(r model.AppArmorReport) string {
	switch {
	case !r.Available:
		return "[INFO] AppArmor: aa-status not available (package may not be installed)\n"
	case !r.SshdLoaded:
		return "[OK]   AppArmor: sshd profile not loaded\n"
	case r.Warning:
		return fmt.Sprintf("[WARN] AppArmor: sshd in %s mode (may silently deny chroot - pitfall A5)\n", r.SshdMode)
	default:
		return fmt.Sprintf("[OK]   AppArmor: sshd in %s mode\n", r.SshdMode)
	}
}

func renderNftConsumers(r model.NftConsumersReport) string {
	if !r.Available {
		return "[INFO] nftables consumers: nft -j not available (package may not be installed)\n"
	}
	if r.DockerDetected || r.TailscaleDetected {
		var parts []string
		if r.DockerDetected {
			parts = append(parts, "Docker")
		}
		if r.TailscaleDetected {
			parts = append(parts, "Tailscale")
		}
		return fmt.Sprintf("[WARN] nftables consumers: %s may desync with ufw (pitfall C5)\n", strings.Join(parts, " + "))
	}
	return "[OK]   nftables consumers: clean\n"
}

func renderSubsystem(r model.SubsystemReport) string {
	// Decision (v1.2.1): rather than dynamically rewriting the [A] rationale
	// based on which subset of issues is present, suppress the [A] prompt
	// entirely when the override resolves the only failing detector.
	// Simpler, fewer string-formatting branches, and operators see [A] only
	// when an action would actually help. The suppression is wired through
	// NeedsCanonicalApply (it gates on JailedOverrideForceInternal too); the
	// renderer just emits [OK] with explanatory text here.
	switch {
	case r.Error != "":
		return fmt.Sprintf("[INFO] subsystem sftp: sshd -T unavailable (%s)\n", r.Error)
	case r.Missing:
		return "[WARN] subsystem sftp: not set in sshd effective config\n"
	case r.Warning && r.JailedOverrideForceInternal:
		// v1.2.1 fix: base Subsystem points outside the chroot, but the
		// canonical drop-in's Match Group sftp-jailer + ForceCommand
		// internal-sftp override means jailed users never invoke the
		// external binary. Render [OK] with the explanatory note so
		// operators understand what the doctor saw.
		return fmt.Sprintf("[OK]   subsystem sftp: %s for non-jailed users; jailed users use ForceCommand internal-sftp via drop-in\n", r.Target)
	case r.Warning:
		return fmt.Sprintf("[FAIL] subsystem sftp: %s - external binary won't exist inside chroot (pitfall A2)\n", r.Target)
	default:
		return fmt.Sprintf("[OK]   subsystem sftp: %s\n", r.Target)
	}
}
