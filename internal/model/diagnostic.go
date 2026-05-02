// Package model holds pure domain types shared between packages. No
// methods, no I/O, no dependencies outside the standard library.
package model

import "io/fs"

// DoctorReport is the aggregated result of the read-only diagnostic run
// (SETUP-01). Populated by internal/doctor in plan 04; rendered by the TUI
// in plan 02.
type DoctorReport struct {
	SshdDropIns  SshdDropInReport
	ChrootChain  ChrootChainReport
	UfwIPv6      UfwIPv6Report
	AppArmor     AppArmorReport
	NftConsumers NftConsumersReport
	Subsystem    SubsystemReport
	Ufw          UfwReport // v1.2.2 - active/inactive signal (separate from UfwIPv6).
}

// SshdDropInReport describes the contents of /etc/ssh/sshd_config.d/.
type SshdDropInReport struct {
	Files               []SshdDropInFile
	ContainsChrootMatch bool
	Error               string
}

// SshdDropInFile is a single drop-in file under sshd_config.d/.
type SshdDropInFile struct {
	Path          string
	Size          int
	HasMatchGroup bool
}

// ChrootChainReport is the ownership chain walk from / down to the chroot
// root directory (SETUP-04).
type ChrootChainReport struct {
	Root  string
	Links []ChrootChainLink
}

// ChrootChainLink is a single path component in the chroot chain.
type ChrootChainLink struct {
	Path         string
	UID          uint32
	GID          uint32
	Mode         fs.FileMode
	IsSymlink    bool
	Missing      bool
	RootOwned    bool
	NoGroupWrite bool
	NoOtherWrite bool
}

// UfwIPv6Report reflects the IPV6= setting in /etc/default/ufw (FW-06).
type UfwIPv6Report struct {
	Value   string // "yes" | "no" | "unset"
	Warning bool
	Missing bool
}

// UfwReport reflects the higher-level state of ufw on the box: whether
// the binary is reachable AND whether the firewall is currently active.
// Populated by Service.detectUfwStatus via firewall.Enumerate (which
// already shells `ufw status numbered` via sysops.Exec and surfaces
// ErrUFWInactive on `Status: inactive`).
//
// Composition with UfwIPv6Report: when Inactive is true, the IPV6
// sub-signal is moot (no rules at all, so IPV6 leak is unobservable);
// the renderer suppresses the IPV6 row in that case. When Available is
// false (binary missing), Inactive defaults to false and the row
// degrades to [INFO] ufw: status unavailable.
//
// v1.2.2: detect + render only. The [A] Enable ufw action label is
// surfaced in the renderer but the apply-flow wiring (`ufw --force
// enable` mutation through internal/txn) is deferred to v1.3 where it
// can land alongside other ufw mutations under proper SAFE-04 timer
// coverage.
type UfwReport struct {
	Available bool   // false when `ufw status` exec failed (binary missing); renders as [INFO]
	Inactive  bool   // true when `ufw status` returns ErrUFWInactive
	Error     string // populated on non-Inactive non-nil exec/parse errors (rendered in [INFO])
}

// AppArmorReport describes whether sshd is confined by an AppArmor profile
// that would block the tool's operations.
type AppArmorReport struct {
	Available  bool
	SshdLoaded bool
	SshdMode   string // "enforce" | "complain" | "unconfined" | ""
	Warning    bool
}

// NftConsumersReport flags other nftables consumers on the box that might
// fight with ufw's ruleset (Docker, Tailscale).
type NftConsumersReport struct {
	Available         bool
	DockerDetected    bool
	TailscaleDetected bool
}

// SubsystemReport describes the Subsystem sftp setting (SETUP-06).
type SubsystemReport struct {
	Target     string
	IsInternal bool
	Warning    bool
	Missing    bool
	Error      string

	// JailedOverrideForceInternal is true when the canonical drop-in
	// (/etc/ssh/sshd_config.d/50-sftp-jailer.conf) has a `Match Group
	// sftp-jailer` block whose body contains `ForceCommand internal-sftp`.
	// When true, jailed users never invoke the external sftp-server
	// binary even if the base Subsystem directive points at it - the
	// doctor renderer downgrades the [FAIL] to [OK] and the
	// NeedsCanonicalApply prescription drops the "external sftp-server"
	// clause. Set by Service.Run AFTER detectSubsystem returns; tests
	// populating SubsystemReport directly may set this field manually.
	JailedOverrideForceInternal bool
}
