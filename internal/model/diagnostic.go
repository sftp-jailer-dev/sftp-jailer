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
}
