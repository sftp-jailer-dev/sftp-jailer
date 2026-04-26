package doctor_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/model"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/service/doctor"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// ---- detectSshdDropIns ---------------------------------------------------

// A Glob returning the canonical drop-in path plus a ReadFile returning the
// fixture contents should flag ContainsChrootMatch true and record one file.
func TestDetectSshdDropIns_canonical(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/sshd_config/50-sftp-jailer-canonical.conf")
	require.NoError(t, err)

	f := sysops.NewFake()
	f.GlobResults["/etc/ssh/sshd_config.d/*.conf"] = []string{"/etc/ssh/sshd_config.d/50-sftp-jailer.conf"}
	f.Files["/etc/ssh/sshd_config.d/50-sftp-jailer.conf"] = b

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)

	require.True(t, r.SshdDropIns.ContainsChrootMatch)
	require.Len(t, r.SshdDropIns.Files, 1)
	require.Equal(t, "/etc/ssh/sshd_config.d/50-sftp-jailer.conf", r.SshdDropIns.Files[0].Path)
	require.True(t, r.SshdDropIns.Files[0].HasMatchGroup)
}

// Empty Glob means no drop-ins: ContainsChrootMatch must be false and Files
// must be empty (no panic, no error).
func TestDetectSshdDropIns_empty(t *testing.T) {
	f := sysops.NewFake()
	// Glob returns no scripted matches → Fake returns nil slice.
	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.False(t, r.SshdDropIns.ContainsChrootMatch)
	require.Empty(t, r.SshdDropIns.Files)
}

// ---- detectChrootChain ---------------------------------------------------

// All three chain links (/, /srv, /srv/sftp-jailer) are root:root, mode 0755.
// Each link should be flagged RootOwned + NoGroupWrite + NoOtherWrite.
func TestDetectChrootChain_all_good(t *testing.T) {
	f := sysops.NewFake()
	good := sysops.FileInfo{UID: 0, GID: 0, Mode: 0o755, IsDir: true}
	f.FileStats["/"] = good
	f.FileStats["/srv"] = good
	f.FileStats["/srv/sftp-jailer"] = good

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)

	require.Equal(t, "/srv/sftp-jailer", r.ChrootChain.Root)
	require.Len(t, r.ChrootChain.Links, 3)
	for _, l := range r.ChrootChain.Links {
		require.False(t, l.Missing)
		require.True(t, l.RootOwned, "link %s should be root:root", l.Path)
		require.True(t, l.NoGroupWrite, "link %s mode 0755 → no group-write", l.Path)
		require.True(t, l.NoOtherWrite, "link %s mode 0755 → no other-write", l.Path)
		require.False(t, l.IsSymlink)
	}
}

// Group-write bit on the chroot root must be flagged NoGroupWrite=false.
func TestDetectChrootChain_group_write_set(t *testing.T) {
	f := sysops.NewFake()
	f.FileStats["/"] = sysops.FileInfo{UID: 0, GID: 0, Mode: 0o755, IsDir: true}
	f.FileStats["/srv"] = sysops.FileInfo{UID: 0, GID: 0, Mode: 0o755, IsDir: true}
	f.FileStats["/srv/sftp-jailer"] = sysops.FileInfo{UID: 0, GID: 0, Mode: 0o775, IsDir: true}

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)

	require.Len(t, r.ChrootChain.Links, 3)
	require.False(t, r.ChrootChain.Links[2].NoGroupWrite,
		"mode 0775 has group-write bit; detector must flag it")
	require.True(t, r.ChrootChain.Links[2].NoOtherWrite)
}

// A missing chroot root must be flagged Missing=true on that link; no panic.
func TestDetectChrootChain_missing_root(t *testing.T) {
	f := sysops.NewFake()
	f.FileStats["/"] = sysops.FileInfo{UID: 0, GID: 0, Mode: 0o755, IsDir: true}
	f.FileStats["/srv"] = sysops.FileInfo{UID: 0, GID: 0, Mode: 0o755, IsDir: true}
	// /srv/sftp-jailer NOT in FileStats → Fake returns fs.ErrNotExist

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)

	found := false
	for _, l := range r.ChrootChain.Links {
		if l.Missing {
			require.Equal(t, "/srv/sftp-jailer", l.Path)
			found = true
		}
	}
	require.True(t, found, "missing chroot root must be reported with Missing=true")
}

// Intermediate symlink is flagged IsSymlink=true (OpenSSH rejects this).
func TestDetectChrootChain_intermediate_symlink(t *testing.T) {
	f := sysops.NewFake()
	f.FileStats["/"] = sysops.FileInfo{UID: 0, GID: 0, Mode: 0o755, IsDir: true}
	f.FileStats["/srv"] = sysops.FileInfo{UID: 0, GID: 0, Mode: 0o777, IsLink: true}
	f.FileStats["/srv/sftp-jailer"] = sysops.FileInfo{UID: 0, GID: 0, Mode: 0o755, IsDir: true}

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	// Find /srv and confirm symlink flag.
	for _, l := range r.ChrootChain.Links {
		if l.Path == "/srv" {
			require.True(t, l.IsSymlink, "intermediate symlink must be flagged")
		}
	}
}

// ---- detectUfwIPv6 -------------------------------------------------------

// IPV6=no → Warning=true, Value="no".
func TestDetectUfwIPv6_no_warns(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/ufw/ipv6-no.txt")
	require.NoError(t, err)

	f := sysops.NewFake()
	f.Files["/etc/default/ufw"] = b

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, "no", r.UfwIPv6.Value)
	require.True(t, r.UfwIPv6.Warning)
	require.False(t, r.UfwIPv6.Missing)
}

// IPV6=yes → Warning=false, Value="yes".
func TestDetectUfwIPv6_yes_ok(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/ufw/ipv6-yes.txt")
	require.NoError(t, err)

	f := sysops.NewFake()
	f.Files["/etc/default/ufw"] = b

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, "yes", r.UfwIPv6.Value)
	require.False(t, r.UfwIPv6.Warning)
}

// Missing /etc/default/ufw → Missing=true (no warning — ufw may simply not
// be installed).
func TestDetectUfwIPv6_missing_file(t *testing.T) {
	f := sysops.NewFake()
	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.True(t, r.UfwIPv6.Missing)
}

// File present but no IPV6= line → Value="unset", Warning=true.
func TestDetectUfwIPv6_unset(t *testing.T) {
	f := sysops.NewFake()
	f.Files["/etc/default/ufw"] = []byte("IPV4=yes\n")
	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, "unset", r.UfwIPv6.Value)
	require.True(t, r.UfwIPv6.Warning)
}

// Quoted IPV6="no" must still parse to Value="no" with quotes stripped.
func TestDetectUfwIPv6_quoted(t *testing.T) {
	f := sysops.NewFake()
	f.Files["/etc/default/ufw"] = []byte(`IPV4=yes
IPV6="no"
`)
	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, "no", r.UfwIPv6.Value)
	require.True(t, r.UfwIPv6.Warning)
}

// ---- detectAppArmor ------------------------------------------------------

// Enforce mode → Available=true, SshdLoaded=true, Warning=true (pitfall A5).
func TestDetectAppArmor_enforce_warns(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/aa-status/enforce.json")
	require.NoError(t, err)

	f := sysops.NewFake()
	f.ExecResponses["aa-status --json"] = sysops.ExecResult{Stdout: b, ExitCode: 0}

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.True(t, r.AppArmor.Available)
	require.True(t, r.AppArmor.SshdLoaded)
	require.Equal(t, "enforce", r.AppArmor.SshdMode)
	require.True(t, r.AppArmor.Warning, "pitfall A5: enforce-mode sshd must warn")
}

// Complain mode → Warning=false.
func TestDetectAppArmor_complain_ok(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/aa-status/complain.json")
	require.NoError(t, err)

	f := sysops.NewFake()
	f.ExecResponses["aa-status --json"] = sysops.ExecResult{Stdout: b, ExitCode: 0}

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, "complain", r.AppArmor.SshdMode)
	require.False(t, r.AppArmor.Warning)
}

// Binary not installed → Available=false. The detector must NOT error the
// overall report.
func TestDetectAppArmor_not_installed(t *testing.T) {
	f := sysops.NewFake()
	// No ExecResponse scripted → Fake returns a generic "no scripted
	// response" error. We also test a more realistic ENOENT-style error
	// via ExecError below; for now just assert that a missing binary
	// degrades gracefully.
	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.False(t, r.AppArmor.Available)
}

// Malformed JSON → Available=false (the detector must not propagate the
// parse error up — it's just a degraded state).
func TestDetectAppArmor_malformed_json(t *testing.T) {
	f := sysops.NewFake()
	f.ExecResponses["aa-status --json"] = sysops.ExecResult{Stdout: []byte("not json {{{"), ExitCode: 0}

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.False(t, r.AppArmor.Available)
}

// ---- detectNftConsumers --------------------------------------------------

func TestDetectNftConsumers_docker(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/nft/docker-present.json")
	require.NoError(t, err)

	f := sysops.NewFake()
	f.ExecResponses["nft -j list ruleset"] = sysops.ExecResult{Stdout: b, ExitCode: 0}

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.True(t, r.NftConsumers.Available)
	require.True(t, r.NftConsumers.DockerDetected)
	require.False(t, r.NftConsumers.TailscaleDetected)
}

func TestDetectNftConsumers_tailscale(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/nft/tailscale-present.json")
	require.NoError(t, err)

	f := sysops.NewFake()
	f.ExecResponses["nft -j list ruleset"] = sysops.ExecResult{Stdout: b, ExitCode: 0}

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.True(t, r.NftConsumers.Available)
	require.False(t, r.NftConsumers.DockerDetected)
	require.True(t, r.NftConsumers.TailscaleDetected)
}

func TestDetectNftConsumers_clean(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/nft/clean.json")
	require.NoError(t, err)

	f := sysops.NewFake()
	f.ExecResponses["nft -j list ruleset"] = sysops.ExecResult{Stdout: b, ExitCode: 0}

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.True(t, r.NftConsumers.Available)
	require.False(t, r.NftConsumers.DockerDetected)
	require.False(t, r.NftConsumers.TailscaleDetected)
}

// Exec error (binary missing) → Available=false, no panic, no overall error.
func TestDetectNftConsumers_exec_error(t *testing.T) {
	f := sysops.NewFake()
	f.ExecError = errors.New("nft not installed")

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.False(t, r.NftConsumers.Available)
}

// ---- detectSubsystem -----------------------------------------------------

func TestDetectSubsystem_internal(t *testing.T) {
	f := sysops.NewFake()
	f.SshdConfig = map[string][]string{
		"subsystem": {"sftp internal-sftp -f AUTHPRIV -l INFO"},
	}
	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.True(t, r.Subsystem.IsInternal)
	require.False(t, r.Subsystem.Warning)
	require.Equal(t, "internal-sftp -f AUTHPRIV -l INFO", r.Subsystem.Target)
	require.False(t, r.Subsystem.Missing)
}

func TestDetectSubsystem_external_warns(t *testing.T) {
	f := sysops.NewFake()
	f.SshdConfig = map[string][]string{
		"subsystem": {"sftp /usr/lib/openssh/sftp-server"},
	}
	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.False(t, r.Subsystem.IsInternal)
	require.True(t, r.Subsystem.Warning)
	require.Equal(t, "/usr/lib/openssh/sftp-server", r.Subsystem.Target)
}

func TestDetectSubsystem_missing(t *testing.T) {
	f := sysops.NewFake()
	f.SshdConfig = map[string][]string{} // empty map → no subsystem key
	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)
	require.True(t, r.Subsystem.Missing)
}

// ---- Service.Run integration --------------------------------------------

// A fake scripted for every detector's happy path returns a fully-populated
// report with no error.
func TestService_Run_all_detectors(t *testing.T) {
	dropIn, err := os.ReadFile("../../../testdata/sshd_config/50-sftp-jailer-canonical.conf")
	require.NoError(t, err)
	aa, err := os.ReadFile("../../../testdata/aa-status/complain.json")
	require.NoError(t, err)
	nftClean, err := os.ReadFile("../../../testdata/nft/clean.json")
	require.NoError(t, err)
	ufw, err := os.ReadFile("../../../testdata/ufw/ipv6-yes.txt")
	require.NoError(t, err)

	f := sysops.NewFake()
	f.GlobResults["/etc/ssh/sshd_config.d/*.conf"] = []string{"/etc/ssh/sshd_config.d/50-sftp-jailer.conf"}
	f.Files["/etc/ssh/sshd_config.d/50-sftp-jailer.conf"] = dropIn
	f.Files["/etc/default/ufw"] = ufw
	good := sysops.FileInfo{UID: 0, GID: 0, Mode: 0o755, IsDir: true}
	f.FileStats["/"] = good
	f.FileStats["/srv"] = good
	f.FileStats["/srv/sftp-jailer"] = good
	f.ExecResponses["aa-status --json"] = sysops.ExecResult{Stdout: aa, ExitCode: 0}
	f.ExecResponses["nft -j list ruleset"] = sysops.ExecResult{Stdout: nftClean, ExitCode: 0}
	f.SshdConfig = map[string][]string{
		"subsystem": {"sftp internal-sftp -f AUTHPRIV -l INFO"},
	}

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err)

	require.True(t, r.SshdDropIns.ContainsChrootMatch)
	require.Len(t, r.ChrootChain.Links, 3)
	require.Equal(t, "yes", r.UfwIPv6.Value)
	require.True(t, r.AppArmor.Available)
	require.True(t, r.NftConsumers.Available)
	require.True(t, r.Subsystem.IsInternal)
}

// Partial failure: aa-status errors → overall Run still returns nil error.
func TestService_Run_partial_failure_ok(t *testing.T) {
	f := sysops.NewFake()
	// Only aa-status scripted to fail; everything else degrades gracefully.
	f.ExecError = errors.New("catastrophic")

	s := doctor.New(f)
	r, err := s.Run(context.Background())
	require.NoError(t, err, "partial detector failures do not error the report")
	require.False(t, r.AppArmor.Available)
	require.False(t, r.NftConsumers.Available)
}

// ---- Regression: fs.ErrNotExist typed error stays ErrNotExist -----------

// The Fake returns fs.ErrNotExist for missing files. If the detector wraps
// it, the typed check via errors.Is(... fs.ErrNotExist) still works.
func TestDetectUfwIPv6_errors_is_fs_errnotexist(t *testing.T) {
	f := sysops.NewFake()
	_, err := f.ReadFile(context.Background(), "/does/not/exist")
	require.True(t, errors.Is(err, fs.ErrNotExist))
}

// ---- Phase 3 plan 03-06: Service.Ops / ChrootRoot / NeedsCanonicalApply ----

// Service.Ops returns exactly the SystemOps handle passed to New — pointer
// equality, not a copy. M-APPLY-SETUP relies on this single-handle ownership
// (the Fake's recorded Calls slice must reflect modal-driven invocations).
func TestService_OpsAccessor_returns_handle_passed_to_New(t *testing.T) {
	f := sysops.NewFake()
	svc := doctor.New(f)
	require.Same(t, f, svc.Ops(), "Service.Ops must return the same SystemOps handle passed to New")
}

// Service.ChrootRoot returns the default /srv/sftp-jailer in absence of any
// override. Phase 3's M-APPLY-SETUP seeds its proposed-root textinput from
// this value; the modal then re-runs preflight against the real filesystem.
func TestService_ChrootRoot_returns_default(t *testing.T) {
	f := sysops.NewFake()
	svc := doctor.New(f)
	require.Equal(t, "/srv/sftp-jailer", svc.ChrootRoot())
}

// NeedsCanonicalApply: missing drop-in (SETUP-02 / D-07 gap) → true.
func TestNeedsCanonicalApply_missing_dropin_true(t *testing.T) {
	rep := model.DoctorReport{
		SshdDropIns: model.SshdDropInReport{ContainsChrootMatch: false},
		ChrootChain: model.ChrootChainReport{
			Root: "/srv/sftp-jailer",
			Links: []model.ChrootChainLink{
				{Path: "/", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
			},
		},
		Subsystem: model.SubsystemReport{IsInternal: true},
	}
	require.True(t, doctor.NeedsCanonicalApply(rep))
}

// NeedsCanonicalApply: clean report (drop-in present, chain clean, internal
// sftp) → false.
func TestNeedsCanonicalApply_clean_report_false(t *testing.T) {
	rep := model.DoctorReport{
		SshdDropIns: model.SshdDropInReport{ContainsChrootMatch: true},
		ChrootChain: model.ChrootChainReport{
			Root: "/srv/sftp-jailer",
			Links: []model.ChrootChainLink{
				{Path: "/", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
				{Path: "/srv", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
				{Path: "/srv/sftp-jailer", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
			},
		},
		Subsystem: model.SubsystemReport{IsInternal: true},
	}
	require.False(t, doctor.NeedsCanonicalApply(rep))
}

// NeedsCanonicalApply: chroot chain has a symlink (pitfall A6) → true.
func TestNeedsCanonicalApply_chroot_chain_symlink_true(t *testing.T) {
	rep := model.DoctorReport{
		SshdDropIns: model.SshdDropInReport{ContainsChrootMatch: true},
		ChrootChain: model.ChrootChainReport{
			Root: "/srv/sftp-jailer",
			Links: []model.ChrootChainLink{
				{Path: "/", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
				{Path: "/srv", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o777, IsSymlink: true},
			},
		},
		Subsystem: model.SubsystemReport{IsInternal: true},
	}
	require.True(t, doctor.NeedsCanonicalApply(rep))
}

// NeedsCanonicalApply: subsystem warning (external sftp-server / pitfall A2)
// → true. SETUP-06 advisory; the modal still surfaces the informational note.
func TestNeedsCanonicalApply_subsystem_warning_true(t *testing.T) {
	rep := model.DoctorReport{
		SshdDropIns: model.SshdDropInReport{ContainsChrootMatch: true},
		ChrootChain: model.ChrootChainReport{
			Root: "/srv/sftp-jailer",
			Links: []model.ChrootChainLink{
				{Path: "/", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
			},
		},
		Subsystem: model.SubsystemReport{Target: "/usr/lib/openssh/sftp-server", Warning: true},
	}
	require.True(t, doctor.NeedsCanonicalApply(rep))
}

// NeedsCanonicalApply: chroot chain group-write on chroot root → true.
func TestNeedsCanonicalApply_chroot_chain_group_write_true(t *testing.T) {
	rep := model.DoctorReport{
		SshdDropIns: model.SshdDropInReport{ContainsChrootMatch: true},
		ChrootChain: model.ChrootChainReport{
			Root: "/srv/sftp-jailer",
			Links: []model.ChrootChainLink{
				{Path: "/", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
				{Path: "/srv", RootOwned: true, NoGroupWrite: false, NoOtherWrite: true, Mode: 0o775},
			},
		},
		Subsystem: model.SubsystemReport{IsInternal: true},
	}
	require.True(t, doctor.NeedsCanonicalApply(rep))
}

// NeedsCanonicalApply: chroot chain entirely Missing (no chroot root yet)
// → false. The first-launch flow takes the SETUP-02 branch via SshdDropIns
// (which will already be flagged), so we don't double-prompt.
func TestNeedsCanonicalApply_chroot_chain_missing_only_false_when_dropin_clean(t *testing.T) {
	rep := model.DoctorReport{
		SshdDropIns: model.SshdDropInReport{ContainsChrootMatch: true},
		ChrootChain: model.ChrootChainReport{
			Root: "/srv/sftp-jailer",
			Links: []model.ChrootChainLink{
				{Path: "/", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
				{Path: "/srv", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
				{Path: "/srv/sftp-jailer", Missing: true},
			},
		},
		Subsystem: model.SubsystemReport{IsInternal: true},
	}
	require.False(t, doctor.NeedsCanonicalApply(rep), "Missing-only links must NOT trip NeedsCanonicalApply (first-launch flow takes the SETUP-02 branch)")
}
