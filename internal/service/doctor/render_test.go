package doctor_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/model"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/service/doctor"
)

// A fully-green report must produce six [OK] rows — one per detector.
func TestRenderText_all_ok(t *testing.T) {
	r := model.DoctorReport{
		SshdDropIns: model.SshdDropInReport{
			Files:               []model.SshdDropInFile{{Path: "/etc/ssh/sshd_config.d/50-sftp-jailer.conf", HasMatchGroup: true}},
			ContainsChrootMatch: true,
		},
		ChrootChain: model.ChrootChainReport{
			Root: "/srv/sftp-jailer",
			Links: []model.ChrootChainLink{
				{Path: "/", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
				{Path: "/srv", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
				{Path: "/srv/sftp-jailer", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
			},
		},
		UfwIPv6:      model.UfwIPv6Report{Value: "yes"},
		AppArmor:     model.AppArmorReport{Available: true, SshdLoaded: true, SshdMode: "complain"},
		NftConsumers: model.NftConsumersReport{Available: true},
		Subsystem:    model.SubsystemReport{Target: "internal-sftp -f AUTHPRIV -l INFO", IsInternal: true},
	}
	got := doctor.RenderText(r)
	require.Contains(t, got, "[OK]   sshd drop-ins")
	require.Contains(t, got, "[OK]   chroot chain /srv/sftp-jailer")
	require.Contains(t, got, "[OK]   ufw IPV6=yes")
	require.Contains(t, got, "[OK]   AppArmor: sshd in complain mode")
	require.Contains(t, got, "[OK]   nftables consumers: clean")
	require.Contains(t, got, "[OK]   subsystem sftp: internal-sftp -f AUTHPRIV -l INFO")
	// Header is present.
	require.True(t, strings.HasPrefix(got, "sftp-jailer doctor\n\n"))
}

// Pitfall A5 retirement: AppArmor enforce mode renders [WARN] with the A5 ref.
func TestRenderText_apparmor_enforce_warns(t *testing.T) {
	r := model.DoctorReport{
		AppArmor: model.AppArmorReport{Available: true, SshdLoaded: true, SshdMode: "enforce", Warning: true},
	}
	got := doctor.RenderText(r)
	require.Contains(t, got, "[WARN] AppArmor: sshd in enforce mode")
	require.Contains(t, got, "pitfall A5")
}

// Pitfall C4 retirement: ufw IPV6=no renders [WARN] with the Launchpad bug ref.
func TestRenderText_ufw_ipv6_no_warns(t *testing.T) {
	r := model.DoctorReport{UfwIPv6: model.UfwIPv6Report{Value: "no", Warning: true}}
	got := doctor.RenderText(r)
	require.Contains(t, got, "[WARN] ufw IPV6=no")
	require.Contains(t, got, "Launchpad #251355")
}

// Pitfall C5 retirement: Docker + Tailscale show as a combined [WARN].
func TestRenderText_nft_consumers_docker_tailscale(t *testing.T) {
	r := model.DoctorReport{NftConsumers: model.NftConsumersReport{
		Available: true, DockerDetected: true, TailscaleDetected: true,
	}}
	got := doctor.RenderText(r)
	require.Contains(t, got, "[WARN] nftables consumers: Docker + Tailscale may desync")
	require.Contains(t, got, "pitfall C5")
}

// Pitfall A2 retirement: external sftp-server target is FAIL, not WARN.
func TestRenderText_subsystem_external_fails(t *testing.T) {
	r := model.DoctorReport{Subsystem: model.SubsystemReport{
		Target: "/usr/lib/openssh/sftp-server", Warning: true,
	}}
	got := doctor.RenderText(r)
	require.Contains(t, got, "[FAIL] subsystem sftp: /usr/lib/openssh/sftp-server")
	require.Contains(t, got, "pitfall A2")
}

// Missing chroot root is a WARN with the missing path named.
func TestRenderText_chroot_missing(t *testing.T) {
	r := model.DoctorReport{ChrootChain: model.ChrootChainReport{
		Root: "/srv/sftp-jailer",
		Links: []model.ChrootChainLink{
			{Path: "/", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
			{Path: "/srv", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
			{Path: "/srv/sftp-jailer", Missing: true},
		},
	}}
	got := doctor.RenderText(r)
	require.Contains(t, got, "[WARN] chroot chain /srv/sftp-jailer:")
	require.Contains(t, got, "/srv/sftp-jailer missing")
}

// Symlink in the chain is a WARN naming the offending path.
func TestRenderText_chroot_symlink(t *testing.T) {
	r := model.DoctorReport{ChrootChain: model.ChrootChainReport{
		Root: "/srv/sftp-jailer",
		Links: []model.ChrootChainLink{
			{Path: "/", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
			{Path: "/srv", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o777, IsSymlink: true},
		},
	}}
	got := doctor.RenderText(r)
	require.Contains(t, got, "/srv is a symlink")
}

// Group-write bit is named in the WARN message.
func TestRenderText_chroot_group_write(t *testing.T) {
	r := model.DoctorReport{ChrootChain: model.ChrootChainReport{
		Root: "/srv/sftp-jailer",
		Links: []model.ChrootChainLink{
			{Path: "/", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
			{Path: "/srv", RootOwned: true, NoGroupWrite: true, NoOtherWrite: true, Mode: 0o755},
			{Path: "/srv/sftp-jailer", RootOwned: true, NoGroupWrite: false, NoOtherWrite: true, Mode: 0o775},
		},
	}}
	got := doctor.RenderText(r)
	require.Contains(t, got, "has group-write")
}

// Unavailable aa-status / nft degrade to [INFO], NOT [WARN].
func TestRenderText_unavailable_detectors_info(t *testing.T) {
	r := model.DoctorReport{
		AppArmor:     model.AppArmorReport{Available: false},
		NftConsumers: model.NftConsumersReport{Available: false},
	}
	got := doctor.RenderText(r)
	require.Contains(t, got, "[INFO] AppArmor:")
	require.Contains(t, got, "[INFO] nftables consumers:")
	// And crucially, not [WARN] for these unavailable rows.
	require.NotContains(t, got, "[WARN] AppArmor:")
	require.NotContains(t, got, "[WARN] nftables consumers:")
}

// Round-trip the structured report through JSON — confirms every field used
// by the renderer is json-serialisable (supports `doctor --json` output).
func TestDoctorReport_json_roundtrip(t *testing.T) {
	r := model.DoctorReport{
		UfwIPv6:      model.UfwIPv6Report{Value: "yes"},
		AppArmor:     model.AppArmorReport{Available: true, SshdLoaded: true, SshdMode: "complain"},
		NftConsumers: model.NftConsumersReport{Available: true},
	}
	b, err := json.Marshal(r)
	require.NoError(t, err)
	var back model.DoctorReport
	require.NoError(t, json.Unmarshal(b, &back))
	require.Equal(t, r.UfwIPv6.Value, back.UfwIPv6.Value)
	require.Equal(t, r.AppArmor.SshdMode, back.AppArmor.SshdMode)
}
