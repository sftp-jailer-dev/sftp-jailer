package doctorscreen_test

import (
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/model"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/service/doctor"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	doctorscreen "github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/doctor"
)

func keyPress(s string) tea.KeyPressMsg {
	if s == "esc" {
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape, Text: ""})
	}
	r := rune(s[0])
	return tea.KeyPressMsg(tea.Key{Code: r, Text: s})
}

// The screen starts in the loading state; View shows a placeholder and no
// panic from View-on-no-report.
func TestDoctorScreen_initial_loading_view(t *testing.T) {
	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	v := s.View()
	require.Contains(t, v, "running diagnostic")
}

// After LoadReportForTest, View renders the six report rows and carries the
// expected severity prefixes.
func TestDoctorScreen_view_after_report(t *testing.T) {
	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	s.LoadReportForTest(model.DoctorReport{
		UfwIPv6:   model.UfwIPv6Report{Value: "no", Warning: true},
		AppArmor:  model.AppArmorReport{Available: true, SshdLoaded: true, SshdMode: "enforce", Warning: true},
		Subsystem: model.SubsystemReport{Target: "/usr/lib/openssh/sftp-server", Warning: true},
	})
	v := s.View()
	require.Contains(t, v, "ufw IPV6=no")
	require.Contains(t, v, "sshd in enforce mode")
	require.Contains(t, v, "subsystem sftp")
}

// `esc` emits a PopCmd.
func TestDoctorScreen_esc_pops(t *testing.T) {
	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	s.LoadReportForTest(model.DoctorReport{})

	_, cmd := s.Update(keyPress("esc"))
	require.NotNil(t, cmd)
	msg := cmd()
	nm, ok := msg.(nav.Msg)
	require.True(t, ok, "expected nav.Msg, got %T", msg)
	require.Equal(t, nav.Pop, nm.Intent)
}

// `q` also pops.
func TestDoctorScreen_q_pops(t *testing.T) {
	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)
	s.LoadReportForTest(model.DoctorReport{})

	_, cmd := s.Update(keyPress("q"))
	require.NotNil(t, cmd)
	nm := cmd().(nav.Msg)
	require.Equal(t, nav.Pop, nm.Intent)
}

// `c` returns a non-nil batch cmd (SetClipboard + Toast flash) once a
// report is loaded; with no report, no command is emitted.
func TestDoctorScreen_c_copies_when_report_loaded(t *testing.T) {
	svc := doctor.New(sysops.NewFake())
	s := doctorscreen.New(svc)

	// No report yet → no clipboard action.
	_, cmd := s.Update(keyPress("c"))
	require.Nil(t, cmd, "copy before load must not emit a tea.Cmd")

	s.LoadReportForTest(model.DoctorReport{
		UfwIPv6: model.UfwIPv6Report{Value: "yes"},
	})
	_, cmd = s.Update(keyPress("c"))
	require.NotNil(t, cmd, "copy after load must emit a tea.Cmd")
}

// The Model satisfies nav.Screen (compile-time check via assignment).
func TestDoctorScreen_implements_nav_Screen(t *testing.T) {
	svc := doctor.New(sysops.NewFake())
	var s nav.Screen = doctorscreen.New(svc)
	require.Equal(t, "diagnostic", s.Title())
	require.False(t, s.WantsRawKeys())
	km := s.KeyMap()
	require.NotNil(t, km)
	require.NotEmpty(t, km.ShortHelp())
	require.NotEmpty(t, km.FullHelp())
}

// KeyMap exposes c + esc/q bindings.
func TestDoctorScreen_keymap_bindings(t *testing.T) {
	km := doctorscreen.DefaultKeyMap()
	short := km.ShortHelp()
	require.Len(t, short, 2)
	found := map[string]bool{}
	for _, b := range short {
		for _, k := range b.Keys {
			found[k] = true
		}
	}
	for _, k := range []string{"esc", "q", "c"} {
		require.True(t, found[k], "KeyMap must expose %q", k)
	}
}
