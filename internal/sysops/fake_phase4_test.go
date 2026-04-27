package sysops

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ============================================================================
// Phase 4 (plan 04-01): Fake mirror tests for the 9 new SystemOps mutation
// methods. Pattern mirrors Phase 3 sysops_test.go: each method gets a
// records-typed-argv test and a returns-scripted-error test, plus a
// compile-time interface-conformance assertion at the bottom.
//
// Critical assertion (per CONTEXT.md "Test strategy"):
// TestFakeSystemdRunOnActive_records_verbatim_command pins the FULL
// opts.Command string in the recorded args, so downstream golden-file
// tests can match SAFE-04 ExecStart shell-script bodies.
// ============================================================================

// --- UfwAllow ---

func TestFakeUfwAllow_records_call_with_typed_argv(t *testing.T) {
	f := NewFake()
	err := f.UfwAllow(context.Background(), UfwAllowOpts{
		Proto:   "tcp",
		Source:  "203.0.113.7/32",
		Port:    "22",
		Comment: "sftpj:v=1:user=alice",
	})
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "UfwAllow", f.Calls[0].Method)
	require.Equal(t, []string{
		"proto=tcp",
		"src=203.0.113.7/32",
		"port=22",
		"comment=sftpj:v=1:user=alice",
	}, f.Calls[0].Args)
}

func TestFakeUfwAllow_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("ufw busy")
	f.UfwAllowError = scripted
	err := f.UfwAllow(context.Background(), UfwAllowOpts{Source: "x", Port: "22"})
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "UfwAllow", f.Calls[0].Method)
}

// --- UfwInsert ---

func TestFakeUfwInsert_records_position_and_comment(t *testing.T) {
	f := NewFake()
	err := f.UfwInsert(context.Background(), 1, UfwAllowOpts{
		Proto:   "tcp",
		Source:  "203.0.113.7/32",
		Port:    "22",
		Comment: "sftpj:v=1:user=alice",
	})
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "UfwInsert", f.Calls[0].Method)
	require.Equal(t, []string{
		"pos=1",
		"proto=tcp",
		"src=203.0.113.7/32",
		"port=22",
		"comment=sftpj:v=1:user=alice",
	}, f.Calls[0].Args)
}

func TestFakeUfwInsert_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("invalid CIDR")
	f.UfwInsertError = scripted
	err := f.UfwInsert(context.Background(), 1, UfwAllowOpts{Source: "x", Port: "22"})
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

// --- UfwDelete ---

func TestFakeUfwDelete_records_id(t *testing.T) {
	f := NewFake()
	err := f.UfwDelete(context.Background(), 7)
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "UfwDelete", f.Calls[0].Method)
	require.Equal(t, []string{"id=7"}, f.Calls[0].Args)
}

func TestFakeUfwDelete_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("not found")
	f.UfwDeleteError = scripted
	err := f.UfwDelete(context.Background(), 99)
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

// --- UfwReload ---

func TestFakeUfwReload_records_call(t *testing.T) {
	f := NewFake()
	err := f.UfwReload(context.Background())
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "UfwReload", f.Calls[0].Method)
	require.Empty(t, f.Calls[0].Args)
}

func TestFakeUfwReload_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("ufw reload failed")
	f.UfwReloadError = scripted
	err := f.UfwReload(context.Background())
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

// --- HasPublicIPv6 ---

func TestFakeHasPublicIPv6_default_returns_false_nil(t *testing.T) {
	f := NewFake()
	got, err := f.HasPublicIPv6(context.Background())
	require.NoError(t, err)
	require.False(t, got, "default fixture must report no public v6")
	require.Len(t, f.Calls, 1)
	require.Equal(t, "HasPublicIPv6", f.Calls[0].Method)
}

func TestFakeHasPublicIPv6_returns_scripted_bool(t *testing.T) {
	f := NewFake()
	f.HasPublicIPv6Result = true
	got, err := f.HasPublicIPv6(context.Background())
	require.NoError(t, err)
	require.True(t, got)
}

func TestFakeHasPublicIPv6_returns_scripted_error(t *testing.T) {
	f := NewFake()
	scripted := errors.New("ip exec failed")
	f.HasPublicIPv6Error = scripted
	_, err := f.HasPublicIPv6(context.Background())
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

// --- RewriteUfwIPV6 ---

func TestFakeRewriteUfwIPV6_records_value(t *testing.T) {
	f := NewFake()
	err := f.RewriteUfwIPV6(context.Background(), "yes")
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "RewriteUfwIPV6", f.Calls[0].Method)
	require.Equal(t, []string{"value=yes"}, f.Calls[0].Args)
}

func TestFakeRewriteUfwIPV6_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("disk full")
	f.RewriteUfwIPV6Error = scripted
	err := f.RewriteUfwIPV6(context.Background(), "no")
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

// --- SystemdRunOnActive (CRITICAL: verbatim command recording) ---

func TestFakeSystemdRunOnActive_records_verbatim_command(t *testing.T) {
	f := NewFake()
	// Reverse-shell body resembling a real SAFE-04 revert payload.
	cmd := "ufw --force delete 3; ufw insert 1 allow proto tcp from 203.0.113.7/32 to any port 22 comment sftpj:v=1:user=alice; ufw reload"
	err := f.SystemdRunOnActive(context.Background(), SystemdRunOpts{
		OnActive: 3 * time.Minute,
		UnitName: "sftpj-revert-1234567890.service",
		Command:  cmd,
	})
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "SystemdRunOnActive", f.Calls[0].Method)
	// Critical pin (D-S04-08): the cmd= entry is the verbatim Command — no
	// truncation, no shell-quoting, no normalization. Tests that golden-file
	// ExecStart bodies depend on this contract.
	require.Equal(t, []string{
		"on-active=3m0s",
		"unit=sftpj-revert-1234567890.service",
		"cmd=" + cmd,
	}, f.Calls[0].Args)
}

func TestFakeSystemdRunOnActive_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("dbus failed")
	f.SystemdRunError = scripted
	err := f.SystemdRunOnActive(context.Background(), SystemdRunOpts{
		OnActive: time.Minute,
		UnitName: "sftpj-revert-x.service",
		Command:  "ufw reload",
	})
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

// --- SystemctlStop ---

func TestFakeSystemctlStop_records_unit(t *testing.T) {
	f := NewFake()
	err := f.SystemctlStop(context.Background(), "sftpj-revert-1234.service")
	require.NoError(t, err)
	require.Len(t, f.Calls, 1)
	require.Equal(t, "SystemctlStop", f.Calls[0].Method)
	require.Equal(t, []string{"unit=sftpj-revert-1234.service"}, f.Calls[0].Args)
}

func TestFakeSystemctlStop_returns_scripted_error_and_still_records(t *testing.T) {
	f := NewFake()
	scripted := errors.New("unit not found")
	f.SystemctlStopError = scripted
	err := f.SystemctlStop(context.Background(), "ghost.service")
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

// --- SystemctlIsActive ---

func TestFakeSystemctlIsActive_returns_scripted_pair_inactive(t *testing.T) {
	f := NewFake()
	got, err := f.SystemctlIsActive(context.Background(), "x.service")
	require.NoError(t, err)
	require.False(t, got, "default fixture must report inactive")
	require.Len(t, f.Calls, 1)
	require.Equal(t, "SystemctlIsActive", f.Calls[0].Method)
	require.Equal(t, []string{"unit=x.service"}, f.Calls[0].Args)
}

func TestFakeSystemctlIsActive_returns_scripted_pair_active(t *testing.T) {
	f := NewFake()
	f.SystemctlIsActiveResult = true
	got, err := f.SystemctlIsActive(context.Background(), "x.service")
	require.NoError(t, err)
	require.True(t, got)
}

func TestFakeSystemctlIsActive_returns_scripted_pair_error(t *testing.T) {
	f := NewFake()
	scripted := errors.New("dbus exploded")
	f.SystemctlIsActiveError = scripted
	_, err := f.SystemctlIsActive(context.Background(), "x.service")
	require.ErrorIs(t, err, scripted)
	require.Len(t, f.Calls, 1)
}

// --- Compile-time interface conformance (Phase 4 surface) ---

// TestFake_implements_SystemOps_phase4 is a compile-time guard. The
// declaration `var _ SystemOps = (*Fake)(nil)` ALSO appears in
// sysops_test.go; this duplicate at the Phase 4 boundary documents that
// the new methods participate in the SystemOps surface. If a Phase 4
// method drops out of either Fake or Real, this fails to compile here
// (and in sysops_test.go).
func TestFake_implements_SystemOps_phase4(t *testing.T) {
	var _ SystemOps = (*Fake)(nil)
	var _ SystemOps = (*Real)(nil)
	t.Log("Fake and Real satisfy SystemOps with Phase 4 methods present")
}
