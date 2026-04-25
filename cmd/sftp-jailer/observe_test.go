package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestObserveRunCmd_help_listed: invoking the root cmd with --help lists
// `observe-run` as a subcommand.
func TestObserveRunCmd_help_listed(t *testing.T) {
	root := rootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"--help"})
	require.NoError(t, root.Execute())
	require.Contains(t, buf.String(), "observe-run")
}

// TestObserveRunCmd_flags: `observe-run --help` lists every advertised flag.
func TestObserveRunCmd_flags(t *testing.T) {
	root := rootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"observe-run", "--help"})
	require.NoError(t, root.Execute())
	out := buf.String()

	for _, want := range []string{"--cursor", "--db", "--config", "--since", "--quiet"} {
		require.Contains(t, out, want, "missing flag in help: %s", want)
	}
}

// TestSchemaCheck_drift_returns_true: schemaCheck helper used by observeRunCmd
// returns drift=true when the on-disk user_version exceeds the binary's
// ExpectedSchemaVersion.
func TestSchemaCheck_drift_returns_true(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "drift.db")

	// Create the file with user_version=99 — well above ExpectedSchemaVersion.
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	_, err = db.Exec(`PRAGMA user_version = 99`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	drift, current, err := schemaCheck(context.Background(), dbPath)
	require.NoError(t, err)
	require.True(t, drift, "user_version=99 must trigger drift gate")
	require.Equal(t, 99, current)
}

// TestSchemaCheck_no_drift_returns_false: a fresh DB starts at user_version=0,
// which is ≤ ExpectedSchemaVersion (drift=false).
func TestSchemaCheck_no_drift_returns_false(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fresh.db")
	drift, current, err := schemaCheck(context.Background(), dbPath)
	require.NoError(t, err)
	require.False(t, drift, "fresh DB has user_version=0; no drift")
	require.Equal(t, 0, current)
}

// TestObserveRunCmd_OBS04_schema_drift_exits_with_message: when observe-run
// is invoked against a DB whose user_version exceeds ExpectedSchemaVersion,
// the cmd writes the OBS-04 error message to stderr and signals the gate.
//
// The implementation calls os.Exit(2) on drift; we test the gate at the
// schemaCheck helper layer (above) rather than catching os.Exit at the
// cobra layer, which is fragile. The textual contract is asserted via the
// formatted error string here.
func TestObserveRunCmd_OBS04_message_format(t *testing.T) {
	msg := schemaDriftMessage(99, 2)
	require.Contains(t, msg, "schema v99")
	require.Contains(t, msg, "v2")
	require.Contains(t, msg, "apt upgrade sftp-jailer")
}

// TestObserveRunCmd_default_flag_values: verify the default flag values
// match the production /var/lib/sftp-jailer + /etc paths.
func TestObserveRunCmd_default_flag_values(t *testing.T) {
	c := observeRunCmd()
	for _, name := range []string{"cursor", "db", "config", "since", "quiet"} {
		f := c.Flags().Lookup(name)
		require.NotNil(t, f, "missing flag: %s", name)
	}
	require.Equal(t, "/var/lib/sftp-jailer/observer.cursor", c.Flags().Lookup("cursor").DefValue)
	require.Equal(t, "/var/lib/sftp-jailer/observations.db", c.Flags().Lookup("db").DefValue)
	require.Equal(t, "/etc/sftp-jailer/config.yaml", c.Flags().Lookup("config").DefValue)
	require.Equal(t, "false", c.Flags().Lookup("quiet").DefValue)
}

// keep a sentinel use so unused-import linter stays quiet if helpers move.
var _ = fmt.Sprintf
var _ = strings.HasPrefix
