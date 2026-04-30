package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/store"

	_ "modernc.org/sqlite"
)

func TestInitDBCmd_Hidden(t *testing.T) {
	c := initDBCmd()
	if !c.Hidden {
		t.Errorf("initDBCmd().Hidden = false, want true")
	}
	if c.Use != "init-db" {
		t.Errorf("Use = %q, want %q", c.Use, "init-db")
	}
	if !strings.HasPrefix(c.Short, "Internal:") {
		t.Errorf("Short = %q, want prefix %q", c.Short, "Internal:")
	}
}

func TestRootCmd_RegistersInitDB(t *testing.T) {
	var found *bool
	for _, sub := range rootCmd().Commands() {
		if sub.Use == "init-db" {
			v := sub.Hidden
			found = &v
			break
		}
	}
	if found == nil {
		t.Fatal("rootCmd does not register init-db")
	}
	if !*found {
		t.Errorf("registered init-db but Hidden = false")
	}
}

func TestRootCmd_HelpOutputExcludesInitDB(t *testing.T) {
	root := rootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"--help"})
	_ = root.Execute()
	output := buf.String()
	if strings.Contains(output, "init-db") {
		t.Errorf("--help output contains 'init-db' (should be excluded by Hidden:true). Output:\n%s", output)
	}
}

// TestInitDB_FreshInstall_CreatesAndMigrates exercises the production code
// path against a clean t.TempDir() — no DB exists, the subcommand creates
// it via store.Open's DSN and migrates to ExpectedSchemaVersion.
func TestInitDB_FreshInstall_CreatesAndMigrates(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "observations.db")

	// Override the test seam.
	origPath := initDBPath
	initDBPath = func() string { return tmp }
	t.Cleanup(func() { initDBPath = origPath })

	cmd := initDBCmd()
	cmd.SetContext(context.Background())
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE on fresh DB returned error: %v", err)
	}

	// Confirm DB now exists at ExpectedSchemaVersion.
	got, err := store.PeekUserVersion(context.Background(), tmp)
	if err != nil {
		t.Fatalf("PeekUserVersion after init-db: %v", err)
	}
	if got != store.ExpectedSchemaVersion {
		t.Errorf("PRAGMA user_version after fresh init-db = %d, want %d", got, store.ExpectedSchemaVersion)
	}
}

// TestInitDB_Idempotent_ReinvokeNoOp confirms re-invocation on an already-
// migrated DB succeeds and leaves the schema unchanged. Mirrors the
// internal/store/store_test.go::TestMigrate_advances_to_expected_version
// contract that Migrate is idempotent.
func TestInitDB_Idempotent_ReinvokeNoOp(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "observations.db")
	origPath := initDBPath
	initDBPath = func() string { return tmp }
	t.Cleanup(func() { initDBPath = origPath })

	cmd := initDBCmd()
	cmd.SetContext(context.Background())

	// First invocation — create + migrate.
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("first RunE: %v", err)
	}
	// Second invocation — must be a no-op.
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("second RunE (idempotent): %v", err)
	}

	got, err := store.PeekUserVersion(context.Background(), tmp)
	if err != nil {
		t.Fatalf("PeekUserVersion after re-invoke: %v", err)
	}
	if got != store.ExpectedSchemaVersion {
		t.Errorf("PRAGMA user_version after re-invoke = %d, want %d", got, store.ExpectedSchemaVersion)
	}
}

// TestInitDB_SchemaDrift_RefusesWithExitCode2 simulates a downgrade-install
// scenario: pre-populate the DB at user_version=999 (higher than this binary's
// ExpectedSchemaVersion=3), then invoke init-db. The OBS-04-style gate must
// refuse with exit code 2 and a clear stderr message.
func TestInitDB_SchemaDrift_RefusesWithExitCode2(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "observations.db")

	// Pre-populate the DB at a "future" schema version. Use the same
	// modernc.org/sqlite driver as production; PRAGMA user_version=N is
	// the canonical way to set the gate value.
	{
		db, err := sql.Open("sqlite", tmp)
		if err != nil {
			t.Fatalf("pre-populate sql.Open: %v", err)
		}
		if _, err := db.Exec("PRAGMA user_version = 999"); err != nil {
			t.Fatalf("pre-populate PRAGMA: %v", err)
		}
		_ = db.Close()
	}

	origPath := initDBPath
	initDBPath = func() string { return tmp }
	t.Cleanup(func() { initDBPath = origPath })

	// Override os.Exit seam to record the code instead of terminating.
	var exitCode int
	origExit := initDBOsExit
	initDBOsExit = func(code int) { exitCode = code }
	t.Cleanup(func() { initDBOsExit = origExit })

	cmd := initDBCmd()
	cmd.SetContext(context.Background())
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE on schema-drift DB returned unexpected error: %v", err)
	}
	if exitCode != 2 {
		t.Errorf("schema-drift exit code = %d, want 2", exitCode)
	}
	wantSubstr := fmt.Sprintf("schema v999 newer than this binary expects (v%d)", store.ExpectedSchemaVersion)
	if !strings.Contains(stderr.String(), wantSubstr) {
		t.Errorf("stderr does not contain %q. Got:\n%s", wantSubstr, stderr.String())
	}
}
