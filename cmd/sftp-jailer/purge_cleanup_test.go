package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/applysetup"
)

func TestPurgeSshdCleanupCmd_Hidden(t *testing.T) {
	c := purgeSshdCleanupCmd()
	if !c.Hidden {
		t.Errorf("purgeSshdCleanupCmd().Hidden = false, want true")
	}
	if c.Use != "purge-sshd-cleanup" {
		t.Errorf("Use = %q, want %q", c.Use, "purge-sshd-cleanup")
	}
}

func TestRootCmd_RegistersPurgeSshdCleanup(t *testing.T) {
	var found *bool
	for _, sub := range rootCmd().Commands() {
		if sub.Use == "purge-sshd-cleanup" {
			v := sub.Hidden
			found = &v
			break
		}
	}
	if found == nil {
		t.Fatal("rootCmd does not register purge-sshd-cleanup")
	}
	if !*found {
		t.Errorf("registered purge-sshd-cleanup but Hidden = false")
	}
}

func TestRootCmd_HelpOutputExcludesHiddenCmd(t *testing.T) {
	root := rootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"--help"})
	_ = root.Execute() // help exits via cobra's own write; no error expected
	output := buf.String()
	if strings.Contains(output, "purge-sshd-cleanup") {
		t.Errorf("--help output contains 'purge-sshd-cleanup' (should be excluded by Hidden:true). Output:\n%s", output)
	}
}

func TestPurgeStepsFn_OrderAndNames(t *testing.T) {
	steps := purgeStepsFn("/etc/ssh/sshd_config.d/50-sftp-jailer.conf", "/var/backups/sftp-jailer", nil)
	want := []string{"RemoveSshdDropIn", "SshdValidate", "SystemctlReload"}
	if len(steps) != len(want) {
		t.Fatalf("purgeStepsFn returned %d steps, want %d", len(steps), len(want))
	}
	for i, s := range steps {
		if s.Name() != want[i] {
			t.Errorf("steps[%d].Name() = %q, want %q", i, s.Name(), want[i])
		}
	}
}

func TestPurgeBackupDir_OutsideVarLib(t *testing.T) {
	// Documents the load-bearing invariant: backup dir must NOT be under
	// /var/lib/sftp-jailer (postrm wipes that on purge). If a future
	// maintainer moves the backup dir there, this test will fail and
	// surface the regression at PR time.
	if strings.HasPrefix(purgeBackupDir, "/var/lib/sftp-jailer") {
		t.Errorf("purgeBackupDir %q is under /var/lib/sftp-jailer - postrm will wipe backups on purge", purgeBackupDir)
	}
	// Also pin the canonical drop-in path constant - if Phase 3 moves it,
	// the import error will catch it at build time, but this assertion
	// provides a clearer failure message.
	const wantPath = "/etc/ssh/sshd_config.d/50-sftp-jailer.conf"
	if applysetup.DropInPath != wantPath {
		t.Errorf("applysetup.DropInPath = %q, want %q", applysetup.DropInPath, wantPath)
	}
}
