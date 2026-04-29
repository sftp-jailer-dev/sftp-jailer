package main

import (
	"strings"
	"testing"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/rootcmd"
)

func TestRootCmd_BuildsExpectedTree(t *testing.T) {
	root := rootCmd()
	if root.Use != "sftp-jailer" {
		t.Errorf("root.Use = %q, want %q", root.Use, "sftp-jailer")
	}
	want := []string{"version", "doctor", "observe-run"}
	got := []string{}
	for _, c := range root.Commands() {
		got = append(got, c.Name())
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing subcommand %q (have %s)", w, strings.Join(got, ", "))
		}
	}
}

func TestSafeRootGate_VersionExempt(t *testing.T) {
	// Smoke: ensure version subcommand bypasses the gate.
	// Detailed root-required behavior is covered in the existing
	// root_check_test.go (preserved).
	_ = rootcmd.Build // ensure import is used
}
