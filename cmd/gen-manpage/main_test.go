package main

import "testing"

func TestGatherSubcommands_HasExpectedNames(t *testing.T) {
	got := gatherSubcommands()
	want := []string{"version", "doctor", "observe-run"}
	if len(got) != len(want) {
		t.Fatalf("gatherSubcommands returned %d cmds, want %d", len(got), len(want))
	}
	for i, c := range got {
		if c.Name() != want[i] {
			t.Errorf("subcommand[%d].Name() = %q, want %q", i, c.Name(), want[i])
		}
	}
}
