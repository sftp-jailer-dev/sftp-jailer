package rootcmd_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/rootcmd"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/version"
)

// Test_VersionFlag_and_Subcommand_byte_identical asserts the v1.2.1 fix
// for `sftp-jailer --version` (issue: previously errored "unknown flag").
// Both surfaces must compose `sftp-jailer {Version} - {ProjectURL}\n`
// from internal/version, byte-for-byte.
func Test_VersionFlag_and_Subcommand_byte_identical(t *testing.T) {
	// Save and restore the package vars so this test does not leak state
	// into siblings that may also touch internal/version.
	origVersion := version.Version
	origURL := version.ProjectURL
	t.Cleanup(func() {
		version.Version = origVersion
		version.ProjectURL = origURL
	})
	version.Version = "1.2.1"
	version.ProjectURL = "https://sftp-jailer.com"

	expected := "sftp-jailer 1.2.1 - https://sftp-jailer.com\n"

	// Stub version subcommand (mirrors cmd/sftp-jailer/main.go's body).
	newVersionSub := func() *cobra.Command {
		return &cobra.Command{
			Use: "version",
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Fprintf(cmd.OutOrStdout(), "sftp-jailer %s - %s\n", version.Version, version.ProjectURL)
				return nil
			},
		}
	}

	// Run --version
	flagBuf := &bytes.Buffer{}
	flagCmd := rootcmd.Build(rootcmd.Opts{Subcommands: []*cobra.Command{newVersionSub()}})
	flagCmd.SetOut(flagBuf)
	flagCmd.SetErr(flagBuf)
	flagCmd.SetArgs([]string{"--version"})
	require.NoError(t, flagCmd.Execute())

	// Run version subcommand
	subBuf := &bytes.Buffer{}
	subCmd := rootcmd.Build(rootcmd.Opts{Subcommands: []*cobra.Command{newVersionSub()}})
	subCmd.SetOut(subBuf)
	subCmd.SetErr(subBuf)
	subCmd.SetArgs([]string{"version"})
	require.NoError(t, subCmd.Execute())

	require.Equal(t, expected, flagBuf.String(), "--version output must match the expected line")
	require.Equal(t, expected, subBuf.String(), "version subcommand output must match the expected line")
	require.Equal(t, flagBuf.String(), subBuf.String(), "--version and version subcommand must be byte-identical")
}
