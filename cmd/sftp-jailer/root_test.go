package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRootCheckMessage_NonRoot_ReturnsExitMessage(t *testing.T) {
	msg, shouldExit := rootCheckMessage([]string{"doctor"}, 1000)
	require.True(t, shouldExit)
	require.True(t, strings.Contains(msg, "sftp-jailer must run as root") ||
		strings.Contains(msg, "must run as root"),
		"message missing 'must run as root': %q", msg)
	require.Contains(t, msg, "sudo sftp-jailer")
	require.Contains(t, msg, "doctor", "invocation args must be echoed back")
}

func TestRootCheckMessage_Root_ReturnsEmpty(t *testing.T) {
	msg, shouldExit := rootCheckMessage([]string{"doctor"}, 0)
	require.False(t, shouldExit)
	require.Equal(t, "", msg)
}
