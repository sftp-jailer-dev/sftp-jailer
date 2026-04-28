package sysops

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// Plan 04-12 (gap closure): ExecResponseQueue mechanism tests.
//
// The queue is a FIFO drain map<key, []ExecResult> that lets tests script
// STATEFUL responses across successive Exec calls — e.g. a `ufw status
// numbered` invocation that returns a different rule listing on each call
// to model ufw's ID compaction after each delete (see plan 04-12's
// NewUfwDeleteCatchAllByEnumerateStep tests).

func TestFake_ExecResponseQueue_drains_FIFO(t *testing.T) {
	t.Parallel()
	f := NewFake()
	// Three distinct stdout payloads for "ufw status numbered".
	f.ExecResponseQueue["ufw status numbered"] = []ExecResult{
		{ExitCode: 0, Stdout: []byte("call-1")},
		{ExitCode: 0, Stdout: []byte("call-2")},
		{ExitCode: 0, Stdout: []byte("call-3")},
	}
	for i, want := range []string{"call-1", "call-2", "call-3"} {
		res, err := f.Exec(context.Background(), "ufw", "status", "numbered")
		require.NoError(t, err, "iteration %d", i)
		require.Equal(t, want, string(res.Stdout), "iteration %d FIFO order broken", i)
	}
	// Queue is now empty; no ExecResponses fallback exists for the same key.
	_, err := f.Exec(context.Background(), "ufw", "status", "numbered")
	require.Error(t, err, "fourth call must fail (queue drained, no ExecResponses entry)")
}

func TestFake_ExecResponseQueue_falls_back_to_ExecResponses(t *testing.T) {
	t.Parallel()
	f := NewFake()
	f.ExecResponseQueue["ufw status numbered"] = []ExecResult{
		{ExitCode: 0, Stdout: []byte("queued-call")},
	}
	f.ExecResponses["ufw status numbered"] = ExecResult{
		ExitCode: 0, Stdout: []byte("fallthrough-call"),
	}
	// First call: queue (FIFO) wins.
	res1, err := f.Exec(context.Background(), "ufw", "status", "numbered")
	require.NoError(t, err)
	require.Equal(t, "queued-call", string(res1.Stdout))
	// Second call: queue empty, ExecResponses wins.
	res2, err := f.Exec(context.Background(), "ufw", "status", "numbered")
	require.NoError(t, err)
	require.Equal(t, "fallthrough-call", string(res2.Stdout))
}

func TestFake_ExecResponseQueue_empty_slice_falls_through(t *testing.T) {
	t.Parallel()
	f := NewFake()
	f.ExecResponseQueue["ufw status numbered"] = []ExecResult{} // present-but-empty
	f.ExecResponses["ufw status numbered"] = ExecResult{
		ExitCode: 0, Stdout: []byte("fallthrough"),
	}
	res, err := f.Exec(context.Background(), "ufw", "status", "numbered")
	require.NoError(t, err)
	require.Equal(t, "fallthrough", string(res.Stdout),
		"present-but-empty queue must not shadow ExecResponses")
}
