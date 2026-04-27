package revert

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/firewall"
)

func TestRenderReverseCommands_add_emits_force_delete(t *testing.T) {
	t.Parallel()
	muts := []PendingMutation{
		{Op: OpAdd, AssignedID: 1, Rule: firewall.Rule{
			User: "alice", Source: "203.0.113.7/32", Port: "22",
		}},
	}
	out := RenderReverseCommands(muts)
	require.Equal(t, []string{"ufw --force delete 1", "ufw reload"}, out)
}

func TestRenderReverseCommands_delete_emits_insert_with_full_qualifiers(t *testing.T) {
	t.Parallel()
	muts := []PendingMutation{
		{Op: OpDelete, Rule: firewall.Rule{
			ID: 5, User: "alice", Source: "203.0.113.7/32", Port: "22",
			RawComment: "sftpj:v=1:user=alice",
		}},
	}
	out := RenderReverseCommands(muts)
	require.Len(t, out, 2)
	require.Contains(t, out[0], "ufw insert 5 allow proto tcp from 203.0.113.7/32 to any port 22 comment 'sftpj:v=1:user=alice'")
	require.Equal(t, "ufw reload", out[1])
}

func TestRenderReverseCommands_mixed_batch(t *testing.T) {
	t.Parallel()
	muts := []PendingMutation{
		{Op: OpAdd, AssignedID: 2, Rule: firewall.Rule{User: "bob", Source: "1.2.3.4/32", Port: "22"}},
		{Op: OpDelete, Rule: firewall.Rule{
			ID: 5, User: "alice", Source: "203.0.113.7/32", Port: "22",
			RawComment: "sftpj:v=1:user=alice",
		}},
	}
	out := RenderReverseCommands(muts)
	require.Len(t, out, 3)
	// First mutation rolled back → emits delete; second → emits insert.
	require.Equal(t, "ufw --force delete 2", out[0])
	require.Contains(t, out[1], "ufw insert 5 allow")
	require.Equal(t, "ufw reload", out[2])
}

func TestRenderReverseCommands_skips_add_with_zero_assigned_id(t *testing.T) {
	t.Parallel()
	// Defensive: malformed input doesn't emit a "delete 0" command.
	muts := []PendingMutation{
		{Op: OpAdd, AssignedID: 0, Rule: firewall.Rule{}},
	}
	out := RenderReverseCommands(muts)
	require.Nil(t, out)
}

func TestRenderReverseCommands_empty_input_returns_nil(t *testing.T) {
	t.Parallel()
	require.Nil(t, RenderReverseCommands(nil))
	require.Nil(t, RenderReverseCommands([]PendingMutation{}))
}

func TestRenderReverseCommands_delete_with_empty_comment_omits_comment_field(t *testing.T) {
	t.Parallel()
	// Catch-all rules (no sftpj comment) — reverse must omit comment clause
	// rather than emit an empty `comment ''`.
	muts := []PendingMutation{
		{Op: OpDelete, Rule: firewall.Rule{
			ID: 3, Source: "Anywhere", Port: "22", RawComment: "",
		}},
	}
	out := RenderReverseCommands(muts)
	require.Len(t, out, 2)
	require.Equal(t, "ufw insert 3 allow proto tcp from Anywhere to any port 22", out[0])
	require.NotContains(t, out[0], "comment")
}
