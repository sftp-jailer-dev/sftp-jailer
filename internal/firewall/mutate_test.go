// Package firewall — Phase 4 plan 04-03 Task 2 RED gate.
//
// Tests pin AddRule / DeleteRule / ResolveRuleIDByCommentSource — the single
// firewall WRITER per D-FW-01. Tests live in `package firewall` (internal)
// to mirror enumerate_test.go's positioning.
package firewall

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
)

// scriptUfw seeds the fake with a successful `ufw status numbered` response
// containing the given body. Mirrors enumerate_test.go's helper.
func scriptUfw(f *sysops.Fake, body string) {
	f.ExecResponses["ufw status numbered"] = sysops.ExecResult{
		ExitCode: 0,
		Stdout:   []byte(body),
	}
}

// findCall returns the first FakeCall whose Method == method, or nil.
func findCall(f *sysops.Fake, method string) *sysops.FakeCall {
	for i := range f.Calls {
		if f.Calls[i].Method == method {
			return &f.Calls[i]
		}
	}
	return nil
}

// argHas reports whether call.Args contains needle as a substring of any arg.
func argHas(call *sysops.FakeCall, needle string) bool {
	if call == nil {
		return false
	}
	for _, a := range call.Args {
		if a == needle {
			return true
		}
	}
	return false
}

func TestAddRule_calls_UfwInsert_and_returns_assigned_id_via_post_enumerate(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	// Pre-script the post-insert ufw status output so Enumerate finds
	// alice's rule at position 1.
	scriptUfw(f, `Status: active

To                         Action      From
--                         ------      ----
[ 1] 22/tcp                     ALLOW IN    203.0.113.7/32             # sftpj:v=1:user=alice
`)
	id, err := AddRule(context.Background(), f, "alice", "203.0.113.7/32", "22")
	require.NoError(t, err)
	require.Equal(t, 1, id)

	// f.Calls should contain UfwInsert(pos=1, comment=sftpj:v=1:user=alice)
	insertCall := findCall(f, "UfwInsert")
	require.NotNil(t, insertCall, "UfwInsert must have been called")
	require.True(t, argHas(insertCall, "pos=1"), "UfwInsert called at position 1 per D-FW-02")
	require.True(t, argHas(insertCall, "comment=sftpj:v=1:user=alice"),
		"comment must come from ufwcomment.Encode")
}

func TestAddRule_post_insert_enumerate_failure_returns_error(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	// UfwInsert succeeds (default-nil error), but the Enumerate Exec call
	// fails because no scripted response is set for "ufw status numbered".
	_, err := AddRule(context.Background(), f, "alice", "203.0.113.7/32", "22")
	require.Error(t, err)
}

func TestAddRule_invalid_user_returns_error_without_calling_UfwInsert(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	// Username with a shell metacharacter rejected by the ufwcomment regex.
	_, err := AddRule(context.Background(), f, "alice;rm -rf /", "203.0.113.7/32", "22")
	require.Error(t, err)
	require.Nil(t, findCall(f, "UfwInsert"),
		"UfwInsert MUST NOT be called when ufwcomment.Encode rejects the user")
}

func TestDeleteRule_treats_rule_not_found_as_ErrRuleNotFound(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.UfwDeleteError = errors.New("Could not delete non-existent rule")
	err := DeleteRule(context.Background(), f, 99)
	require.ErrorIs(t, err, ErrRuleNotFound)
}

func TestDeleteRule_no_match_phrase_also_yields_ErrRuleNotFound(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.UfwDeleteError = errors.New("ufw: No matching rule for ID 17")
	err := DeleteRule(context.Background(), f, 17)
	require.ErrorIs(t, err, ErrRuleNotFound)
}

func TestDeleteRule_other_errors_pass_through_wrapped(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.UfwDeleteError = errors.New("permission denied")
	err := DeleteRule(context.Background(), f, 5)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrRuleNotFound)
}

func TestDeleteRule_success_returns_nil(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	require.NoError(t, DeleteRule(context.Background(), f, 1))
	require.NotNil(t, findCall(f, "UfwDelete"), "UfwDelete must have been called")
}

func TestResolveRuleIDByCommentSource_returns_lowest_matching_id(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	scriptUfw(f, `Status: active

[ 1] 22/tcp                     ALLOW IN    203.0.113.7/32             # sftpj:v=1:user=alice
[ 5] 22/tcp                     ALLOW IN    203.0.113.7/32             # sftpj:v=1:user=alice
`)
	id, err := ResolveRuleIDByCommentSource(context.Background(), f, "alice", "203.0.113.7/32")
	require.NoError(t, err)
	require.Equal(t, 1, id) // lowest, even though both match
}

func TestResolveRuleIDByCommentSource_no_match_returns_minus_one(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	scriptUfw(f, `Status: active

[ 1] 22/tcp                     ALLOW IN    Anywhere
`)
	id, err := ResolveRuleIDByCommentSource(context.Background(), f, "alice", "1.2.3.4/32")
	require.NoError(t, err)
	require.Equal(t, -1, id)
}

func TestResolveRuleIDByCommentSource_enumerate_failure_propagates(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	f.ExecError = errors.New("ufw exec crashed")
	_, err := ResolveRuleIDByCommentSource(context.Background(), f, "alice", "1.2.3.4/32")
	require.Error(t, err)
}
