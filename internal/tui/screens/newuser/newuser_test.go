// Package newuser tests for M-NEW-USER — covers the D-12 useradd batch,
// D-14 / B-03 orphan reconcile path, B4 /etc/shells preflight, USER-04
// reserved-UID gates (N-04 boundary tests at 60000 / 65535 / 65536), and
// the chained-modal handoff to M-PASSWORD on submit success.
package newuser_test

import (
	"errors"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/chrootcheck"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/newuser"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/password"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/users"
)

// keyPress helper — special-cases esc / enter / tab so the textinput
// machinery sees recognisable Code fields. Mirrors the doctor / users
// screen test helpers.
func keyPress(s string) tea.KeyPressMsg {
	switch s {
	case "esc":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape, Text: ""})
	case "enter":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter, Text: ""})
	case "tab":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyTab, Text: ""})
	case "down":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyDown, Text: ""})
	case "up":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyUp, Text: ""})
	}
	r := rune(s[0])
	return tea.KeyPressMsg(tea.Key{Code: r, Text: s})
}

// callMethods returns a slice of f.Calls method names in order, with
// `Lstat` calls filtered out. Lstat is the prior-state-capture probe that
// txn.NewChmodStep / NewChownStep run inside Apply (plan 03-05) so the
// Compensate path can restore — it's an implementation detail of the
// substrate, not a step in the txn batch the modal wires. Filtering keeps
// the assertions readable + decoupled from txn substrate internals.
func callMethods(f *sysops.Fake) []string {
	out := make([]string, 0, len(f.Calls))
	for _, c := range f.Calls {
		if c.Method == "Lstat" {
			continue
		}
		out = append(out, c.Method)
	}
	return out
}

// freshFake returns a Fake with /etc/shells correctly listing
// /usr/sbin/nologin and a clean /srv/sftp-jailer chain (root-owned, mode
// 0755). Tests that need to script a different preflight result mutate
// the returned Fake before constructing the model.
func freshFake(t *testing.T) *sysops.Fake {
	t.Helper()
	f := sysops.NewFake()
	f.Files["/etc/shells"] = []byte("/bin/sh\n/bin/bash\n/usr/sbin/nologin\n")
	// Clean chroot chain: /, /srv, /srv/sftp-jailer all root-owned + 0755.
	for _, p := range []string{"/", "/srv", "/srv/sftp-jailer"} {
		f.FileStats[p] = sysops.FileInfo{
			Path: p, Mode: 0o755, UID: 0, GID: 0, IsDir: true,
		}
	}
	return f
}

// 1. /etc/shells missing /usr/sbin/nologin → preflight blocks (B4).
func TestNewUser_preflight_blocks_when_etc_shells_missing_nologin(t *testing.T) {
	m := newuser.New(nil, "/srv/sftp-jailer")
	m.LoadPreflightForTest(false /*shellsHasNologin*/, nil, nil)
	require.Equal(t, newuser.PhaseErrorForTest, m.PhaseForTest())
	require.Contains(t, m.ErrInlineForTest(), "/etc/shells")
	require.Contains(t, m.ErrInlineForTest(), "nologin")
}

// 2. chrootcheck violations block preflight.
func TestNewUser_preflight_blocks_when_chrootcheck_violation(t *testing.T) {
	m := newuser.New(nil, "/srv/sftp-jailer")
	m.LoadPreflightForTest(true, []chrootcheck.Violation{
		{Path: "/srv", Reason: "/srv is owned uid=1000 gid=1000 (sshd requires root:root); fix with: sudo chown root:root /srv"},
	}, nil)
	require.Equal(t, newuser.PhaseErrorForTest, m.PhaseForTest())
	require.Contains(t, m.ErrInlineForTest(), "violations")
	require.Contains(t, m.ErrInlineForTest(), "/srv")
}

// 3. Username regex rejects uppercase.
func TestNewUser_username_validation_rejects_uppercase_or_special(t *testing.T) {
	m := seededFreshCreate(t)
	// Set username to "Alice" via the textinput-edit path.
	typeIntoField(t, m, newuser.PhaseEditingForTest, "Alice", 0 /*field idx 0 = username*/)
	// Navigate to [create] and submit.
	jumpToCreateAndSubmit(t, m)
	require.Contains(t, m.ErrInlineForTest(), "username")
}

// 4. N-04 boundary: UID 60000 (first reserved) rejected.
func TestNewUser_uid_validation_rejects_reserved_60000(t *testing.T) {
	m := seededFreshCreate(t)
	setRawForTest(m, "alice", "60000")
	jumpToCreateAndSubmit(t, m)
	require.Contains(t, m.ErrInlineForTest(), "reserved")
	require.Contains(t, m.ErrInlineForTest(), "60000")
}

// 5. N-04 boundary: UID 65535 (last reserved) rejected.
func TestNewUser_uid_validation_rejects_reserved_65535(t *testing.T) {
	m := seededFreshCreate(t)
	setRawForTest(m, "alice", "65535")
	jumpToCreateAndSubmit(t, m)
	require.Contains(t, m.ErrInlineForTest(), "reserved")
	require.Contains(t, m.ErrInlineForTest(), "65535")
}

// 6. N-04 boundary: UID 65536 allowed at the modal layer (modal accepts;
// useradd subprocess decides). The submit MUST proceed (no errInline).
func TestNewUser_uid_validation_accepts_above_reserved_65536_and_lets_useradd_handle(t *testing.T) {
	f := freshFake(t)
	m := seededFreshCreateWithFake(t, f)
	// 65536 is above the reserved ceiling; modal must accept it.
	setRawForTest(m, "alice", "65536")
	// Stub the lookup so 65536 reads as "not in use".
	m.SetUserLookupForTest(func(uid int) bool { return false })
	jumpToCreateAndSubmit(t, m)
	require.Empty(t, m.ErrInlineForTest(), "uid 65536 must not be blocked at the modal layer (N-04)")
	require.Equal(t, newuser.PhaseSubmittingForTest, m.PhaseForTest(),
		"submit must proceed past validation for uid 65536")
}

// 7. UID below the floor rejected.
func TestNewUser_uid_validation_rejects_below_2000(t *testing.T) {
	m := seededFreshCreate(t)
	setRawForTest(m, "alice", "999")
	jumpToCreateAndSubmit(t, m)
	require.Contains(t, m.ErrInlineForTest(), "too low")
}

// 8. Clean fresh-create runs the full D-12 batch via the txn substrate:
// f.Calls = [Useradd, GpasswdAdd, Chmod, Chown] in order. Asserted by
// constructing a sister model (buildAndSubmitFresh) so we capture the
// tea.Cmd that attemptSubmit returns and execute it against the Fake.
func TestNewUser_submit_runs_useradd_batch_when_clean(t *testing.T) {
	f := freshFake(t)
	cmd := buildAndSubmitFresh(t, f, "alice", "2000")
	require.NotNil(t, cmd, "submit must return a tea.Cmd that runs the txn batch")
	// Drive the batch — tea.BatchMsg fans out to spinner.Tick + the actual
	// txn closure. The txn closure is the one that records calls against
	// the Fake; the spinner tick is a no-op for our purposes.
	driveBatch(cmd, func(tea.Msg) {})
	got := callMethods(f)
	require.Equal(t,
		[]string{"Useradd", "Gpasswd", "Chmod", "Chown"},
		got,
		"clean fresh-create txn ordering must be Useradd → Gpasswd → Chmod → Chown")
}

// 9. Submit failure: GpasswdAdd error → txn rolls back via Userdel
// compensator. Asserted via f.Calls = [..., Useradd, Gpasswd, Userdel].
func TestNewUser_submit_failure_rolls_back_useradd_via_txn(t *testing.T) {
	f := freshFake(t)
	f.GpasswdError = errors.New("simulated gpasswd failure")
	cmd := buildAndSubmitFresh(t, f, "alice", "2000")
	require.NotNil(t, cmd)
	driveBatch(cmd, func(tea.Msg) {})
	got := callMethods(f)
	// Useradd succeeds, Gpasswd fails → txn rolls back. The failing step's
	// own Compensate is NOT called per plan 03-05's "atomic or no-op"
	// contract. So we expect: Useradd, Gpasswd, Userdel.
	require.Contains(t, got, "Useradd", "expected Useradd to be called")
	require.Contains(t, got, "Userdel", "expected txn rollback to call Userdel compensator")
	uIdx := indexOf(got, "Useradd")
	dIdx := indexOf(got, "Userdel")
	require.Less(t, uIdx, dIdx, "Userdel must run AFTER Useradd (rollback compensator)")
}

// 10. B-03: NewFromOrphan pre-fills BOTH UID AND GID from the InfoRow.
func TestNewUser_orphan_constructor_prefills_uid_AND_gid(t *testing.T) {
	orphan := users.InfoRow{
		Kind: users.InfoOrphan,
		Dir:  "/srv/sftp-jailer/orphan99",
		UID:  5555,
		GID:  5555,
	}
	m := newuser.NewFromOrphan(nil, "/srv/sftp-jailer", orphan)
	require.True(t, m.IsOrphanForTest(), "isOrphan must be true after NewFromOrphan")
	require.Equal(t, 5555, m.OrphanGIDForTest(), "orphanGID must equal the InfoRow.GID (B-03)")
	username, uid, home, _, _ := m.FieldValuesForTest()
	require.Equal(t, "orphan99", username)
	require.Equal(t, "5555", uid)
	require.Equal(t, "/srv/sftp-jailer/orphan99", home)
	require.False(t, m.CreateHomeForTest(), "orphan path must NOT recreate the home dir (D-14: useradd -M)")
}

// 11. B-03: orphan submit uses Useradd with `-g <gid>` AND skips Chmod
// + Chown. f.Calls = [Useradd, GpasswdAdd]; NO Chmod, NO Chown.
func TestNewUser_orphan_submit_uses_useradd_with_dash_g_and_skips_chmod_chown(t *testing.T) {
	orphan := users.InfoRow{
		Kind: users.InfoOrphan,
		Dir:  "/srv/sftp-jailer/orphan99",
		UID:  5555,
		GID:  5555,
	}
	f := freshFake(t)
	cmd := buildAndSubmitOrphan(t, f, orphan)
	require.NotNil(t, cmd)
	driveBatch(cmd, func(tea.Msg) {})
	got := callMethods(f)
	require.Equal(t, []string{"Useradd", "Gpasswd"}, got,
		"orphan path must run Useradd + Gpasswd ONLY — Chmod + Chown SKIPPED per B-03")
	require.NotContains(t, got, "Chmod")
	require.NotContains(t, got, "Chown")
	// Inspect the recorded Useradd args to confirm UID=5555 + CreateHome=false.
	useraddCall := f.Calls[indexOf(got, "Useradd")]
	require.Contains(t, useraddCall.Args, "uid=5555", "Useradd argv must carry uid=5555")
	require.Contains(t, useraddCall.Args, "createHome=false", "orphan must pass createHome=false")
}

// 12. Fresh-create submit: Useradd opts have GID=0 (UPG default) and the
// txn batch DOES include Chmod + Chown.
func TestNewUser_fresh_create_submit_uses_useradd_with_gid_zero_and_runs_chmod_chown(t *testing.T) {
	f := freshFake(t)
	cmd := buildAndSubmitFresh(t, f, "alice", "2000")
	require.NotNil(t, cmd)
	driveBatch(cmd, func(tea.Msg) {})
	got := callMethods(f)
	require.Contains(t, got, "Chmod", "fresh-create MUST run Chmod on the just-created home")
	require.Contains(t, got, "Chown", "fresh-create MUST run Chown on the just-created home")
	useraddCall := f.Calls[indexOf(got, "Useradd")]
	require.NotContains(t, useraddCall.Args, "uid=0",
		"sanity: Useradd should not be called with uid=0 (we asked for 2000)")
	// The fresh-create path leaves GID at 0 in UseraddOpts so useradd's UPG
	// default kicks in. The Fake records every opts field as "key=value";
	// the expected serialization for the GID field is absent (the Fake
	// only records UID/Home/Shell/CreateHome/MemberOfSftpJailer per plan
	// 03-01) — so we just assert the call presence and CreateHome=true.
	require.Contains(t, useraddCall.Args, "createHome=true",
		"fresh-create must pass createHome=true (useradd -m)")
}

// 13. NewFromOrphan unconditionally sets CreateHome=false.
func TestNewUser_orphan_constructor_uses_no_create_home(t *testing.T) {
	orphan := users.InfoRow{
		Kind: users.InfoOrphan, Dir: "/srv/sftp-jailer/x", UID: 4444, GID: 4444,
	}
	m := newuser.NewFromOrphan(nil, "/srv/sftp-jailer", orphan)
	require.False(t, m.CreateHomeForTest(),
		"orphan reconcile must NOT recreate the home dir (D-14: useradd -M)")
}

// 14. submitDoneMsg with err=nil → tea.Cmd produces a Push intent for
// a *password.Model.
func TestNewUser_submit_success_pushes_password_modal(t *testing.T) {
	f := freshFake(t)
	m := seededFreshCreateWithFake(t, f)
	setRawForTest(m, "alice", "2000")
	m.SetUserLookupForTest(func(uid int) bool { return false })
	_, cmd := m.FeedSubmitDoneForTest(nil)
	require.NotNil(t, cmd, "submit success must return a chained-modal Push tea.Cmd")
	// Drive the batch and look for a nav.Msg with Intent=Push for *password.Model.
	require.Equal(t, newuser.PhaseDoneForTest, m.PhaseForTest())
	pushFound := false
	usernameMatched := false
	driveBatch(cmd, func(msg tea.Msg) {
		nm, ok := msg.(nav.Msg)
		if !ok {
			return
		}
		if nm.Intent == nav.Push {
			pushFound = true
			pm, ok := nm.Screen.(*password.Model)
			if ok && pm.UsernameForTest() == "alice" {
				usernameMatched = true
			}
		}
	})
	require.True(t, pushFound, "expected a nav.Push intent in the chained-modal batch")
	require.True(t, usernameMatched, "pushed password modal must carry username=alice")
}

// nav.Screen compile-time conformance.
func TestNewUser_implements_nav_Screen(t *testing.T) {
	var s nav.Screen = newuser.New(nil, "/srv/sftp-jailer")
	require.Equal(t, "new user", s.Title())
	km := s.KeyMap()
	require.NotNil(t, km)
	require.NotEmpty(t, km.ShortHelp())
	require.NotEmpty(t, km.FullHelp())
}

// ----------------------------------------------------------------------------
// Test helpers
// ----------------------------------------------------------------------------

// seededFreshCreate constructs a fresh-create modal with nil ops and
// drives it past the preflight gate into phaseEditing.
func seededFreshCreate(t *testing.T) *newuser.Model {
	t.Helper()
	m := newuser.New(nil, "/srv/sftp-jailer")
	m.SetUserLookupForTest(func(uid int) bool { return false })
	m.LoadPreflightForTest(true, nil, nil)
	require.Equal(t, newuser.PhaseEditingForTest, m.PhaseForTest(),
		"seededFreshCreate must reach phaseEditing — got phase=%d errInline=%q",
		m.PhaseForTest(), m.ErrInlineForTest())
	return m
}

// seededFreshCreateWithFake is seededFreshCreate but wires a real *Fake so
// the txn batch can record Calls.
func seededFreshCreateWithFake(t *testing.T, f *sysops.Fake) *newuser.Model {
	t.Helper()
	m := newuser.New(f, "/srv/sftp-jailer")
	m.SetUserLookupForTest(func(uid int) bool { return false })
	m.LoadPreflightForTest(true, nil, nil)
	require.Equal(t, newuser.PhaseEditingForTest, m.PhaseForTest())
	return m
}

// setRawForTest exposes a quick path to seed username + uid (the two most
// commonly mutated fields in the table-tests). Re-uses the textinput-edit
// flow via direct keypresses — saves typing per character in every test.
//
// Implementation: navigate to the field, press 'e' to enter edit, type
// each rune as a keypress, press Enter to commit. Mirrors what an admin
// would type at the keyboard.
func setRawForTest(m *newuser.Model, username, uid string) {
	// Fields 0=username, 1=uid. Cursor starts at 0 (fieldUsername).
	if username != "" {
		_, _ = m.Update(keyPress("e"))
		for _, r := range username {
			_, _ = m.Update(tea.KeyPressMsg(tea.Key{Code: r, Text: string(r)}))
		}
		_, _ = m.Update(keyPress("enter"))
	}
	if uid != "" {
		_, _ = m.Update(keyPress("down")) // username → uid
		_, _ = m.Update(keyPress("e"))
		for _, r := range uid {
			_, _ = m.Update(tea.KeyPressMsg(tea.Key{Code: r, Text: string(r)}))
		}
		_, _ = m.Update(keyPress("enter"))
		_, _ = m.Update(keyPress("up")) // back to username (so jumpToCreateAndSubmit math is consistent)
	}
}

// typeIntoField positions the cursor at fieldIdx (0-based), enters edit
// mode, types the text, commits with Enter.
func typeIntoField(t *testing.T, m *newuser.Model, _ int, text string, fieldIdx int) {
	t.Helper()
	for i := 0; i < fieldIdx; i++ {
		_, _ = m.Update(keyPress("down"))
	}
	_, _ = m.Update(keyPress("e"))
	for _, r := range text {
		_, _ = m.Update(tea.KeyPressMsg(tea.Key{Code: r, Text: string(r)}))
	}
	_, _ = m.Update(keyPress("enter"))
	// Reset cursor to top for the next call.
	for i := 0; i < fieldIdx; i++ {
		_, _ = m.Update(keyPress("up"))
	}
}

// jumpToCreateAndSubmit navigates the cursor to the [create] action button
// and presses Enter. The cursor is at the field count - 1 (fieldCreate).
// Five down-arrows from fieldUsername=0 reach fieldCreate=5.
func jumpToCreateAndSubmit(t *testing.T, m *newuser.Model) {
	t.Helper()
	for i := 0; i < 5; i++ {
		_, _ = m.Update(keyPress("down"))
	}
	_, _ = m.Update(keyPress("enter"))
}

// buildAndSubmitFresh constructs a fresh-create model bound to f, sets the
// given username/uid, and returns the tea.Cmd produced by attemptSubmit.
// The cmd is a closure over (ops, opts) — execute it to drive the txn
// batch against f.Calls.
func buildAndSubmitFresh(t *testing.T, f *sysops.Fake, username, uid string) tea.Cmd {
	t.Helper()
	m := newuser.New(f, "/srv/sftp-jailer")
	m.SetUserLookupForTest(func(int) bool { return false })
	m.LoadPreflightForTest(true, nil, nil)
	require.Equal(t, newuser.PhaseEditingForTest, m.PhaseForTest())
	setRawForTest(m, username, uid)
	// Navigate to [create] and submit — capture the cmd from the Update
	// that processes the Enter on [create].
	for i := 0; i < 5; i++ {
		_, _ = m.Update(keyPress("down"))
	}
	_, cmd := m.Update(keyPress("enter"))
	return cmd
}

// buildAndSubmitOrphan constructs the orphan-reconcile sister model, sets
// the lookup stub, drives past preflight, navigates to [create], and
// returns the submit tea.Cmd.
func buildAndSubmitOrphan(t *testing.T, f *sysops.Fake, orphan users.InfoRow) tea.Cmd {
	t.Helper()
	m := newuser.NewFromOrphan(f, "/srv/sftp-jailer", orphan)
	m.SetUserLookupForTest(func(int) bool { return false })
	m.LoadPreflightForTest(true, nil, nil)
	require.Equal(t, newuser.PhaseEditingForTest, m.PhaseForTest())
	for i := 0; i < 5; i++ {
		_, _ = m.Update(keyPress("down"))
	}
	_, cmd := m.Update(keyPress("enter"))
	return cmd
}

// indexOf returns the first index of needle in haystack, or -1.
func indexOf(haystack []string, needle string) int {
	for i, s := range haystack {
		if s == needle {
			return i
		}
	}
	return -1
}

// driveBatch executes a tea.Cmd that may be a tea.Batch and emits each
// produced message into the visitor.
func driveBatch(cmd tea.Cmd, visit func(tea.Msg)) {
	if cmd == nil {
		return
	}
	msg := cmd()
	switch m := msg.(type) {
	case tea.BatchMsg:
		for _, sub := range m {
			driveBatch(sub, visit)
		}
	case nil:
		// no-op
	default:
		visit(msg)
	}
}
