// Package deleteuser tests for M-DELETE-USER — D-15 Permanent
// (type-username gate) + Archive (mkdir+tar+userdel batch + size+keys
// async load).
package deleteuser_test

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/require"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/nav"
	"github.com/sftp-jailer-dev/sftp-jailer/internal/tui/screens/deleteuser"
)

const (
	testChrootRoot = "/srv/sftp"
	testUsername   = "alice"
	testHome       = "/srv/sftp/alice"
)

// keyPress mirrors the userdetail / users test helpers.
func keyPress(s string) tea.KeyPressMsg {
	switch s {
	case "esc":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape, Text: ""})
	case "enter":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter, Text: ""})
	case "tab":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyTab, Text: ""})
	}
	r := rune(s[0])
	return tea.KeyPressMsg(tea.Key{Code: r, Text: s})
}

// frozenNow returns a deterministic time-source so archive paths are
// reproducible across test runs.
func frozenNow() func() time.Time {
	return func() time.Time {
		return time.Date(2026, 4, 26, 12, 34, 56, 0, time.UTC)
	}
}

const frozenStamp = "20260426T123456Z"

// TestDeleteUser_implements_nav_Screen — compile-time check + Title +
// KeyMap shape.
func TestDeleteUser_implements_nav_Screen(t *testing.T) {
	t.Parallel()
	var s nav.Screen = deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	require.Equal(t, "delete user — alice", s.Title())
	km := s.KeyMap()
	require.NotNil(t, km)
	require.NotEmpty(t, km.ShortHelp())
	require.NotEmpty(t, km.FullHelp())
}

// TestDeleteUser_default_mode_is_Permanent — D-15 requires Permanent
// to be the default focus.
func TestDeleteUser_default_mode_is_Permanent(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	require.Equal(t, deleteuser.ModePermanent, m.ModeForTest(),
		"D-15 contract: default mode is Permanent (admin sees the destructive option focused so the friction is in the typing-username gate, not in a wrong-default)")
}

// TestDeleteUser_tab_toggles_mode — pressing tab in review phase flips
// the mode between Permanent and Archive.
func TestDeleteUser_tab_toggles_mode(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(1024, 2)

	require.Equal(t, deleteuser.ModePermanent, m.ModeForTest())
	_, _ = m.Update(keyPress("tab"))
	require.Equal(t, deleteuser.ModeArchive, m.ModeForTest(), "tab → Archive")
	_, _ = m.Update(keyPress("tab"))
	require.Equal(t, deleteuser.ModePermanent, m.ModeForTest(), "tab again → Permanent")
}

// TestDeleteUser_enter_review_modePermanent_enters_confirm_phase —
// from phase=Review with mode=Permanent, Enter advances to
// phaseConfirmingPermanent (textinput focused).
func TestDeleteUser_enter_review_modePermanent_enters_confirm_phase(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(0, 0)
	require.Equal(t, deleteuser.PhaseReviewForTest, m.PhaseForTest())

	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, deleteuser.PhaseConfirmingPermanentForTest, m.PhaseForTest(),
		"Permanent + Enter from Review → ConfirmingPermanent (admin must type username verbatim)")
}

// TestDeleteUser_enter_confirm_blocks_when_text_does_not_match_username —
// the irreversibility gate: phase stays at confirm + errInline mentions
// 'verbatim'.
func TestDeleteUser_enter_confirm_blocks_when_text_does_not_match_username(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(0, 0)
	_, _ = m.Update(keyPress("enter")) // → phaseConfirmingPermanent
	m.SetConfirmTextForTest("al")      // wrong text

	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, deleteuser.PhaseConfirmingPermanentForTest, m.PhaseForTest(),
		"mismatched text MUST NOT advance the phase — irreversibility gate")
	require.Contains(t, m.ErrInlineForTest(), "verbatim",
		"mismatched text must produce an errInline that mentions 'verbatim' so admin understands the gate")
}

// TestDeleteUser_enter_confirm_proceeds_when_text_matches — typing the
// username verbatim activates submit (phase advances to Submitting).
func TestDeleteUser_enter_confirm_proceeds_when_text_matches(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := deleteuser.New(f, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(0, 0)
	_, _ = m.Update(keyPress("enter")) // → phaseConfirmingPermanent
	m.SetConfirmTextForTest(testUsername)

	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, deleteuser.PhaseSubmittingForTest, m.PhaseForTest(),
		"matching confirm text → phaseSubmitting (txn batch in flight)")
}

// TestDeleteUser_modeArchive_enter_review_starts_submit_immediately —
// Archive path skips the type-username gate. Enter from Review →
// Submitting directly.
func TestDeleteUser_modeArchive_enter_review_starts_submit_immediately(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	m := deleteuser.New(f, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(0, 0)
	_, _ = m.Update(keyPress("tab")) // → ModeArchive
	require.Equal(t, deleteuser.ModeArchive, m.ModeForTest())

	_, _ = m.Update(keyPress("enter"))
	require.Equal(t, deleteuser.PhaseSubmittingForTest, m.PhaseForTest(),
		"Archive path skips the type-username confirm gate — Enter from Review → Submitting directly (admin already chose tabbed-to-Archive deliberately)")
}

// TestDeleteUser_compose_steps_modePermanent_runs_userdel_dash_r —
// composeSteps for Permanent is [Userdel(removeHome=true)] (1 step).
func TestDeleteUser_compose_steps_modePermanent_runs_userdel_dash_r(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(0, 0)

	steps := m.ComposeStepsForTest()
	require.Len(t, steps, 1, "Permanent batch is exactly 1 step: Userdel")
	require.Equal(t, "Userdel", steps[0].Name())

	// Drive the step against a Fake to confirm removeHome=true.
	f := sysops.NewFake()
	require.NoError(t, steps[0].Apply(context.Background(), f))
	for _, c := range f.Calls {
		if c.Method == "Userdel" {
			require.Equal(t, testUsername, c.Args[0])
			require.Equal(t, "removeHome=true", c.Args[1],
				"Permanent path uses userdel -r (irreversible — deletes home)")
		}
	}
}

// TestDeleteUser_compose_steps_modeArchive_runs_mkdir_then_tar_then_userdel_no_r
// — composeSteps for Archive is [MkdirAll, Tar, Userdel] in order.
func TestDeleteUser_compose_steps_modeArchive_runs_mkdir_then_tar_then_userdel_no_r(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(0, 0)
	m.SetNowFnForTest(frozenNow())
	_, _ = m.Update(keyPress("tab"))

	steps := m.ComposeStepsForTest()
	require.Len(t, steps, 3, "Archive batch is exactly 3 steps: MkdirAll, Tar, Userdel")
	require.Equal(t, "MkdirAll", steps[0].Name())
	require.Equal(t, "Tar", steps[1].Name())
	require.Equal(t, "Userdel", steps[2].Name())

	// Drive against a Fake so we can assert on the args (especially
	// the tar archive path with the frozen ISO timestamp + the
	// userdel removeHome=false signal).
	f := sysops.NewFake()
	for _, s := range steps {
		require.NoError(t, s.Apply(context.Background(), f))
	}
	expectedArchive := filepath.Join(deleteuser.ArchiveDir, testUsername+"-"+frozenStamp+".tar.gz")
	var sawMkdir, sawTar, sawUserdel bool
	for _, c := range f.Calls {
		switch c.Method {
		case "MkdirAll":
			if c.Args[0] == deleteuser.ArchiveDir {
				sawMkdir = true
				require.Equal(t, "mode=700", c.Args[1],
					"archive dir must be mode 0700 root:root per T-03-08a-05")
			}
		case "Tar":
			require.Equal(t, "mode=czf", c.Args[0])
			require.Equal(t, "archive="+expectedArchive, c.Args[1])
			require.Equal(t, "source="+testHome, c.Args[2])
			sawTar = true
		case "Userdel":
			require.Equal(t, testUsername, c.Args[0])
			require.Equal(t, "removeHome=false", c.Args[1],
				"Archive path uses userdel WITHOUT -r (the tar already preserved the home content)")
			sawUserdel = true
		}
	}
	require.True(t, sawMkdir, "MkdirAll on /var/lib/sftp-jailer/archive must run")
	require.True(t, sawTar, "Tar on the archive path must run")
	require.True(t, sawUserdel, "Userdel must run after Tar")
}

// TestDeleteUser_archive_path_rolls_back_partial_tarball_on_userdel_failure —
// script Userdel to fail; assert (a) Tar's compensator removes the
// partial tarball via ops.RemoveAll, AND (b) MkdirAll's compensator
// removes the archive dir we created (W-02 typed wrappers).
func TestDeleteUser_archive_path_rolls_back_partial_tarball_on_userdel_failure(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(0, 0)
	m.SetNowFnForTest(frozenNow())
	_, _ = m.Update(keyPress("tab")) // ModeArchive

	steps := m.ComposeStepsForTest()
	require.Len(t, steps, 3)

	f := sysops.NewFake()
	f.UserdelError = errors.New("simulated userdel failure")

	// Apply manually — first two succeed, Userdel fails.
	require.NoError(t, steps[0].Apply(context.Background(), f), "MkdirAll")
	require.NoError(t, steps[1].Apply(context.Background(), f), "Tar")
	err := steps[2].Apply(context.Background(), f)
	require.Error(t, err, "Userdel must propagate the simulated failure")

	// Now drive the compensators in reverse order (matches what
	// txn.Tx.rollback does). Userdel's Compensate is a no-op (D-15);
	// Tar's Compensate removes the archive path; MkdirAll's Compensate
	// removes the archive dir iff it didn't exist before.
	require.NoError(t, steps[2].Compensate(context.Background(), f), "Userdel compensate is no-op (D-15)")
	require.NoError(t, steps[1].Compensate(context.Background(), f), "Tar compensate")
	require.NoError(t, steps[0].Compensate(context.Background(), f), "MkdirAll compensate")

	expectedArchive := filepath.Join(deleteuser.ArchiveDir, testUsername+"-"+frozenStamp+".tar.gz")

	var removeAllCalls []string
	for _, c := range f.Calls {
		if c.Method == "RemoveAll" {
			removeAllCalls = append(removeAllCalls, c.Args[0])
		}
	}
	require.Contains(t, removeAllCalls, expectedArchive,
		"Tar compensator must remove the partial tarball via ops.RemoveAll (W-02 typed wrapper)")
	require.Contains(t, removeAllCalls, deleteuser.ArchiveDir,
		"MkdirAll compensator must remove the archive dir we created via ops.RemoveAll (W-02 typed wrapper) — the dir didn't exist before this batch")
}

// TestDeleteUser_metaLoadedMsg_populates_size_and_keysCount — a
// LoadMetaForTest poke pre-populates the dirSize + keysCount; the View
// surface includes the humanized size and keys count.
func TestDeleteUser_metaLoadedMsg_populates_size_and_keysCount(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(1024*1024, 3) // 1 MiB, 3 keys

	v := m.View()
	require.Contains(t, v, "1.0 MiB",
		"humanize.IBytes(1024*1024) renders '1.0 MiB' — review surface must show it; got View=%s", v)
	require.Contains(t, v, "3 keys")
}

// TestDeleteUser_review_surface_shows_archive_path_when_modeArchive —
// the review-surface preview includes the archive path so admin sees
// where the tarball will land before submitting.
func TestDeleteUser_review_surface_shows_archive_path_when_modeArchive(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(0, 0)
	m.SetNowFnForTest(frozenNow())
	_, _ = m.Update(keyPress("tab"))

	v := m.View()
	require.Contains(t, v, deleteuser.ArchiveDir, "review must show the canonical archive dir")
	require.Contains(t, v, testUsername+"-"+frozenStamp+".tar.gz",
		"review must show the exact archive filename so admin sees the destination")
}

// TestDeleteUser_submit_done_msg_advances_to_done_phase — feeding a
// successful submitDoneMsg flips phase to Done and emits an auto-pop
// tick batch.
func TestDeleteUser_submit_done_msg_advances_to_done_phase(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(0, 0)

	_, cmd := m.FeedSubmitDoneForTest(nil)
	require.Equal(t, deleteuser.PhaseDoneForTest, m.PhaseForTest())
	require.NotNil(t, cmd, "successful submit must emit toast.Flash + auto-pop tick batch")
}

// TestDeleteUser_submit_done_msg_with_error_advances_to_error_phase —
// txn-batch failure surfaces inline and lets admin Esc out.
func TestDeleteUser_submit_done_msg_with_error_advances_to_error_phase(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(0, 0)

	_, _ = m.FeedSubmitDoneForTest(errors.New("simulated txn failure"))
	require.Equal(t, deleteuser.PhaseErrorForTest, m.PhaseForTest())
	require.Contains(t, m.ErrInlineForTest(), "simulated txn failure",
		"errInline must surface the txn-batch error verbatim")
}

// TestDeleteUser_esc_from_review_pops — Esc on the review screen pops
// the modal back to S-USERS.
func TestDeleteUser_esc_from_review_pops(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(0, 0)

	_, cmd := m.Update(keyPress("esc"))
	require.NotNil(t, cmd)
	nm, ok := cmd().(nav.Msg)
	require.True(t, ok)
	require.Equal(t, nav.Pop, nm.Intent)
}

// TestDeleteUser_esc_from_confirm_returns_to_review — Esc on the
// confirm-typing surface backs out to review (without losing typed
// text — admin can re-enter or tab to Archive).
func TestDeleteUser_esc_from_confirm_returns_to_review(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(0, 0)
	_, _ = m.Update(keyPress("enter")) // → confirm
	require.Equal(t, deleteuser.PhaseConfirmingPermanentForTest, m.PhaseForTest())

	_, cmd := m.Update(keyPress("esc"))
	require.Equal(t, deleteuser.PhaseReviewForTest, m.PhaseForTest(),
		"Esc from confirm returns to review — does NOT pop the whole modal (admin can change mind without re-loading meta)")
	require.Nil(t, cmd, "Esc-back-to-review must NOT emit a Pop")
}

// TestDeleteUser_WantsRawKeys_only_in_confirm_phase — type-username
// confirm phase needs raw keys (admin types arbitrary chars including
// 'q' if their username contains it). Other phases swallow.
func TestDeleteUser_WantsRawKeys_only_in_confirm_phase(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	require.False(t, m.WantsRawKeys(), "loading phase doesn't want raw keys")

	m.LoadMetaForTest(0, 0)
	require.False(t, m.WantsRawKeys(), "review phase doesn't want raw keys")

	_, _ = m.Update(keyPress("enter")) // → confirm
	require.True(t, m.WantsRawKeys(), "ConfirmingPermanent phase MUST want raw keys (admin types username including any chars)")
}

// TestDeleteUser_archive_path_uses_typed_sysops_wrappers_w02 — the
// Archive composeSteps must use ops.MkdirAll + ops.RemoveAll typed
// wrappers (W-02). The Fake records every typed-wrapper call; if the
// step regresses to raw os calls, the Fake won't see them.
func TestDeleteUser_archive_path_uses_typed_sysops_wrappers_w02(t *testing.T) {
	t.Parallel()
	m := deleteuser.New(nil, testChrootRoot, testUsername, testHome)
	m.LoadMetaForTest(0, 0)
	m.SetNowFnForTest(frozenNow())
	_, _ = m.Update(keyPress("tab"))

	steps := m.ComposeStepsForTest()
	f := sysops.NewFake()

	for _, s := range steps {
		require.NoError(t, s.Apply(context.Background(), f))
	}

	var sawMkdirAll bool
	for _, c := range f.Calls {
		if c.Method == "MkdirAll" && c.Args[0] == deleteuser.ArchiveDir {
			sawMkdirAll = true
		}
	}
	require.True(t, sawMkdirAll,
		"W-02: archive path must invoke ops.MkdirAll (the Fake records it; raw os.MkdirAll would be invisible to the Fake)")
}

// TestDeleteUser_metaLoad_async_path_walks_home_via_sysops — exercises
// startMetaLoad's async path with a real Fake-backed home tree. Drives
// Init's cmd to completion and feeds metaLoadedMsg back through
// Update; assert View shows the summed size + key count.
func TestDeleteUser_metaLoad_async_path_walks_home_via_sysops(t *testing.T) {
	t.Parallel()
	f := sysops.NewFake()
	// Pre-seed home dir + one file + the authorized_keys file.
	f.FileStats[testHome] = sysops.FileInfo{Path: testHome, Mode: 0o750, IsDir: true}
	// ReadDir of testHome returns one entry: "data.txt" (file).
	f.DirEntries[testHome] = []fs.DirEntry{simpleDirEntry{n: "data.txt"}}
	f.FileStats[filepath.Join(testHome, "data.txt")] = sysops.FileInfo{Path: filepath.Join(testHome, "data.txt"), Mode: 0o644}
	f.Files[filepath.Join(testHome, "data.txt")] = []byte("hello world\n") // 12 bytes

	authPath := filepath.Join(testChrootRoot, testUsername, ".ssh", "authorized_keys")
	f.Files[authPath] = []byte("ssh-ed25519 AAAA-fakeforcount alice@a\n# a comment\n\nssh-ed25519 AAAA-second alice@b\n")

	m := deleteuser.New(f, testChrootRoot, testUsername, testHome)
	cmd := m.Init()
	require.NotNil(t, cmd)

	// Init returns a tea.Batch — we want to specifically execute the
	// meta-load cmd (not the spinner tick which schedules another tick).
	// Walk the batch and find a msg that's a metaLoadedMsg by feeding
	// each non-tick message back through Update.
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	require.True(t, ok, "Init returns a tea.Batch")

	for _, sub := range batch {
		if sub == nil {
			continue
		}
		_, _ = m.Update(sub())
	}

	v := m.View()
	require.Contains(t, v, "12 B",
		"summed home size (12 bytes from data.txt) must render in the review")
	require.Contains(t, v, "2 keys",
		"non-blank, non-comment lines in authorized_keys count as keys (2 here)")
}

// simpleDirEntry is a minimal fs.DirEntry impl for seeding f.DirEntries
// with one regular file.
type simpleDirEntry struct{ n string }

func (e simpleDirEntry) Name() string               { return e.n }
func (e simpleDirEntry) IsDir() bool                { return false }
func (e simpleDirEntry) Type() fs.FileMode          { return 0 }
func (e simpleDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

// Sanity that strings.Builder still compiles — quiets unused import.
func TestDeleteUser_strings_builder_compiles(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("ok")
	require.Equal(t, "ok", b.String())
}
