package sysops

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// Fake is the in-memory scriptable SystemOps implementation used by tests.
// Every field is exported so tests can construct a Fake and poke values
// directly; every method records the call in f.Calls under a mutex so
// downstream tests can assert on call order + args.
type Fake struct {
	mu sync.Mutex

	// EUID is returned from Geteuid. Default 0 (root).
	EUID int

	// Files maps absolute path -> content returned from ReadFile.
	Files map[string][]byte

	// Shadow maps username -> the /etc/shadow fields exposed via ReadShadow
	// (last-change-day = field 3; max-days = field 5). A missing username
	// causes ReadShadow to return fs.ErrNotExist (graceful-degradation
	// contract: caller leaves PasswordAgeDays / PasswordMaxDays at -1).
	Shadow map[string]ShadowEntry

	// FileStats maps absolute path -> FileInfo returned from Stat and Lstat.
	// Phase 1 keeps a single map; a separate LstatResults map could be added
	// later if Stat/Lstat need to diverge in tests.
	FileStats map[string]FileInfo

	// DirEntries maps path -> the ReadDir result.
	DirEntries map[string][]fs.DirEntry

	// GlobResults maps pattern -> matches returned from Glob.
	GlobResults map[string][]string

	// ExecResponses maps the exact invocation string
	// "<name> <arg1> <arg2> ..." to a scripted ExecResult.
	// Lookup is performed BEFORE ExecResponsesByPrefix.
	ExecResponses map[string]ExecResult

	// ExecResponsesByPrefix maps a prefix (e.g. "nft -j list") to an
	// ExecResult. The longest-prefix match wins when multiple prefixes
	// would match the same invocation.
	ExecResponsesByPrefix map[string]ExecResult

	// ExecError, if non-nil, is returned from every Exec call before any
	// response map lookup. Used to simulate catastrophic failures.
	ExecError error

	// SshdConfig is returned from SshdDumpConfig. Keys are lowercase directive
	// names; values are a slice of space-joined argument strings.
	SshdConfig map[string][]string

	// Phase 2 additions — scripted-response mirrors of the new sysops methods.

	// AtomicWriteError, if non-nil, is returned from AtomicWriteFile before
	// any state mutation. Used to simulate write failures.
	AtomicWriteError error

	// JournalctlStdout maps unit string → canned stdout bytes returned from
	// JournalctlStream. Each call returns a fresh ReadCloser over the bytes
	// (i.e. consumable independently across calls).
	JournalctlStdout map[string][]byte

	// JournalctlStreamError, if non-nil, is returned from JournalctlStream
	// before any state mutation.
	JournalctlStreamError error

	// ObserveRunStdout: canned stdout for ObserveRunStream. Each call returns
	// a fresh ReadCloser over the same bytes.
	ObserveRunStdout []byte

	// ObserveRunStreamError, if non-nil, is returned from ObserveRunStream
	// before any state mutation.
	ObserveRunStreamError error

	// LockHeld toggles AcquireRunLock between "succeeds + flips to held" and
	// "returns ErrLockHeld." Tests mutate this to script the lockfile state.
	LockHeld bool

	// LockError, if non-nil, takes precedence over LockHeld in AcquireRunLock.
	// Used to simulate flock(2) failures.
	LockError error

	// ----------------------------------------------------------------
	// Phase 3 additions — scripted-response mirrors of the new sysops
	// mutation methods. Each *Error field, if non-nil, is returned from
	// the corresponding method AFTER the call is recorded (parity with
	// AtomicWriteError convention). Tests script the error path by
	// setting the field; default zero-value = success.
	// ----------------------------------------------------------------

	// UseraddError, if non-nil, is returned from Useradd after recording.
	UseraddError error

	// UserdelError, if non-nil, is returned from Userdel after recording.
	UserdelError error

	// GpasswdError, if non-nil, is returned from Gpasswd after recording.
	GpasswdError error

	// ChpasswdStderr is returned in the *ChpasswdError.Stderr field when
	// ChpasswdError is set. Tests use this to script pam_pwquality output.
	ChpasswdStderr []byte

	// ChpasswdError, if non-nil, becomes the ExitErr inside the
	// *ChpasswdError returned from Chpasswd. ChpasswdStderr is bundled
	// alongside.
	ChpasswdError error

	// ChageError, if non-nil, is returned from Chage after recording.
	ChageError error

	// ChmodError, if non-nil, is returned from Chmod after recording.
	ChmodError error

	// ChownError, if non-nil, is returned from Chown after recording.
	ChownError error

	// MkdirAllError, if non-nil, is returned from MkdirAll after recording.
	MkdirAllError error

	// RemoveAllError, if non-nil, is returned from RemoveAll after recording.
	RemoveAllError error

	// WriteAuthorizedKeysError, if non-nil, is returned from
	// WriteAuthorizedKeys BEFORE materializing state in f.Files (parity
	// with AtomicWriteError).
	WriteAuthorizedKeysError error

	// SshdTStderr is returned as the stderr return value from SshdT.
	SshdTStderr []byte

	// SshdTError, if non-nil, is returned as the error return value from SshdT.
	SshdTError error

	// SshdTWithContextStderr is returned as the stderr return value from
	// SshdTWithContext.
	SshdTWithContextStderr []byte

	// SshdTWithContextError, if non-nil, is returned as the error return
	// value from SshdTWithContext.
	SshdTWithContextError error

	// SystemctlReloadError, if non-nil, is returned from SystemctlReload.
	SystemctlReloadError error

	// SystemctlRestartSocketError, if non-nil, is returned from
	// SystemctlRestartSocket.
	SystemctlRestartSocketError error

	// SystemctlDaemonReloadError, if non-nil, is returned from
	// SystemctlDaemonReload.
	SystemctlDaemonReloadError error

	// TarError, if non-nil, is returned from Tar after recording.
	TarError error

	// SshdConfigResponse is returned from SshdDumpConfig (W-04 — fakeable
	// post-reload verifier in plan 03-09 + advisory checks in plan 03-08b).
	// nil → empty map (callers don't need nil-checks).
	SshdConfigResponse map[string][]string

	// SshdDumpConfigError, if non-nil, takes precedence and is returned
	// from SshdDumpConfig.
	SshdDumpConfigError error

	// ----------------------------------------------------------------
	// Phase 4 additions — scripted-response mirrors of the new ufw /
	// systemd-run / systemctl / ip mutation methods. Each *Error field,
	// if non-nil, is returned from the corresponding method AFTER the
	// call is recorded (parity with AtomicWriteError convention). Result
	// fields default to the zero value so a fresh Fake reports
	// HasPublicIPv6=(false,nil) and SystemctlIsActive=(false,nil).
	// ----------------------------------------------------------------

	// UfwAllowError, if non-nil, is returned from UfwAllow after recording.
	UfwAllowError error

	// UfwInsertError, if non-nil, is returned from UfwInsert after recording.
	UfwInsertError error

	// UfwDeleteError, if non-nil, is returned from UfwDelete after recording.
	UfwDeleteError error

	// UfwReloadError, if non-nil, is returned from UfwReload after recording.
	UfwReloadError error

	// HasPublicIPv6Result is returned as the bool result from HasPublicIPv6.
	// Default false. Pair with HasPublicIPv6Error for failure paths.
	HasPublicIPv6Result bool

	// HasPublicIPv6Error, if non-nil, is returned as the err result from
	// HasPublicIPv6 (Result is also returned but typically false on err).
	HasPublicIPv6Error error

	// RewriteUfwIPV6Error, if non-nil, is returned from RewriteUfwIPV6
	// after recording.
	RewriteUfwIPV6Error error

	// SystemdRunError, if non-nil, is returned from SystemdRunOnActive
	// after recording. Tests typically assert on f.Calls argv to verify
	// the inline /bin/sh -c '<reverse>' shell-script body — the Fake
	// records the FULL Command string verbatim per D-S04-08.
	SystemdRunError error

	// SystemctlStopError, if non-nil, is returned from SystemctlStop after
	// recording.
	SystemctlStopError error

	// SystemctlIsActiveResult is returned as the bool result from
	// SystemctlIsActive. Default false (parity with the inactive/not-loaded
	// state on a clean test fixture).
	SystemctlIsActiveResult bool

	// SystemctlIsActiveError, if non-nil, is returned as the err result
	// from SystemctlIsActive.
	SystemctlIsActiveError error

	// Calls is a recording of every method invocation in call order, with
	// args serialized to the argv Args field.
	Calls []FakeCall
}

// FakeCall records a single method call on a Fake.
type FakeCall struct {
	Method string
	Args   []string
}

// ShadowEntry is the test-injection shape for /etc/shadow fields exposed
// through ReadShadow. LastChangeDay corresponds to field 3 (days since
// 1970-01-01 UTC); MaxDays corresponds to field 5 (>= 99999 conventionally
// means "no expiry policy"; 0 means "field empty / not set").
type ShadowEntry struct {
	LastChangeDay int
	MaxDays       int
}

// NewFake returns an initialized Fake with EUID=0 (root) and all maps
// non-nil but empty.
func NewFake() *Fake {
	return &Fake{
		EUID:                  0,
		Files:                 map[string][]byte{},
		Shadow:                map[string]ShadowEntry{},
		FileStats:             map[string]FileInfo{},
		DirEntries:            map[string][]fs.DirEntry{},
		GlobResults:           map[string][]string{},
		ExecResponses:         map[string]ExecResult{},
		ExecResponsesByPrefix: map[string]ExecResult{},
		SshdConfig:            map[string][]string{},
		JournalctlStdout:      map[string][]byte{},
	}
}

func (f *Fake) record(method string, args ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Copy args to avoid downstream aliasing.
	a := make([]string, len(args))
	copy(a, args)
	f.Calls = append(f.Calls, FakeCall{Method: method, Args: a})
}

// Geteuid implements [SystemOps.Geteuid].
func (f *Fake) Geteuid() int {
	f.record("Geteuid")
	return f.EUID
}

// ReadFile implements [SystemOps.ReadFile].
func (f *Fake) ReadFile(_ context.Context, path string) ([]byte, error) {
	f.record("ReadFile", path)
	b, ok := f.Files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return b, nil
}

// ReadShadow implements [SystemOps.ReadShadow]. Returns the seeded
// ShadowEntry for `username`; an unseeded username returns fs.ErrNotExist
// so the enrichment-layer caller can branch on errors.Is and degrade
// gracefully (leave PasswordAgeDays / PasswordMaxDays at -1).
func (f *Fake) ReadShadow(_ context.Context, username string) (int, int, error) {
	f.record("ReadShadow", username)
	if f.Shadow == nil {
		return 0, 0, fs.ErrNotExist
	}
	e, ok := f.Shadow[username]
	if !ok {
		return 0, 0, fs.ErrNotExist
	}
	return e.LastChangeDay, e.MaxDays, nil
}

// ReadDir implements [SystemOps.ReadDir].
func (f *Fake) ReadDir(_ context.Context, path string) ([]fs.DirEntry, error) {
	f.record("ReadDir", path)
	d, ok := f.DirEntries[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return d, nil
}

// Stat implements [SystemOps.Stat].
func (f *Fake) Stat(_ context.Context, path string) (FileInfo, error) {
	f.record("Stat", path)
	fi, ok := f.FileStats[path]
	if !ok {
		return FileInfo{}, fs.ErrNotExist
	}
	return fi, nil
}

// Lstat implements [SystemOps.Lstat].
func (f *Fake) Lstat(_ context.Context, path string) (FileInfo, error) {
	f.record("Lstat", path)
	fi, ok := f.FileStats[path]
	if !ok {
		return FileInfo{}, fs.ErrNotExist
	}
	return fi, nil
}

// Glob implements [SystemOps.Glob].
func (f *Fake) Glob(_ context.Context, pattern string) ([]string, error) {
	f.record("Glob", pattern)
	m, ok := f.GlobResults[pattern]
	if !ok {
		// Glob with no matches returns an empty slice (not ErrNotExist),
		// matching filepath.Glob semantics.
		return nil, nil
	}
	return m, nil
}

// Exec key format: strings.TrimSpace(name + " " + strings.Join(args, " ")).
// Exact match in ExecResponses wins; otherwise longest-prefix match in
// ExecResponsesByPrefix; otherwise error.
func (f *Fake) Exec(_ context.Context, name string, args ...string) (ExecResult, error) {
	argv := append([]string{name}, args...)
	f.record("Exec", argv...)

	if f.ExecError != nil {
		return ExecResult{}, f.ExecError
	}

	key := strings.TrimSpace(name + " " + strings.Join(args, " "))

	if r, ok := f.ExecResponses[key]; ok {
		return r, nil
	}

	// Longest-prefix match wins.
	var bestK string
	for k := range f.ExecResponsesByPrefix {
		if strings.HasPrefix(key, k) && len(k) > len(bestK) {
			bestK = k
		}
	}
	if bestK != "" {
		return f.ExecResponsesByPrefix[bestK], nil
	}

	return ExecResult{}, fmt.Errorf("sysops.Fake: no scripted response for %q", key)
}

// SshdDumpConfig implements [SystemOps.SshdDumpConfig]. Phase 3 (W-04)
// adds two new ways to script:
//   - SshdConfigResponse (preferred for Phase 3+ tests) — set the field to
//     the desired map directly. Default nil → empty map (no nil-check needed).
//   - SshdDumpConfigError, if non-nil, takes precedence and is returned.
//
// SshdConfig (legacy Phase 1/2 field) is consulted as a fallback so existing
// tests keep working.
func (f *Fake) SshdDumpConfig(_ context.Context) (map[string][]string, error) {
	f.record("SshdDumpConfig")
	if f.SshdDumpConfigError != nil {
		return nil, f.SshdDumpConfigError
	}
	src := f.SshdConfigResponse
	if src == nil {
		src = f.SshdConfig
	}
	if src == nil {
		return map[string][]string{}, nil
	}
	// Shallow-copy the top-level map so callers can't mutate fixture state.
	out := make(map[string][]string, len(src))
	for k, v := range src {
		out[k] = append([]string(nil), v...)
	}
	return out, nil
}

// AtomicWriteFile implements [SystemOps.AtomicWriteFile]. Records the call
// and persists data into f.Files[path] so subsequent ReadFile round-trips
// return the same bytes.
func (f *Fake) AtomicWriteFile(_ context.Context, path string, data []byte, mode fs.FileMode) error {
	f.record("AtomicWriteFile", path, fmt.Sprintf("len=%d", len(data)), fmt.Sprintf("mode=%o", mode))
	if f.AtomicWriteError != nil {
		return f.AtomicWriteError
	}
	// Defensive copy so callers can mutate `data` afterwards without
	// affecting our scripted state.
	cp := make([]byte, len(data))
	copy(cp, data)
	f.mu.Lock()
	if f.Files == nil {
		f.Files = map[string][]byte{}
	}
	f.Files[path] = cp
	f.mu.Unlock()
	return nil
}

// JournalctlStream implements [SystemOps.JournalctlStream]. Returns a fresh
// io.NopCloser over the canned bytes for opts.Unit; the *os.Process return
// is always nil for the Fake (the runner does not call proc.Wait when proc
// is nil — see internal/observe/runner.go).
func (f *Fake) JournalctlStream(_ context.Context, opts JournalctlStreamOpts) (*os.Process, io.ReadCloser, error) {
	f.record("JournalctlStream", opts.CursorFile, opts.Unit, opts.Since)
	if f.JournalctlStreamError != nil {
		return nil, nil, f.JournalctlStreamError
	}
	canned := f.JournalctlStdout[opts.Unit] // empty map / missing key → nil → empty stream
	return nil, io.NopCloser(bytes.NewReader(canned)), nil
}

// JournalctlFollowCmd implements [SystemOps.JournalctlFollowCmd]. Returns a
// no-op *exec.Cmd whose program name is the literal "journalctl" and whose
// args mirror Real. The returned Cmd is never Run by the unit tests — the
// production caller (live-tail screen, plan 02-06) hands it to tea.ExecProcess.
func (f *Fake) JournalctlFollowCmd(unit string) *exec.Cmd {
	f.record("JournalctlFollowCmd", unit)
	return exec.Command("journalctl", "-u", unit, "-f", "--no-pager") //nolint:gosec // G204: typed wrapper, fixed argv shape
}

// ObserveRunStream implements [SystemOps.ObserveRunStream]. Returns a fresh
// io.NopCloser over the scripted ObserveRunStdout bytes.
func (f *Fake) ObserveRunStream(_ context.Context, opts ObserveRunSubprocessOpts) (*os.Process, io.ReadCloser, error) {
	f.record("ObserveRunStream", opts.SelfPath, opts.CursorFile, opts.DBPath, opts.ConfigPath)
	if f.ObserveRunStreamError != nil {
		return nil, nil, f.ObserveRunStreamError
	}
	return nil, io.NopCloser(bytes.NewReader(f.ObserveRunStdout)), nil
}

// AcquireRunLock implements [SystemOps.AcquireRunLock]. Returns ErrLockHeld
// when LockHeld is true; otherwise flips LockHeld=true and returns a release
// closure that flips it back. LockError takes precedence over LockHeld.
func (f *Fake) AcquireRunLock(_ context.Context, path string) (release func(), err error) {
	f.record("AcquireRunLock", path)
	if f.LockError != nil {
		return nil, f.LockError
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.LockHeld {
		return nil, ErrLockHeld
	}
	f.LockHeld = true
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.LockHeld = false
	}, nil
}

// ============================================================================
// Phase 3 Fake methods. Each records the call into f.Calls (under f.mu in
// record()), then consults the matching scripted-error field. Argv is the
// typed-string representation documented in plan 03-01 — exactly mirrors
// the test expectations to keep the contract evident.
// ============================================================================

// Useradd implements [SystemOps.Useradd] (Fake).
func (f *Fake) Useradd(_ context.Context, opts UseraddOpts) error {
	f.record("Useradd",
		opts.Username,
		fmt.Sprintf("uid=%d", opts.UID),
		fmt.Sprintf("home=%s", opts.Home),
		fmt.Sprintf("shell=%s", opts.Shell),
		fmt.Sprintf("createHome=%t", opts.CreateHome),
		fmt.Sprintf("memberOfSftpJailer=%t", opts.MemberOfSftpJailer),
	)
	return f.UseraddError
}

// Userdel implements [SystemOps.Userdel] (Fake).
func (f *Fake) Userdel(_ context.Context, username string, removeHome bool) error {
	f.record("Userdel", username, fmt.Sprintf("removeHome=%t", removeHome))
	return f.UserdelError
}

// Gpasswd implements [SystemOps.Gpasswd] (Fake).
func (f *Fake) Gpasswd(_ context.Context, op GpasswdOp, username, group string) error {
	var opStr string
	switch op {
	case GpasswdAdd:
		opStr = "op=add"
	case GpasswdDel:
		opStr = "op=del"
	default:
		opStr = fmt.Sprintf("op=unknown(%d)", op)
	}
	f.record("Gpasswd", opStr, username, group)
	return f.GpasswdError
}

// Chpasswd implements [SystemOps.Chpasswd] (Fake). The password is NEVER
// recorded — only its length appears in the recorded args (security
// invariant per pitfall E3 / D-13). On scripted error, returns *ChpasswdError
// matching the Real implementation's typed return.
func (f *Fake) Chpasswd(_ context.Context, username, password string) error {
	f.record("Chpasswd", username, fmt.Sprintf("len=%d", len(password)))
	if f.ChpasswdError != nil {
		return &ChpasswdError{
			Username: username,
			Stderr:   f.ChpasswdStderr,
			ExitErr:  f.ChpasswdError,
		}
	}
	return nil
}

// Chage implements [SystemOps.Chage] (Fake).
func (f *Fake) Chage(_ context.Context, username string, opts ChageOpts) error {
	f.record("Chage", username, fmt.Sprintf("lastDay=%d", opts.LastDay))
	return f.ChageError
}

// Chmod implements [SystemOps.Chmod] (Fake).
func (f *Fake) Chmod(_ context.Context, path string, mode fs.FileMode) error {
	f.record("Chmod", path, fmt.Sprintf("mode=%o", mode))
	return f.ChmodError
}

// Chown implements [SystemOps.Chown] (Fake).
func (f *Fake) Chown(_ context.Context, path string, uid, gid int) error {
	f.record("Chown", path, fmt.Sprintf("uid=%d", uid), fmt.Sprintf("gid=%d", gid))
	return f.ChownError
}

// MkdirAll implements [SystemOps.MkdirAll] (Fake).
func (f *Fake) MkdirAll(_ context.Context, path string, mode fs.FileMode) error {
	f.record("MkdirAll", path, fmt.Sprintf("mode=%o", mode))
	return f.MkdirAllError
}

// RemoveAll implements [SystemOps.RemoveAll] (Fake).
func (f *Fake) RemoveAll(_ context.Context, path string) error {
	f.record("RemoveAll", path)
	return f.RemoveAllError
}

// WriteAuthorizedKeys implements [SystemOps.WriteAuthorizedKeys] (Fake).
// On the success path, materializes the bytes in f.Files at the conventional
// chrooted path so subsequent ReadFile round-trips return the same content.
// Error path returns BEFORE state mutation (parity with AtomicWriteFile fake).
func (f *Fake) WriteAuthorizedKeys(_ context.Context, username, chrootRoot string, keys []byte) error {
	f.record("WriteAuthorizedKeys",
		username,
		chrootRoot,
		fmt.Sprintf("len=%d", len(keys)),
		"mode=600",
	)
	if f.WriteAuthorizedKeysError != nil {
		return f.WriteAuthorizedKeysError
	}
	cp := make([]byte, len(keys))
	copy(cp, keys)
	authPath := chrootRoot + "/" + username + "/.ssh/authorized_keys"
	f.mu.Lock()
	if f.Files == nil {
		f.Files = map[string][]byte{}
	}
	f.Files[authPath] = cp
	f.mu.Unlock()
	return nil
}

// SshdT implements [SystemOps.SshdT] (Fake). Records empty args; returns
// (SshdTStderr, SshdTError) verbatim.
func (f *Fake) SshdT(_ context.Context) ([]byte, error) {
	f.record("SshdT")
	return f.SshdTStderr, f.SshdTError
}

// SshdTWithContext implements [SystemOps.SshdTWithContext] (Fake). Records
// the user/host/addr triple as `key=value` strings; returns
// (SshdTWithContextStderr, SshdTWithContextError) verbatim.
func (f *Fake) SshdTWithContext(_ context.Context, opts SshdTContextOpts) ([]byte, error) {
	f.record("SshdTWithContext",
		"user="+opts.User,
		"host="+opts.Host,
		"addr="+opts.Addr,
	)
	return f.SshdTWithContextStderr, f.SshdTWithContextError
}

// SystemctlReload implements [SystemOps.SystemctlReload] (Fake).
func (f *Fake) SystemctlReload(_ context.Context, unit string) error {
	f.record("SystemctlReload", unit)
	return f.SystemctlReloadError
}

// SystemctlRestartSocket implements [SystemOps.SystemctlRestartSocket] (Fake).
func (f *Fake) SystemctlRestartSocket(_ context.Context, unit string) error {
	f.record("SystemctlRestartSocket", unit)
	return f.SystemctlRestartSocketError
}

// SystemctlDaemonReload implements [SystemOps.SystemctlDaemonReload] (Fake).
func (f *Fake) SystemctlDaemonReload(_ context.Context) error {
	f.record("SystemctlDaemonReload")
	return f.SystemctlDaemonReloadError
}

// Tar implements [SystemOps.Tar] (Fake).
func (f *Fake) Tar(_ context.Context, opts TarOpts) error {
	var modeStr string
	switch opts.Mode {
	case TarCreateGzip:
		modeStr = "mode=czf"
	default:
		modeStr = fmt.Sprintf("mode=unknown(%d)", opts.Mode)
	}
	f.record("Tar",
		modeStr,
		"archive="+opts.ArchivePath,
		"source="+opts.SourceDir,
	)
	return f.TarError
}

// ============================================================================
// Phase 4 Fake methods. Each records the call into f.Calls (under f.mu in
// record()), then consults the matching scripted-error / result field. Argv
// is the typed-string representation pinned by plan 04-01 — exactly mirrors
// the test expectations to keep the contract evident.
//
// Critical: SystemdRunOnActive records the FULL opts.Command string verbatim
// in the recorded args. Tests golden-file the reverse-ufw shell-script body
// against this entry per CONTEXT.md "Test strategy."
// ============================================================================

// UfwAllow implements [SystemOps.UfwAllow] (Fake).
func (f *Fake) UfwAllow(_ context.Context, opts UfwAllowOpts) error {
	f.record("UfwAllow",
		"proto="+opts.Proto,
		"src="+opts.Source,
		"port="+opts.Port,
		"comment="+opts.Comment,
	)
	return f.UfwAllowError
}

// UfwInsert implements [SystemOps.UfwInsert] (Fake).
func (f *Fake) UfwInsert(_ context.Context, position int, opts UfwAllowOpts) error {
	f.record("UfwInsert",
		fmt.Sprintf("pos=%d", position),
		"proto="+opts.Proto,
		"src="+opts.Source,
		"port="+opts.Port,
		"comment="+opts.Comment,
	)
	return f.UfwInsertError
}

// UfwDelete implements [SystemOps.UfwDelete] (Fake).
func (f *Fake) UfwDelete(_ context.Context, ruleID int) error {
	f.record("UfwDelete", fmt.Sprintf("id=%d", ruleID))
	return f.UfwDeleteError
}

// UfwReload implements [SystemOps.UfwReload] (Fake).
func (f *Fake) UfwReload(_ context.Context) error {
	f.record("UfwReload")
	return f.UfwReloadError
}

// HasPublicIPv6 implements [SystemOps.HasPublicIPv6] (Fake). Returns the
// scripted (HasPublicIPv6Result, HasPublicIPv6Error) pair. Default zero
// value is (false, nil) — appropriate for tests that don't care about v6
// detection.
func (f *Fake) HasPublicIPv6(_ context.Context) (bool, error) {
	f.record("HasPublicIPv6")
	return f.HasPublicIPv6Result, f.HasPublicIPv6Error
}

// RewriteUfwIPV6 implements [SystemOps.RewriteUfwIPV6] (Fake).
func (f *Fake) RewriteUfwIPV6(_ context.Context, value string) error {
	f.record("RewriteUfwIPV6", "value="+value)
	return f.RewriteUfwIPV6Error
}

// SystemdRunOnActive implements [SystemOps.SystemdRunOnActive] (Fake).
//
// Critical recording invariant (D-S04-08): the verbatim opts.Command string
// is recorded in args as `cmd=<verbatim>`. Tests assert this against
// golden-file ExecStart bodies for representative SAFE-04 batches.
func (f *Fake) SystemdRunOnActive(_ context.Context, opts SystemdRunOpts) error {
	f.record("SystemdRunOnActive",
		"on-active="+opts.OnActive.String(),
		"unit="+opts.UnitName,
		"cmd="+opts.Command,
	)
	return f.SystemdRunError
}

// SystemctlStop implements [SystemOps.SystemctlStop] (Fake).
func (f *Fake) SystemctlStop(_ context.Context, unitName string) error {
	f.record("SystemctlStop", "unit="+unitName)
	return f.SystemctlStopError
}

// SystemctlIsActive implements [SystemOps.SystemctlIsActive] (Fake). Returns
// the scripted (SystemctlIsActiveResult, SystemctlIsActiveError) pair.
// Default zero value is (false, nil) — parity with the systemctl exit-3
// "inactive" state on a fresh fixture.
func (f *Fake) SystemctlIsActive(_ context.Context, unitName string) (bool, error) {
	f.record("SystemctlIsActive", "unit="+unitName)
	return f.SystemctlIsActiveResult, f.SystemctlIsActiveError
}
