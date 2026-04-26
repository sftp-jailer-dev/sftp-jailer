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

// SshdDumpConfig implements [SystemOps.SshdDumpConfig].
func (f *Fake) SshdDumpConfig(_ context.Context) (map[string][]string, error) {
	f.record("SshdDumpConfig")
	if f.SshdConfig == nil {
		return map[string][]string{}, nil
	}
	// Shallow-copy the top-level map so callers can't mutate fixture state.
	out := make(map[string][]string, len(f.SshdConfig))
	for k, v := range f.SshdConfig {
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
