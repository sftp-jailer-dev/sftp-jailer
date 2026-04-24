package sysops

import (
	"context"
	"fmt"
	"io/fs"
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

	// Calls is a recording of every method invocation in call order, with
	// args serialized to the argv Args field.
	Calls []FakeCall
}

// FakeCall records a single method call on a Fake.
type FakeCall struct {
	Method string
	Args   []string
}

// NewFake returns an initialized Fake with EUID=0 (root) and all maps
// non-nil but empty.
func NewFake() *Fake {
	return &Fake{
		EUID:                  0,
		Files:                 map[string][]byte{},
		FileStats:             map[string]FileInfo{},
		DirEntries:            map[string][]fs.DirEntry{},
		GlobResults:           map[string][]string{},
		ExecResponses:         map[string]ExecResult{},
		ExecResponsesByPrefix: map[string]ExecResult{},
		SshdConfig:            map[string][]string{},
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
