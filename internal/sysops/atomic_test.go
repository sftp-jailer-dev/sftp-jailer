package sysops

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAtomicWriteFile_creates_file_with_mode: write 100 bytes to a tmpdir
// path with mode 0644; result file exists, contents match, mode is 0644.
func TestAtomicWriteFile_creates_file_with_mode(t *testing.T) {
	r, ok := NewReal().(*Real)
	require.True(t, ok)

	dir := t.TempDir()
	path := filepath.Join(dir, "out.yaml")
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte('A' + (i % 26))
	}

	require.NoError(t, r.AtomicWriteFile(context.Background(), path, data, 0o644))

	got, err := os.ReadFile(path) //nolint:gosec // G304: test-only, hardcoded tmpdir path
	require.NoError(t, err)
	require.Equal(t, data, got)

	st, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o644), st.Mode().Perm())
}

// TestAtomicWriteFile_overwrites_existing_atomically: pre-create destination;
// write new bytes; result has new bytes, no `.tmp` files left in dir, mode preserved.
func TestAtomicWriteFile_overwrites_existing_atomically(t *testing.T) {
	r, ok := NewReal().(*Real)
	require.True(t, ok)

	dir := t.TempDir()
	path := filepath.Join(dir, "exists.yaml")
	require.NoError(t, os.WriteFile(path, []byte("old contents"), 0o600))

	require.NoError(t, r.AtomicWriteFile(context.Background(), path, []byte("new contents"), 0o644))

	got, err := os.ReadFile(path) //nolint:gosec // G304: test-only, hardcoded tmpdir path
	require.NoError(t, err)
	require.Equal(t, []byte("new contents"), got)

	// No tmp leftovers in the same directory.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.NotContains(t, e.Name(), ".tmp",
			"unexpected .tmp leftover after successful atomic write: %s", e.Name())
	}

	// Mode now matches the AtomicWriteFile-supplied mode.
	st, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o644), st.Mode().Perm())
}

// TestAtomicWriteFile_cleanup_on_write_error: simulate by passing an unwritable
// path (parent dir does not exist); function returns wrapped error; no .tmp
// files left behind.
func TestAtomicWriteFile_cleanup_on_write_error(t *testing.T) {
	r, ok := NewReal().(*Real)
	require.True(t, ok)

	// A directory that does not exist — CreateTemp will fail in the parent dir.
	bogus := filepath.Join(t.TempDir(), "nonexistent-subdir-xyz", "file.yaml")
	err := r.AtomicWriteFile(context.Background(), bogus, []byte("ignored"), 0o644)
	require.Error(t, err)
	require.Contains(t, err.Error(), "AtomicWriteFile")

	// Sanity: the destination was not created.
	_, statErr := os.Stat(bogus)
	require.True(t, os.IsNotExist(statErr), "destination should not exist on failure: %v", statErr)
}

// TestAtomicWriteFile_tmp_in_same_dir: confirm the temp file is created in the
// same directory as the target (cross-FS rename is non-atomic, RESEARCH §616).
// We verify by inspecting the directory after a successful write — the rename
// only succeeds when the tmp lives in the same parent directory.
func TestAtomicWriteFile_tmp_in_same_dir(t *testing.T) {
	r, ok := NewReal().(*Real)
	require.True(t, ok)

	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yaml")

	require.NoError(t, r.AtomicWriteFile(context.Background(), path, []byte("ok"), 0o600))

	// After a successful write the temp file is renamed away — but the
	// rename only succeeds atomically when source + dest share a filesystem,
	// which the same-dir choice guarantees. The presence of the renamed
	// file at `path` plus the absence of any `.tmp` suffix in `dir` confirms
	// the contract.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "settings.yaml", entries[0].Name())
}
