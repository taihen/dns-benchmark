package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dirEntries returns the names in dir, so tests can assert that no temporary
// file is left behind.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestOutputFileReplacesTargetOnlyOnCommit(t *testing.T) {
	tests := []struct {
		name     string
		existing bool
		commit   bool
		want     string // expected target content; empty with wantFile false
		wantFile bool
	}{
		{"existing file kept when discarded", true, false, "previous results", true},
		{"existing file replaced on commit", true, true, "new report", true},
		{"new path not created when discarded", false, false, "", false},
		{"new path created on commit", false, true, "new report", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "results.json")
			if tt.existing {
				require.NoError(t, os.WriteFile(target, []byte("previous results"), 0o600))
			}

			out, err := openOutputFile(target)
			require.NoError(t, err)
			_, err = out.Write([]byte("new report"))
			require.NoError(t, err)

			// Until commit, the target is untouched even though data was written.
			if tt.existing {
				content, err := os.ReadFile(target)
				require.NoError(t, err)
				assert.Equal(t, "previous results", string(content))
			} else {
				assert.NoFileExists(t, target)
			}

			if tt.commit {
				require.NoError(t, out.Commit())
			}
			out.Discard() // always safe, including after Commit

			if tt.wantFile {
				content, err := os.ReadFile(target)
				require.NoError(t, err)
				assert.Equal(t, tt.want, string(content))
				assert.Equal(t, []string{"results.json"}, dirEntries(t, dir), "no temporary file may be left behind")
			} else {
				assert.NoFileExists(t, target)
				assert.Empty(t, dirEntries(t, dir), "no temporary file may be left behind")
			}
		})
	}
}

func TestOutputFileKeepsExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not meaningful on Windows")
	}
	target := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(target, []byte("previous"), 0o640))
	require.NoError(t, os.Chmod(target, 0o640))

	out, err := openOutputFile(target)
	require.NoError(t, err)
	require.NoError(t, out.Commit())

	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

func TestOutputFileWritesThroughSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs extra privileges on Windows")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	link := filepath.Join(dir, "link.json")
	require.NoError(t, os.WriteFile(real, []byte("previous"), 0o600))
	require.NoError(t, os.Symlink(real, link))

	out, err := openOutputFile(link)
	require.NoError(t, err)
	_, err = out.Write([]byte("new report"))
	require.NoError(t, err)
	require.NoError(t, out.Commit())

	info, err := os.Lstat(link)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink, "the symlink itself must not be replaced")
	content, err := os.ReadFile(real)
	require.NoError(t, err)
	assert.Equal(t, "new report", string(content))
}

func TestOutputFileWritesDevicesDirectly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /dev/null on Windows")
	}
	out, err := openOutputFile(os.DevNull)
	require.NoError(t, err)
	_, err = out.Write([]byte("report"))
	require.NoError(t, err)
	require.NoError(t, out.Commit())

	info, err := os.Stat(os.DevNull)
	require.NoError(t, err)
	assert.False(t, info.Mode().IsRegular(), "the device must not be replaced by a regular file")
}

func TestOutputFileRejectsReadOnlyTargetUpFront(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission checks do not apply on Windows or as root")
	}
	target := filepath.Join(t.TempDir(), "results.json")
	require.NoError(t, os.WriteFile(target, []byte("previous"), 0o400))

	_, err := openOutputFile(target)
	assert.Error(t, err, "a read-only output file must fail before the benchmark, not be silently replaced")
}
