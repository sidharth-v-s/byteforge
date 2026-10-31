// Package fsutil provides binary-safe, non-destructive file output helpers.
package fsutil

import (
	"os"
	"path/filepath"

	"github.com/zoro/byteforge/internal/bferrors"
)

// WriteFile writes data to path without silently overwriting an existing file
// unless force is true.
//
// Non-forced writes create the destination with O_EXCL and mode 0600 so a
// concurrent writer cannot be clobbered. Forced writes use a temporary file in
// the destination directory followed by an atomic rename where the platform
// supports it. A failed write never leaves a partial file at the destination.
func WriteFile(path string, data []byte, force bool) error {
	if path == "" {
		return bferrors.New(bferrors.IO, "empty output path")
	}
	if force {
		return writeAtomic(path, data)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		switch {
		case os.IsExist(err):
			return bferrors.Wrap(bferrors.IO, err, "output file already exists: %s (use --force to overwrite)", path)
		case os.IsNotExist(err):
			return bferrors.Wrap(bferrors.IO, err, "cannot create %s: output directory does not exist", path)
		default:
			return bferrors.Wrap(bferrors.IO, err, "cannot create %s", path)
		}
	}

	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(path)
	}
	if _, err := f.Write(data); err != nil {
		cleanup()
		return bferrors.Wrap(bferrors.IO, err, "writing %s", path)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return bferrors.Wrap(bferrors.IO, err, "syncing %s", path)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return bferrors.Wrap(bferrors.IO, err, "closing %s", path)
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".byteforge-*")
	if err != nil {
		if os.IsNotExist(err) {
			return bferrors.Wrap(bferrors.IO, err, "cannot write %s: output directory does not exist", path)
		}
		return bferrors.Wrap(bferrors.IO, err, "cannot create temporary file in %s", dir)
	}
	name := tmp.Name()
	defer os.Remove(name)

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return bferrors.Wrap(bferrors.IO, err, "setting permissions on temporary output")
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return bferrors.Wrap(bferrors.IO, err, "writing temporary output")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return bferrors.Wrap(bferrors.IO, err, "syncing temporary output")
	}
	if err := tmp.Close(); err != nil {
		return bferrors.Wrap(bferrors.IO, err, "closing temporary output")
	}

	if err := os.Rename(name, path); err != nil {
		// Windows cannot rename over an existing file. Remove and retry once;
		// this still avoids leaving a partial destination.
		if rmErr := os.Remove(path); rmErr == nil {
			if retryErr := os.Rename(name, path); retryErr == nil {
				return nil
			}
		}
		return bferrors.Wrap(bferrors.IO, err, "replacing %s", path)
	}
	return nil
}

// Exists reports whether path exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
