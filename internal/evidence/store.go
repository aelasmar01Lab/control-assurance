// Package evidence stores evidence payloads addressed by their SHA-256.
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// Store keeps payload bytes under their SHA-256. Storing the same bytes twice
// keeps one copy.
type Store interface {
	// Put stores data and returns its SHA-256 and a reference to where it lives.
	Put(ctx context.Context, data []byte) (sha256Hex, ref string, err error)
	// Get returns the bytes stored under sha256Hex, verified against that hash.
	Get(ctx context.Context, sha256Hex string) ([]byte, error)
}

// ErrCorrupt means stored bytes no longer match the hash they are filed under.
var ErrCorrupt = errors.New("evidence payload does not match its hash")

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// FS is a Store backed by a directory on the local filesystem.
type FS struct {
	root string
}

// NewFS returns a filesystem store rooted at dir, creating it if needed.
func NewFS(dir string) (*FS, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create evidence directory: %w", err)
	}
	return &FS{root: dir}, nil
}

func (s *FS) path(sha string) string {
	return filepath.Join(s.root, sha[:2], sha)
}

// Put implements Store.
func (s *FS) Put(_ context.Context, data []byte) (string, string, error) {
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	ref := "fs:" + filepath.Join(sha[:2], sha)
	dst := s.path(sha)

	if _, err := os.Stat(dst); err == nil {
		return sha, ref, nil // already stored
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return "", "", fmt.Errorf("create evidence directory: %w", err)
	}
	// Write to a temporary file and rename, so a crash never leaves a
	// partial payload under a valid hash.
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tmp-*")
	if err != nil {
		return "", "", fmt.Errorf("write evidence: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", "", fmt.Errorf("write evidence: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", "", fmt.Errorf("write evidence: %w", err)
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", "", fmt.Errorf("write evidence: %w", err)
	}
	return sha, ref, nil
}

// Get implements Store.
func (s *FS) Get(_ context.Context, sha string) ([]byte, error) {
	if !shaPattern.MatchString(sha) {
		return nil, fmt.Errorf("invalid sha256 %q", sha)
	}
	data, err := os.ReadFile(s.path(sha))
	if err != nil {
		return nil, fmt.Errorf("read evidence %s: %w", sha, err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != sha {
		return nil, fmt.Errorf("%w: %s", ErrCorrupt, sha)
	}
	return data, nil
}
