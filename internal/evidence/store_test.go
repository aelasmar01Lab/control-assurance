package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFSStore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := NewFS(dir)
	if err != nil {
		t.Fatal(err)
	}

	sha, ref, err := s.Put(ctx, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if sha != want {
		t.Errorf("sha = %s, want %s", sha, want)
	}
	if ref == "" {
		t.Error("empty storage reference")
	}

	// Storing the same bytes again keeps one copy.
	sha2, _, err := s.Put(ctx, []byte("hello"))
	if err != nil || sha2 != sha {
		t.Fatalf("second Put = %s, %v", sha2, err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*", "*"))
	if len(files) != 1 {
		t.Errorf("stored files = %d, want 1", len(files))
	}

	got, err := s.Get(ctx, sha)
	if err != nil || string(got) != "hello" {
		t.Fatalf("Get = %q, %v", got, err)
	}

	// Tampering with stored bytes is detected on read.
	if err := os.WriteFile(files[0], []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, sha); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Get after tampering: err = %v, want ErrCorrupt", err)
	}

	if _, err := s.Get(ctx, "../../etc/passwd"); err == nil {
		t.Error("Get accepted a value that is not a sha256")
	}
}
