package evidence

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
)

// memoryObjects is an in-memory stand-in for a bucket.
type memoryObjects struct {
	objects map[string][]byte
	puts    int
	fail    error
}

func (m *memoryObjects) PutIfAbsent(_ context.Context, key string, data []byte, sum [sha256.Size]byte) (bool, error) {
	if m.fail != nil {
		return false, m.fail
	}
	if sha256.Sum256(data) != sum {
		return false, errors.New("synthetic: checksum mismatch")
	}
	m.puts++
	if _, exists := m.objects[key]; exists {
		return false, nil
	}
	m.objects[key] = append([]byte(nil), data...)
	return true, nil
}

func (m *memoryObjects) Get(_ context.Context, key string) ([]byte, error) {
	data, ok := m.objects[key]
	if !ok {
		return nil, errors.New("synthetic: NoSuchKey")
	}
	return data, nil
}

func TestS3Store(t *testing.T) {
	ctx := context.Background()
	bucket := &memoryObjects{objects: map[string][]byte{}}
	s := NewS3(bucket, "synthetic-bucket", "/evidence/")

	sha, ref, err := s.Put(ctx, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	const key = "evidence/2c/" + want
	if sha != want || ref != "s3://synthetic-bucket/"+key {
		t.Errorf("Put = %s, %s", sha, ref)
	}
	if _, ok := bucket.objects[key]; !ok || len(bucket.objects) != 1 {
		t.Errorf("objects = %v, want one under %s", bucket.objects, key)
	}

	// Storing the same bytes again keeps one copy and is not an error.
	if sha2, _, err := s.Put(ctx, []byte("hello")); err != nil || sha2 != sha || len(bucket.objects) != 1 {
		t.Errorf("second Put = %s, %v; %d objects", sha2, err, len(bucket.objects))
	}

	got, err := s.Get(ctx, sha)
	if err != nil || string(got) != "hello" {
		t.Fatalf("Get = %q, %v", got, err)
	}

	// Bytes changed in the bucket are detected on read.
	bucket.objects[key] = []byte("tampered")
	if _, err := s.Get(ctx, sha); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Get after tampering: err = %v, want ErrCorrupt", err)
	}
	// An existing key is never overwritten, even by the right bytes.
	if _, _, err := s.Put(ctx, []byte("hello")); err != nil || string(bucket.objects[key]) != "tampered" {
		t.Errorf("Put replaced an existing object (%v)", err)
	}

	if _, err := s.Get(ctx, "../../etc/passwd"); err == nil {
		t.Error("Get accepted a value that is not a sha256")
	}
	if _, err := s.Get(ctx, "aa"+want[2:]); err == nil {
		t.Error("Get of a missing object succeeded")
	}
	bucket.fail = errors.New("synthetic: AccessDenied")
	if _, _, err := s.Put(ctx, []byte("other")); err == nil {
		t.Error("a refused write was reported as stored")
	}
}

func TestOpenS3NeedsItsOwnProfile(t *testing.T) {
	if _, err := OpenS3(context.Background(), "", "bucket", ""); err == nil {
		t.Error("OpenS3 accepted an empty profile")
	}
	if _, err := OpenS3(context.Background(), "profile", "", ""); err == nil {
		t.Error("OpenS3 accepted an empty bucket")
	}
}
