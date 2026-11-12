package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	const password = "correct horse battery staple"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("hash = %q, want argon2id with the documented parameters", hash)
	}
	if strings.Contains(hash, password) {
		t.Error("hash contains the password")
	}

	ok, err := VerifyPassword(hash, password)
	if err != nil || !ok {
		t.Errorf("correct password: ok = %v, err = %v", ok, err)
	}
	ok, err = VerifyPassword(hash, password+"x")
	if err != nil || ok {
		t.Errorf("wrong password: ok = %v, err = %v", ok, err)
	}

	// The same password hashes differently each time (random salt).
	again, _ := HashPassword(password)
	if again == hash {
		t.Error("two hashes of the same password are identical")
	}
}

func TestPasswordLength(t *testing.T) {
	if _, err := HashPassword("short"); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("short password: err = %v", err)
	}
	if _, err := HashPassword(strings.Repeat("a", 257)); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("overlong password: err = %v", err)
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	for _, h := range []string{
		"", "plaintext", "$2b$12$bcrypt-not-supported",
		"$argon2id$v=19$m=4294967295,t=2,p=1$c2FsdA$a2V5", // absurd memory
		"$argon2id$v=19$m=19456,t=2,p=1$!!!$a2V5",
	} {
		if ok, err := VerifyPassword(h, "whatever-password"); ok || err == nil {
			t.Errorf("VerifyPassword(%q) = %v, %v; want false and an error", h, ok, err)
		}
	}
}

func TestGeneratePassword(t *testing.T) {
	a, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GeneratePassword()
	if len(a) != 24 || a == b {
		t.Errorf("generated %q and %q", a, b)
	}
}
