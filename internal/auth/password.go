// Package auth hashes and verifies passwords with argon2id.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Parameters follow the OWASP minimum for argon2id: 19 MiB, 2 iterations,
// 1 degree of parallelism. They are stored in each hash, so they can be
// raised without invalidating existing hashes.
const (
	argonMemoryKiB = 19 * 1024
	argonTime      = 2
	argonThreads   = 1
	saltLen        = 16
	keyLen         = 32

	// MinPasswordLength is the shortest password HashPassword accepts.
	MinPasswordLength = 12
	// maxPasswordLength bounds the work an attacker can force per attempt.
	maxPasswordLength = 256
)

// ErrWeakPassword is returned for a password outside the accepted length.
var ErrWeakPassword = fmt.Errorf("password must be %d to %d characters", MinPasswordLength, maxPasswordLength)

// HashPassword returns an encoded argon2id hash of password.
func HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLength || len(password) > maxPasswordLength {
		return "", ErrWeakPassword
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches the encoded hash.
func VerifyPassword(encoded, password string) (bool, error) {
	if len(password) > maxPasswordLength {
		return false, nil
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("unrecognised password hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("unsupported argon2 version")
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, errors.New("unrecognised argon2 parameters")
	}
	// Refuse parameters that would make verification a denial of service.
	if memory == 0 || memory > 1<<20 || time == 0 || time > 16 || threads == 0 {
		return false, errors.New("argon2 parameters out of range")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errors.New("unrecognised password salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 128 {
		return false, errors.New("unrecognised password key")
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want))) //nolint:gosec // length bounded above
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// GeneratePassword returns a random 24-character password.
func GeneratePassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
