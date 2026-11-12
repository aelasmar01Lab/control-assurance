package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// Objects is the object storage the S3 store needs: create-only writes and
// reads. It has no delete and no overwrite.
type Objects interface {
	// PutIfAbsent stores data under key unless the key already exists, and
	// reports whether it wrote. sha256Sum is the SHA-256 of data, for the
	// storage service to verify on arrival.
	PutIfAbsent(ctx context.Context, key string, data []byte, sha256Sum [sha256.Size]byte) (written bool, err error)
	// Get returns the bytes stored under key.
	Get(ctx context.Context, key string) ([]byte, error)
}

// maxObjectBytes bounds how much is read back for one payload.
const maxObjectBytes = 64 << 20

// S3 is a Store backed by an S3 bucket. Payloads are written once under
// the SHA-256 of their bytes and never overwritten.
type S3 struct {
	objects Objects
	bucket  string
	prefix  string
}

// NewS3 returns a store that keeps payloads in bucket under prefix.
func NewS3(objects Objects, bucket, prefix string) *S3 {
	prefix = strings.Trim(prefix, "/")
	if prefix != "" {
		prefix += "/"
	}
	return &S3{objects: objects, bucket: bucket, prefix: prefix}
}

func (s *S3) key(sha string) string { return s.prefix + sha[:2] + "/" + sha }

// Put implements Store.
func (s *S3) Put(ctx context.Context, data []byte) (string, string, error) {
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	key := s.key(sha)
	// A key that exists already holds these bytes: the key is their hash.
	if _, err := s.objects.PutIfAbsent(ctx, key, data, sum); err != nil {
		return "", "", fmt.Errorf("write evidence %s: %w", sha, err)
	}
	return sha, "s3://" + s.bucket + "/" + key, nil
}

// Get implements Store.
func (s *S3) Get(ctx context.Context, sha string) ([]byte, error) {
	if !shaPattern.MatchString(sha) {
		return nil, fmt.Errorf("invalid sha256 %q", sha)
	}
	data, err := s.objects.Get(ctx, s.key(sha))
	if err != nil {
		return nil, fmt.Errorf("read evidence %s: %w", sha, err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != sha {
		return nil, fmt.Errorf("%w: %s", ErrCorrupt, sha)
	}
	return data, nil
}

// bucketObjects implements Objects with the AWS SDK.
type bucketObjects struct {
	client *s3.Client
	bucket string
}

// OpenS3 returns an S3 store that uses the named AWS profile. The profile
// is named explicitly, never taken from AWS_PROFILE, so that the evidence
// store's credentials stay apart from the collector's: the role that reads
// the sources cannot write evidence, and the role that writes evidence
// cannot read the sources.
func OpenS3(ctx context.Context, profile, bucket, prefix string) (*S3, error) {
	if profile == "" || bucket == "" {
		return nil, errors.New("the S3 evidence store needs a bucket and its own AWS profile")
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile))
	if err != nil {
		return nil, fmt.Errorf("load AWS profile %s: %w", profile, err)
	}
	return NewS3(&bucketObjects{client: s3.NewFromConfig(cfg), bucket: bucket}, bucket, prefix), nil
}

func (b *bucketObjects) PutIfAbsent(ctx context.Context, key string, data []byte, sum [sha256.Size]byte) (bool, error) {
	_, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &b.bucket,
		Key:         &key,
		Body:        bytes.NewReader(data),
		ContentType: awssdk.String("application/octet-stream"),
		// Refuse to replace an existing object.
		IfNoneMatch: awssdk.String("*"),
		// Have S3 reject the upload if the bytes changed on the way.
		ChecksumSHA256: awssdk.String(base64.StdEncoding.EncodeToString(sum[:])),
	})
	var api smithy.APIError
	if errors.As(err, &api) && api.ErrorCode() == "PreconditionFailed" {
		return false, nil
	}
	if err != nil {
		return false, describe("PutObject", err)
	}
	return true, nil
}

func (b *bucketObjects) Get(ctx context.Context, key string) ([]byte, error) {
	out, err := b.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &b.bucket, Key: &key})
	if err != nil {
		return nil, describe("GetObject", err)
	}
	defer func() { _ = out.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(out.Body, maxObjectBytes+1))
	if err != nil {
		return nil, fmt.Errorf("s3:GetObject: the object could not be read: %w", err)
	}
	if len(data) > maxObjectBytes {
		return nil, fmt.Errorf("s3:GetObject: the object is larger than %d bytes", maxObjectBytes)
	}
	return data, nil
}

// describe reduces an SDK error to the operation and the error code.
func describe(operation string, err error) error {
	var api smithy.APIError
	if errors.As(err, &api) {
		return fmt.Errorf("s3:%s: %s", operation, api.ErrorCode())
	}
	return fmt.Errorf("s3:%s failed: %w", operation, err)
}
