// Package aws reads evidence from an AWS account. It is the only package
// that talks to AWS, and it only reads.
package aws

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/collect"
)

// The kinds of observation collected from an account, and the version of
// each payload's shape.
const (
	IAMCredentialsKind       = "aws.iam_credentials"   //nolint:gosec // the name of a kind of evidence, not a credential
	IAMCredentialsNormalizer = "aws.iam_credentials/1" //nolint:gosec // a version label, not a credential
	TrailsKind               = "aws.cloudtrail_trails"
	TrailsNormalizer         = "aws.cloudtrail_trails/1"
	BedrockLoggingKind       = "aws.bedrock_logging"
	BedrockLoggingNormalizer = "aws.bedrock_logging/1"
)

// Kinds lists the kinds of observation collected from an account.
var Kinds = []string{IAMCredentialsKind, TrailsKind, BedrockLoggingKind}

// API is the handful of read-only AWS calls the collector makes, reduced to
// plain values. Every error it returns is a *collect.Error.
type API interface {
	// AccountID returns the account the credentials belong to.
	AccountID(ctx context.Context) (string, error)
	// GenerateCredentialReport asks IAM for a credential report and
	// reports whether one is ready.
	GenerateCredentialReport(ctx context.Context) (ready bool, err error)
	// CredentialReport returns the report as CSV and when IAM generated it.
	CredentialReport(ctx context.Context) (csv []byte, generated time.Time, err error)
	// AccountSummary returns IAM's account summary counters.
	AccountSummary(ctx context.Context) (map[string]int32, error)
	// Trails describes the trails visible in the collector's Region.
	Trails(ctx context.Context) ([]Trail, error)
	// TrailLogging reports whether the trail is currently logging.
	TrailLogging(ctx context.Context, arn string) (bool, error)
	// BedrockLogging returns the model invocation logging destinations in
	// the collector's Region. Both are empty when none is configured.
	BedrockLogging(ctx context.Context) (s3Bucket, logGroup string, err error)
	// Region is the Region the regional calls are made in.
	Region() string
}

// Collector turns API responses into normalized evidence.
type Collector struct {
	API API
	// Sleep waits between polls for the credential report. It defaults to
	// a real wait that stops when the context ends.
	Sleep func(ctx context.Context, d time.Duration) error
}

// reportPolls and reportPollInterval bound the wait for a credential report.
const (
	reportPolls        = 10
	reportPollInterval = 2 * time.Second
)

func (c *Collector) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// account checks that the credentials belong to the account being
// collected, so one account's evidence is never filed under another.
func (c *Collector) account(ctx context.Context, want string) error {
	got, err := c.API.AccountID(ctx)
	if err != nil {
		return err
	}
	if got != want {
		return &collect.Error{Class: collect.Permission,
			Detail: fmt.Sprintf("the credentials are for account %s, not %s", got, want)}
	}
	return nil
}

// AccessKey is one of an IAM user's two access key slots.
type AccessKey struct {
	Slot        int        `json:"slot"`
	Active      bool       `json:"active"`
	LastRotated *time.Time `json:"last_rotated,omitempty"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
}

// User is one row of the credential report.
type User struct {
	Name string `json:"name"`
	// Root marks the account's root user row.
	Root                bool        `json:"root"`
	Created             *time.Time  `json:"created,omitempty"`
	PasswordEnabled     bool        `json:"password_enabled"`
	PasswordLastUsed    *time.Time  `json:"password_last_used,omitempty"`
	PasswordLastChanged *time.Time  `json:"password_last_changed,omitempty"`
	MFAActive           bool        `json:"mfa_active"`
	AccessKeys          []AccessKey `json:"access_keys"`
}

// IAMCredentials is the normalized evidence from the IAM credential report
// and account summary. The report's generation time is not part of it; it is
// stored as the observation's source timestamp.
type IAMCredentials struct {
	AccountID string `json:"account_id"`
	// RootMFAEnabled and RootAccessKeysPresent come from the account summary.
	RootMFAEnabled        bool   `json:"root_mfa_enabled"`
	RootAccessKeysPresent bool   `json:"root_access_keys_present"`
	Users                 []User `json:"users"`
}

// CollectIAMCredentials reads the credential report and account summary.
// IAM may serve a report it generated up to four hours earlier, so the
// returned time, not the time of the call, says how current the data is.
func (c *Collector) CollectIAMCredentials(ctx context.Context, account string) (*IAMCredentials, time.Time, error) {
	if err := c.account(ctx, account); err != nil {
		return nil, time.Time{}, err
	}
	ready := false
	for i := 0; i < reportPolls && !ready; i++ {
		if i > 0 {
			if err := c.sleep(ctx, reportPollInterval); err != nil {
				return nil, time.Time{}, &collect.Error{Class: collect.Network, Detail: "stopped while waiting for the credential report"}
			}
		}
		var err error
		if ready, err = c.API.GenerateCredentialReport(ctx); err != nil {
			return nil, time.Time{}, err
		}
	}
	if !ready {
		return nil, time.Time{}, &collect.Error{Class: collect.Network,
			Detail: fmt.Sprintf("the credential report was not ready after %d requests", reportPolls)}
	}
	raw, generated, err := c.API.CredentialReport(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	if generated.IsZero() {
		return nil, time.Time{}, &collect.Error{Class: collect.Malformed, Detail: "the credential report has no generation time"}
	}
	users, err := parseCredentialReport(raw)
	if err != nil {
		return nil, time.Time{}, err
	}
	summary, err := c.API.AccountSummary(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	mfa, okMFA := summary["AccountMFAEnabled"]
	keys, okKeys := summary["AccountAccessKeysPresent"]
	if !okMFA || !okKeys {
		return nil, time.Time{}, &collect.Error{Class: collect.Malformed, Detail: "the account summary lacks the root MFA or root access key counters"}
	}
	return &IAMCredentials{
		AccountID: account, RootMFAEnabled: mfa == 1, RootAccessKeysPresent: keys != 0, Users: users,
	}, generated.UTC(), nil
}

// reportColumns are the credential report columns the collector keeps. Every
// other column is dropped.
var reportColumns = []string{
	"user", "user_creation_time", "password_enabled", "password_last_used", "password_last_changed", "mfa_active",
	"access_key_1_active", "access_key_1_last_rotated", "access_key_1_last_used_date",
	"access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date",
}

const rootUser = "<root_account>"

func parseCredentialReport(raw []byte) ([]User, error) {
	malformed := func(detail string) error {
		return &collect.Error{Class: collect.Malformed, Detail: "credential report: " + detail}
	}
	rows, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil || len(rows) == 0 {
		return nil, malformed("not valid CSV")
	}
	col := map[string]int{}
	for i, name := range rows[0] {
		col[name] = i
	}
	for _, name := range reportColumns {
		if _, ok := col[name]; !ok {
			return nil, malformed("column " + name + " is missing")
		}
	}
	// when reads a timestamp cell. IAM writes N/A, no_information or
	// not_supported where there is no date.
	when := func(row []string, name string) (*time.Time, error) {
		v := row[col[name]]
		if v == "" || v == "N/A" || v == "no_information" || v == "not_supported" {
			return nil, nil
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, malformed("column " + name + " holds something that is not a time")
		}
		t = t.UTC()
		return &t, nil
	}

	users := make([]User, 0, len(rows)-1)
	for _, row := range rows[1:] {
		if len(row) != len(rows[0]) {
			return nil, malformed("a row has the wrong number of columns")
		}
		u := User{
			Name:            row[col["user"]],
			Root:            row[col["user"]] == rootUser,
			PasswordEnabled: row[col["password_enabled"]] == "true",
			MFAActive:       row[col["mfa_active"]] == "true",
		}
		if u.Name == "" {
			return nil, malformed("a row has no user name")
		}
		var err error
		if u.Created, err = when(row, "user_creation_time"); err != nil {
			return nil, err
		}
		if u.PasswordLastUsed, err = when(row, "password_last_used"); err != nil {
			return nil, err
		}
		if u.PasswordLastChanged, err = when(row, "password_last_changed"); err != nil {
			return nil, err
		}
		for slot := 1; slot <= 2; slot++ {
			prefix := fmt.Sprintf("access_key_%d_", slot)
			k := AccessKey{Slot: slot, Active: row[col[prefix+"active"]] == "true"}
			if k.LastRotated, err = when(row, prefix+"last_rotated"); err != nil {
				return nil, err
			}
			if k.LastUsed, err = when(row, prefix+"last_used_date"); err != nil {
				return nil, err
			}
			u.AccessKeys = append(u.AccessKeys, k)
		}
		users = append(users, u)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	return users, nil
}

// Trail is one CloudTrail trail visible in the collector's Region.
type Trail struct {
	Name              string `json:"name"`
	ARN               string `json:"arn"`
	HomeRegion        string `json:"home_region"`
	MultiRegion       bool   `json:"multi_region"`
	LogFileValidation bool   `json:"log_file_validation"`
	OrganizationTrail bool   `json:"organization_trail"`
	// StatusReadable is false when the collector was refused the trail's
	// status, as happens for an organization trail owned by another account.
	StatusReadable bool `json:"status_readable"`
	// Logging is meaningful only when StatusReadable is true.
	Logging bool `json:"logging"`
}

// Trails is the normalized evidence for the account's CloudTrail trails.
type Trails struct {
	AccountID string  `json:"account_id"`
	Region    string  `json:"region"`
	Trails    []Trail `json:"trails"`
}

// CollectTrails describes each trail and reads whether it is logging.
func (c *Collector) CollectTrails(ctx context.Context, account string) (*Trails, error) {
	if err := c.account(ctx, account); err != nil {
		return nil, err
	}
	trails, err := c.API.Trails(ctx)
	if err != nil {
		return nil, err
	}
	out := &Trails{AccountID: account, Region: c.API.Region(), Trails: []Trail{}}
	for _, t := range trails {
		if t.ARN == "" {
			return nil, &collect.Error{Class: collect.Malformed, Detail: "a trail has no ARN"}
		}
		logging, err := c.API.TrailLogging(ctx, t.ARN)
		var ce *collect.Error
		switch {
		case err == nil:
			t.StatusReadable, t.Logging = true, logging
		case errors.As(err, &ce) && ce.Class == collect.Permission:
			// Record that the status could not be read, rather than
			// guess, and let the check decide what that means.
			t.StatusReadable, t.Logging = false, false
		default:
			return nil, err
		}
		out.Trails = append(out.Trails, t)
	}
	sort.Slice(out.Trails, func(i, j int) bool { return out.Trails[i].ARN < out.Trails[j].ARN })
	return out, nil
}

// BedrockLogging is the normalized evidence for Bedrock model invocation
// logging in one Region.
type BedrockLogging struct {
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
	// S3Bucket and CloudWatchLogGroup are the configured destinations.
	// Both are empty when invocation logging is not configured.
	S3Bucket           string `json:"s3_bucket"`
	CloudWatchLogGroup string `json:"cloudwatch_log_group"`
}

// CollectBedrockLogging reads the model invocation logging configuration.
func (c *Collector) CollectBedrockLogging(ctx context.Context, account string) (*BedrockLogging, error) {
	if err := c.account(ctx, account); err != nil {
		return nil, err
	}
	bucket, group, err := c.API.BedrockLogging(ctx)
	if err != nil {
		return nil, err
	}
	return &BedrockLogging{
		AccountID: account, Region: c.API.Region(),
		S3Bucket: strings.TrimSpace(bucket), CloudWatchLogGroup: strings.TrimSpace(group),
	}, nil
}

// Collectors returns the collectors, keyed by the kind of observation each
// produces. The target of each is a twelve-digit account ID.
func (c *Collector) Collectors() map[string]func(ctx context.Context, account string) (*collect.Snapshot, error) {
	return map[string]func(ctx context.Context, account string) (*collect.Snapshot, error){
		IAMCredentialsKind: func(ctx context.Context, account string) (*collect.Snapshot, error) {
			v, generated, err := c.CollectIAMCredentials(ctx, account)
			if err != nil {
				return nil, err
			}
			s, err := snapshot(IAMCredentialsKind, IAMCredentialsNormalizer, v)
			if err == nil {
				s.SourceTimestamp = &generated
			}
			return s, err
		},
		TrailsKind: func(ctx context.Context, account string) (*collect.Snapshot, error) {
			v, err := c.CollectTrails(ctx, account)
			if err != nil {
				return nil, err
			}
			return snapshot(TrailsKind, TrailsNormalizer, v)
		},
		BedrockLoggingKind: func(ctx context.Context, account string) (*collect.Snapshot, error) {
			v, err := c.CollectBedrockLogging(ctx, account)
			if err != nil {
				return nil, err
			}
			return snapshot(BedrockLoggingKind, BedrockLoggingNormalizer, v)
		},
	}
}

func snapshot(kind, normalizer string, v any) (*collect.Snapshot, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, &collect.Error{Class: collect.Storage, Detail: "evidence could not be encoded"}
	}
	// None of these listings is paginated, so each is read whole.
	return &collect.Snapshot{Kind: kind, Normalizer: normalizer, Payload: payload, Complete: true}, nil
}

// ValidAccount reports whether s looks like an AWS account ID.
func ValidAccount(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
