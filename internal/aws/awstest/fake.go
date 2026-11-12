// Package awstest provides a synthetic AWS account for tests.
package awstest

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/aws"
)

// FakeAccount is the account a Fake serves.
const FakeAccount = "000000000000"

// FakeRegion is the Region a Fake reports.
const FakeRegion = "us-east-1"

// User is a synthetic IAM user row for the credential report.
type User struct {
	Name            string
	PasswordEnabled bool
	MFA             bool
	// PasswordLastUsed, Key1LastUsed and Key1LastRotated are RFC 3339
	// times, or "" for none. Key1Active turns the first access key on.
	PasswordLastUsed string
	Key1Active       bool
	Key1LastUsed     string
	Key1LastRotated  string
}

// Fake is an in-memory stand-in for the AWS calls the collector makes.
// Everything it returns is synthetic. The zero value is not usable; call New.
type Fake struct {
	mu sync.Mutex

	Account         string
	Users           []User
	RootMFA         bool
	RootAccessKeys  bool
	ReportGenerated time.Time
	// ReportReadyAfter is how many GenerateCredentialReport calls return
	// "not ready" first.
	ReportReadyAfter int
	// ReportCSV, when set, is served instead of a report built from Users.
	ReportCSV string

	TrailList []aws.Trail
	// Logging says which trail ARNs are logging.
	Logging map[string]bool
	// StatusErr is returned by TrailLogging when set.
	StatusErr error

	BedrockBucket   string
	BedrockLogGroup string

	// Err, when set, is returned by every call.
	Err error

	generateCalls int
}

// New returns a fake account in a healthy state: root and every password
// user have MFA, nothing is unused, one multi-Region trail is logging with
// validation on, and Bedrock invocation logging has a destination.
func New(now time.Time) *Fake {
	recent := now.Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	const arn = "arn:aws:cloudtrail:us-east-1:000000000000:trail/synthetic-trail"
	return &Fake{
		Account: FakeAccount,
		Users: []User{
			{Name: "synthetic-admin", PasswordEnabled: true, MFA: true, PasswordLastUsed: recent},
			{Name: "synthetic-deployer", Key1Active: true, Key1LastUsed: recent, Key1LastRotated: recent},
		},
		RootMFA:         true,
		ReportGenerated: now.Add(-30 * time.Minute).UTC(),
		TrailList: []aws.Trail{{
			Name: "synthetic-trail", ARN: arn, HomeRegion: FakeRegion, MultiRegion: true, LogFileValidation: true,
		}},
		Logging:       map[string]bool{arn: true},
		BedrockBucket: "synthetic-invocation-logs",
	}
}

// Set changes the fake under its lock.
func (f *Fake) Set(change func(f *Fake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

// Region is the Region the fake reports.
func (f *Fake) Region() string { return FakeRegion }

// AccountID returns the fake account.
func (f *Fake) AccountID(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Account, f.Err
}

// GenerateCredentialReport reports ready once ReportReadyAfter calls have been made.
func (f *Fake) GenerateCredentialReport(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return false, f.Err
	}
	f.generateCalls++
	return f.generateCalls > f.ReportReadyAfter, nil
}

const header = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active," +
	"access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service," +
	"access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service," +
	"cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated"

func cell(v string) string {
	if v == "" {
		return "N/A"
	}
	return v
}

// CredentialReport serves a report in the format IAM uses.
func (f *Fake) CredentialReport(context.Context) ([]byte, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return nil, time.Time{}, f.Err
	}
	if f.ReportCSV != "" {
		return []byte(f.ReportCSV), f.ReportGenerated, nil
	}
	const created = "2025-01-01T00:00:00+00:00"
	var b strings.Builder
	b.WriteString(header + "\n")
	fmt.Fprintf(&b, "<root_account>,arn:aws:iam::%s:root,%s,not_supported,no_information,not_supported,not_supported,%t,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n",
		f.Account, created, f.RootMFA)
	for _, u := range f.Users {
		fmt.Fprintf(&b, "%s,arn:aws:iam::%s:user/%s,%s,%t,%s,%s,N/A,%t,%t,%s,%s,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n",
			u.Name, f.Account, u.Name, created, u.PasswordEnabled, cell(u.PasswordLastUsed), cell(""),
			u.MFA, u.Key1Active, cell(u.Key1LastRotated), cell(u.Key1LastUsed))
	}
	return []byte(b.String()), f.ReportGenerated, nil
}

// AccountSummary serves the two root counters the collector reads.
func (f *Fake) AccountSummary(context.Context) (map[string]int32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return nil, f.Err
	}
	out := map[string]int32{"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}
	if f.RootMFA {
		out["AccountMFAEnabled"] = 1
	}
	if f.RootAccessKeys {
		out["AccountAccessKeysPresent"] = 1
	}
	return out, nil
}

// Trails serves the fake's trails.
func (f *Fake) Trails(context.Context) ([]aws.Trail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]aws.Trail(nil), f.TrailList...), f.Err
}

// TrailLogging reports whether the trail is logging.
func (f *Fake) TrailLogging(_ context.Context, arn string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return false, f.Err
	}
	if f.StatusErr != nil {
		return false, f.StatusErr
	}
	return f.Logging[arn], nil
}

// BedrockLogging serves the configured destinations.
func (f *Fake) BedrockLogging(context.Context) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.BedrockBucket, f.BedrockLogGroup, f.Err
}
