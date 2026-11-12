package aws_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/smithy-go"

	"github.com/aelasmar01Lab/control-assurance/internal/aws"
	"github.com/aelasmar01Lab/control-assurance/internal/aws/awstest"
	"github.com/aelasmar01Lab/control-assurance/internal/collect"
)

var now = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

func newCollector(f *awstest.Fake) (*aws.Collector, *int) {
	sleeps := 0
	return &aws.Collector{API: f, Sleep: func(context.Context, time.Duration) error { sleeps++; return nil }}, &sleeps
}

func TestCollectIAMCredentials(t *testing.T) {
	ctx := context.Background()
	f := awstest.New(now)
	f.ReportReadyAfter = 2 // IAM answers "started", "in progress", then "complete"
	c, sleeps := newCollector(f)

	got, generated, err := c.CollectIAMCredentials(ctx, awstest.FakeAccount)
	if err != nil {
		t.Fatalf("CollectIAMCredentials: %v", err)
	}
	if *sleeps != 2 {
		t.Errorf("waited %d times for the report, want 2", *sleeps)
	}
	// The report's own time is returned, not the time of the call.
	if !generated.Equal(now.Add(-30 * time.Minute)) {
		t.Errorf("generated = %s, want the report's generation time", generated)
	}
	if !got.RootMFAEnabled || got.RootAccessKeysPresent || len(got.Users) != 3 {
		t.Fatalf("snapshot = %+v", got)
	}
	// Sorted by name: the root row sorts first.
	root, admin, deployer := got.Users[0], got.Users[1], got.Users[2]
	if !root.Root || root.PasswordEnabled || root.PasswordLastUsed != nil {
		t.Errorf("root row = %+v", root)
	}
	if admin.Name != "synthetic-admin" || !admin.PasswordEnabled || !admin.MFAActive || admin.PasswordLastUsed == nil {
		t.Errorf("admin row = %+v", admin)
	}
	if len(deployer.AccessKeys) != 2 || !deployer.AccessKeys[0].Active || deployer.AccessKeys[0].LastUsed == nil || deployer.AccessKeys[1].Active {
		t.Errorf("deployer keys = %+v", deployer.AccessKeys)
	}

	// The payload carries no timestamp of its own, so an unchanged account
	// yields identical bytes from a later report.
	collectIAM := c.Collectors()[aws.IAMCredentialsKind]
	a, err := collectIAM(ctx, awstest.FakeAccount)
	if err != nil {
		t.Fatal(err)
	}
	f.Set(func(f *awstest.Fake) { f.ReportGenerated = now.Add(4 * time.Hour) })
	b, err := collectIAM(ctx, awstest.FakeAccount)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Payload) != string(b.Payload) {
		t.Error("two reports of an unchanged account produced different payloads")
	}
	if a.SourceTimestamp == nil || b.SourceTimestamp == nil || !b.SourceTimestamp.After(*a.SourceTimestamp) {
		t.Errorf("source timestamps = %v, %v; want each report's own time", a.SourceTimestamp, b.SourceTimestamp)
	}
	if strings.Contains(string(a.Payload), "arn:aws:iam") {
		t.Error("the payload keeps a column the normalizer is meant to drop")
	}
}

func TestCredentialReportFaults(t *testing.T) {
	tests := []struct {
		name   string
		change func(f *awstest.Fake)
		want   collect.Class
	}{
		{"never ready", func(f *awstest.Fake) { f.ReportReadyAfter = 1 << 30 }, collect.Network},
		{"missing column", func(f *awstest.Fake) { f.ReportCSV = "user,arn\nx,y\n" }, collect.Malformed},
		{"not CSV", func(f *awstest.Fake) { f.ReportCSV = "\"unterminated" }, collect.Malformed},
		{"no generation time", func(f *awstest.Fake) { f.ReportGenerated = time.Time{} }, collect.Malformed},
		{"credentials for another account", func(f *awstest.Fake) { f.Account = "111111111111" }, collect.Permission},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := awstest.New(now)
			tt.change(f)
			c, _ := newCollector(f)
			_, _, err := c.CollectIAMCredentials(context.Background(), awstest.FakeAccount)
			var ce *collect.Error
			if !errors.As(err, &ce) || ce.Class != tt.want {
				t.Errorf("err = %v, want class %s", err, tt.want)
			}
		})
	}
}

func TestCollectTrails(t *testing.T) {
	ctx := context.Background()
	f := awstest.New(now)
	c, _ := newCollector(f)
	got, err := c.CollectTrails(ctx, awstest.FakeAccount)
	if err != nil {
		t.Fatalf("CollectTrails: %v", err)
	}
	if len(got.Trails) != 1 || !got.Trails[0].StatusReadable || !got.Trails[0].Logging || got.Region != awstest.FakeRegion {
		t.Errorf("snapshot = %+v", got)
	}

	// A refused status is recorded as unreadable, not as "not logging".
	f.Set(func(f *awstest.Fake) {
		f.StatusErr = &collect.Error{Class: collect.Permission, Detail: "synthetic"}
	})
	got, err = c.CollectTrails(ctx, awstest.FakeAccount)
	if err != nil {
		t.Fatalf("CollectTrails with status refused: %v", err)
	}
	if got.Trails[0].StatusReadable || got.Trails[0].Logging {
		t.Errorf("trail = %+v, want status unreadable", got.Trails[0])
	}

	// Any other failure to read status fails the collection.
	f.Set(func(f *awstest.Fake) { f.StatusErr = &collect.Error{Class: collect.Server, Detail: "synthetic"} })
	if _, err := c.CollectTrails(ctx, awstest.FakeAccount); err == nil {
		t.Error("a server fault reading trail status was swallowed")
	}
}

func TestCollectBedrockLogging(t *testing.T) {
	f := awstest.New(now)
	c, _ := newCollector(f)
	got, err := c.CollectBedrockLogging(context.Background(), awstest.FakeAccount)
	if err != nil || got.S3Bucket != "synthetic-invocation-logs" || got.Region != awstest.FakeRegion {
		t.Errorf("snapshot = %+v, %v", got, err)
	}
}

func TestClassify(t *testing.T) {
	api := func(code string, fault smithy.ErrorFault) error {
		return &smithy.OperationError{ServiceID: "IAM", OperationName: "Synthetic",
			Err: &smithy.GenericAPIError{Code: code, Message: "secret-looking detail that must not be kept", Fault: fault}}
	}
	tests := []struct {
		name string
		err  error
		want collect.Class
	}{
		{"expired token", api("ExpiredToken", smithy.FaultClient), collect.Auth},
		{"invalid key", api("InvalidClientTokenId", smithy.FaultClient), collect.Auth},
		{"bad signature", api("SignatureDoesNotMatch", smithy.FaultClient), collect.Auth},
		{"access denied", api("AccessDenied", smithy.FaultClient), collect.Permission},
		{"access denied exception", api("AccessDeniedException", smithy.FaultClient), collect.Permission},
		{"throttling", api("Throttling", smithy.FaultClient), collect.RateLimited},
		{"throttling exception", api("ThrottlingException", smithy.FaultClient), collect.RateLimited},
		{"trail not found", api("TrailNotFoundException", smithy.FaultClient), collect.NotFound},
		{"service unavailable", api("ServiceUnavailable", smithy.FaultServer), collect.Server},
		{"unknown server fault", api("SomethingNew", smithy.FaultServer), collect.Server},
		{"unknown client error", api("SomethingNew", smithy.FaultClient), collect.Unexpected},
		{"deadline", context.DeadlineExceeded, collect.Network},
		{"no credentials", errors.New("failed to refresh cached credentials, no EC2 IMDS role found"), collect.Auth},
		{"missing profile", errors.New("failed to get shared config profile, cca-collector"), collect.Auth},
		{"connection refused", errors.New("dial tcp 192.0.2.1:443: connect: connection refused"), collect.Network},
		{"undecodable response", &smithy.DeserializationError{Err: errors.New("unexpected EOF")}, collect.Malformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := aws.Classify("iam:Synthetic", tt.err)
			if got.Class != tt.want {
				t.Errorf("class = %s (%s), want %s", got.Class, got.Detail, tt.want)
			}
			if !strings.HasPrefix(got.Detail, "iam:Synthetic") || strings.Contains(got.Detail, "secret-looking") {
				t.Errorf("detail = %q, want the operation and code only", got.Detail)
			}
		})
	}
	// An already classified error passes through unchanged.
	in := &collect.Error{Class: collect.Storage, Detail: "kept"}
	if got := aws.Classify("x", in); got != in {
		t.Errorf("Classify rewrote a classified error: %+v", got)
	}
}

func TestValidAccount(t *testing.T) {
	for s, want := range map[string]bool{"000000000000": true, "12345": false, "00000000000a": false, "": false, "0000000000000": false} {
		if aws.ValidAccount(s) != want {
			t.Errorf("ValidAccount(%q) = %v, want %v", s, !want, want)
		}
	}
}
