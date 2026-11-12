package control

import (
	"strings"
	"testing"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/check"
)

var now = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

func res(key string, result check.Result, age time.Duration, cover Cover) CheckResult {
	return CheckResult{
		CheckKey: key, Resource: "lab-org/lab-repo", Result: result,
		CollectedAt: now.Add(-age), Cover: cover, CoverUntil: now.Add(24 * time.Hour),
	}
}

func TestDeriveAutomatedControl(t *testing.T) {
	c, ok := Lookup("change-management")
	if !ok {
		t.Fatal("change-management control not defined")
	}
	hour := time.Hour

	tests := []struct {
		name    string
		results []CheckResult
		want    State
		reason  string
	}{
		{"nothing evaluated", nil, NotEvaluated, "No check"},
		{"all pass on fresh evidence", []CheckResult{res("GH-01", check.Pass, hour, 0), res("GH-02", check.Pass, hour, 0)}, Supported, "GH-01 passes"},
		{"a failure with no exception", []CheckResult{res("GH-01", check.Fail, hour, NoException), res("GH-02", check.Pass, hour, 0)}, NeedsAttention, "no approved exception"},
		{"a failure under an active exception", []CheckResult{res("GH-01", check.Fail, hour, ActiveException), res("GH-02", check.Pass, hour, 0)}, AcceptedRisk, "approved exception covers it"},
		{"a failure whose exception expired", []CheckResult{res("GH-01", check.Fail, hour, ExpiredException)}, NeedsAttention, "exception expired"},
		{"one failure covered, one not", []CheckResult{res("GH-01", check.Fail, hour, ActiveException), res("GH-02", check.Fail, hour, NoException)}, NeedsAttention, "GH-02 fails"},
		{"passing but old evidence", []CheckResult{res("GH-01", check.Pass, 49*hour, 0), res("GH-02", check.Pass, hour, 0)}, Stale, "49 hours old"},
		{"evidence exactly at the window is fresh", []CheckResult{res("GH-01", check.Pass, 48*hour, 0)}, Supported, ""},
		// Needs attention outranks stale: an old failure is still a failure.
		{"old failure", []CheckResult{res("GH-01", check.Fail, 100*hour, NoException)}, NeedsAttention, "no approved exception"},
		// Stale outranks accepted risk: the exception was granted on evidence that has aged out.
		{"old failure under an active exception", []CheckResult{res("GH-01", check.Fail, 100*hour, ActiveException)}, Stale, "hours old"},
		{"a result that could not be determined", []CheckResult{res("GH-01", check.NotEvaluated, hour, 0), res("GH-02", check.Pass, hour, 0)}, NotEvaluated, "could not be evaluated"},
		{"a failure outranks an undetermined result", []CheckResult{res("GH-01", check.NotEvaluated, hour, 0), res("GH-02", check.Fail, hour, NoException)}, NeedsAttention, "GH-02 fails"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reasons := Derive(c, Input{Now: now, Results: tt.results})
			if got != tt.want {
				t.Errorf("state = %s, want %s (%v)", got, tt.want, reasons)
			}
			if len(reasons) == 0 {
				t.Error("a state was returned with no reason")
			}
			if !strings.Contains(strings.Join(reasons, " "), tt.reason) {
				t.Errorf("reasons = %v, want one to contain %q", reasons, tt.reason)
			}
		})
	}
}

func TestDeriveManualControl(t *testing.T) {
	c, ok := Lookup("backup-recovery")
	if !ok {
		t.Fatal("backup-recovery control not defined")
	}
	until := now.AddDate(0, 6, 0)
	past := now.AddDate(0, -1, 0)

	tests := []struct {
		name   string
		manual ManualStatus
		until  *time.Time
		want   State
	}{
		{"nothing submitted", ManualMissing, nil, NeedsAttention},
		{"awaiting review", ManualPending, nil, NeedsAttention},
		{"rejected", ManualRejected, nil, NeedsAttention},
		{"accepted and in period", ManualAccepted, &until, Supported},
		{"accepted but out of period", ManualExpired, &past, Stale},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reasons := Derive(c, Input{Now: now, Manual: tt.manual, ManualValidUntil: tt.until})
			if got != tt.want {
				t.Errorf("state = %s, want %s (%v)", got, tt.want, reasons)
			}
			if !strings.Contains(strings.Join(reasons, " "), "REC-01") {
				t.Errorf("reasons = %v, want them to name REC-01", reasons)
			}
		})
	}
}

func TestManualEvidence(t *testing.T) {
	day := func(offset int) *time.Time {
		d := now.Truncate(24*time.Hour).AddDate(0, 0, offset)
		return &d
	}
	tests := []struct {
		name string
		subs []Submission
		want ManualStatus
	}{
		{"none", nil, ManualMissing},
		{"pending only", []Submission{{ID: 1, Status: "pending"}}, ManualPending},
		{"rejected only", []Submission{{ID: 1, Status: "rejected"}}, ManualRejected},
		{"accepted, valid", []Submission{{ID: 1, Status: "accepted", ValidUntil: day(30)}}, ManualAccepted},
		{"accepted, valid through today", []Submission{{ID: 1, Status: "accepted", ValidUntil: day(0)}}, ManualAccepted},
		{"accepted, expired yesterday", []Submission{{ID: 1, Status: "accepted", ValidUntil: day(-1)}}, ManualExpired},
		// A valid accepted record still counts while a newer one is pending or was rejected.
		{"valid, then a newer pending", []Submission{{ID: 1, Status: "accepted", ValidUntil: day(30)}, {ID: 2, Status: "pending"}}, ManualAccepted},
		{"valid, then a newer rejected", []Submission{{ID: 1, Status: "accepted", ValidUntil: day(30)}, {ID: 2, Status: "rejected"}}, ManualAccepted},
		// Once the accepted record has expired, the newest submission decides.
		{"expired, then a newer rejected", []Submission{{ID: 1, Status: "accepted", ValidUntil: day(-5)}, {ID: 2, Status: "rejected"}}, ManualRejected},
		{"expired, then a newer pending", []Submission{{ID: 2, Status: "pending"}, {ID: 1, Status: "accepted", ValidUntil: day(-5)}}, ManualPending},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := ManualEvidence(tt.subs, now); got != tt.want {
				t.Errorf("status = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestControlDefinitions(t *testing.T) {
	if LoadErr != nil {
		t.Fatalf("the built-in content is not valid:\n%v", LoadErr)
	}
	seen := map[string]bool{}
	for _, c := range All {
		if seen[c.Key] {
			t.Errorf("control %s defined twice", c.Key)
		}
		seen[c.Key] = true
		if c.Title == "" || c.Statement == "" || c.Risk == "" || c.Owner == "" || c.EvidenceExpectation == "" {
			t.Errorf("%s: title, statement, risk, owner and evidence expectation are all required", c.Key)
		}
		if len(c.ContentSHA256) != 64 || c.Path == "" || c.Domain == "" {
			t.Errorf("%s: revision %q, path %q, domain %q", c.Key, c.ContentSHA256, c.Path, c.Domain)
		}
		if len(c.Checks) > 0 && c.Freshness <= 0 {
			t.Errorf("%s: automated checks need a freshness window", c.Key)
		}
		for _, k := range append(append([]string(nil), c.Checks...), c.ManualCheck) {
			if k == "" || k == manualEvidenceLabel {
				continue
			}
			def, ok := check.Lookup(k, "1")
			if !ok {
				t.Errorf("%s: check %s is not registered", c.Key, k)
			}
			if def.Manual != (k == c.ManualCheck) {
				t.Errorf("%s: check %s is listed on the wrong side of manual/automated", c.Key, k)
			}
		}
		for _, m := range c.Mappings {
			if m.Framework == "" || m.Version == "" || m.Requirement == "" || m.Rationale == "" || (m.Limitation == "" && m.Strength != "direct") {
				t.Errorf("%s: mapping %+v is incomplete", c.Key, m)
			}
			if m.Strength != "direct" && m.Strength != "partial" && m.Strength != "supporting" {
				t.Errorf("%s: mapping strength %q", c.Key, m.Strength)
			}
		}
	}
	if got := OwnersForCheck("GH-01"); len(got) != 1 || got[0] != "control-owner" {
		t.Errorf("OwnersForCheck(GH-01) = %v", got)
	}
}
