package demo_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/control"
	"github.com/aelasmar01Lab/control-assurance/internal/demo"
	"github.com/aelasmar01Lab/control-assurance/internal/evidence"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
	"github.com/aelasmar01Lab/control-assurance/internal/testdb"
)

// The seeded demo replays the whole loop, and what it leaves behind is what
// the README says a visitor will find.
func TestSeededDemoReplaysTheLoop(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.New(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := &assurance.Service{Store: st, Evidence: ev}
	now := time.Now()

	if seeded, err := demo.Seeded(ctx, st); err != nil || seeded {
		t.Fatalf("an empty database: seeded = %v, %v", seeded, err)
	}
	steps, err := demo.Seed(ctx, svc, now)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if len(steps) < 8 {
		t.Errorf("the demo reported %d steps", len(steps))
	}
	if seeded, err := demo.Seeded(ctx, st); err != nil || !seeded {
		t.Errorf("after seeding: seeded = %v, %v", seeded, err)
	}
	if svc.Now != nil || svc.Collectors != nil {
		t.Error("Seed left its clock or its synthetic collectors on the service")
	}

	// Every demo account signs in with its published password.
	for _, name := range demo.Users {
		if _, err := svc.Authenticate(ctx, name, demo.Password(name)); err != nil {
			t.Errorf("sign in as %s: %v", name, err)
		}
	}
	viewer, err := svc.ActorByUsername(ctx, "auditor")
	if err != nil {
		t.Fatal(err)
	}

	// The states a visitor finds: one of each kind worth seeing.
	ov, err := svc.Overview(ctx, viewer)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]control.State{
		"change-management":        control.Supported,
		"vulnerability-disclosure": control.Supported,
		"human-access":             control.Supported,
		"credential-lifecycle":     control.Supported,
		"audit-logging":            control.Supported,
		"backup-recovery":          control.Supported,
		// Records from a company with people in it: one accepted, one
		// still waiting for review.
		"access-request-approval":    control.Supported,
		"access-offboarding-removal": control.NeedsAttention,
		"dependency-remediation":     control.NotEvaluated,
		"ai-usage-logging":           control.NeedsAttention,
	}
	seen := 0
	for _, c := range ov.Controls {
		wanted, ok := want[c.Control.Key]
		if !ok {
			// A control the demo plays no evidence for. Whatever else it
			// reads, it cannot read as supported or as an accepted risk.
			if c.State != control.NotEvaluated && c.State != control.NeedsAttention {
				t.Errorf("%s is %s (%v) with no evidence in the demo", c.Control.Key, c.State, c.Reasons)
			}
			continue
		}
		seen++
		if c.State != wanted {
			t.Errorf("%s is %s (%v), want %s", c.Control.Key, c.State, c.Reasons, wanted)
		}
		if c.Control.Key == "ai-usage-logging" && !strings.Contains(strings.Join(c.Reasons, " "), "exception expired") {
			t.Errorf("ai-usage-logging reasons = %v, want the lapsed exception named", c.Reasons)
		}
	}
	if seen != len(want) {
		t.Errorf("the demo shows %d of the %d controls it plays a history for", seen, len(want))
	}
	// The company is the one scope/demo.yaml describes, and is fictional.
	sc, ok := control.ScopeFor(demo.Organization)
	if !ok || !sc.Synthetic || sc.Name != demo.Company || len(demo.People) != 25 {
		t.Errorf("the demo company is %+v with %d people, want the fictional %s with 25", sc, len(demo.People), demo.Company)
	}
	seenLogin := map[string]bool{}
	for _, p := range demo.People {
		if seenLogin[p.Login()] || !strings.HasSuffix(p.Email(), "@pellwick.example") {
			t.Errorf("%s: login %s, address %s", p.Name, p.Login(), p.Email())
		}
		seenLogin[p.Login()] = true
	}
	if ov.IntegrationProblems != 0 {
		t.Errorf("the demo ends with %d integration problems", ov.IntegrationProblems)
	}

	// Every earlier step is still visible: the failed runs, the retry,
	// the closed findings with their exceptions and notes.
	runs, err := st.Runs(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	classes, retries := map[string]int{}, 0
	for _, r := range runs {
		classes[r.ErrorClass]++
		if r.Cause == "retry" && r.Outcome == "succeeded" {
			retries++
		}
	}
	if classes["auth"] != 3 || classes["server"] != 3 || retries != 3 {
		t.Errorf("run classes = %v, successful retries = %d; want 3 auth, 3 server, 3 retries", classes, retries)
	}
	findings, err := svc.Findings(ctx, viewer)
	if err != nil {
		t.Fatal(err)
	}
	open, closed := 0, 0
	for _, f := range findings {
		if f.Open() {
			open++
		} else {
			closed++
		}
	}
	if open != 1 || closed != 3 {
		t.Errorf("findings: %d open, %d closed; want 1 and 3", open, closed)
	}
	r, err := svc.Reproduce(ctx, viewer)
	if err != nil || r.Reproduced != r.Evaluations || r.Evaluations == 0 {
		t.Errorf("reproduction = %+v, %v", r, err)
	}

	// A review package for the demo's past holds the fail, the exception
	// and the pass, and verifies.
	from := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -demo.Days)
	p, err := svc.BuildPackage(ctx, viewer, from, from.AddDate(0, 0, 6))
	if err != nil {
		t.Fatal(err)
	}
	evals := string(p.Files["evaluations.json"])
	if !strings.Contains(evals, `"Result": "fail"`) || !strings.Contains(evals, `"Result": "pass"`) ||
		!strings.Contains(string(p.Files["exceptions.json"]), `"status_at_period_end": "approved"`) ||
		!strings.Contains(string(p.Files["index.html"]), demo.Repository) {
		t.Error("the demo's review package lacks the fail, the pass, the approved exception or the report")
	}

	// A visitor can still act: request and approve a new exception on the
	// open finding, as the walkthrough describes.
	owner, _ := svc.ActorByUsername(ctx, "control-owner")
	reviewer, _ := svc.ActorByUsername(ctx, "reviewer")
	for _, f := range findings {
		if !f.Open() {
			continue
		}
		xid, err := svc.RequestException(ctx, owner, f.ID, "Still waiting on the log bucket.", time.Now().Add(72*time.Hour))
		if err != nil {
			t.Fatalf("request a new exception: %v", err)
		}
		if err := svc.DecideException(ctx, owner, xid, true, "self"); err == nil {
			t.Error("the requester approved their own exception")
		}
		if err := svc.DecideException(ctx, reviewer, xid, true, "Accepted for three days."); err != nil {
			t.Fatalf("approve it: %v", err)
		}
	}
	ov, err = svc.Overview(ctx, viewer)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range ov.Controls {
		if c.Control.Key == "ai-usage-logging" && c.State != control.AcceptedRisk {
			t.Errorf("after the new exception ai-usage-logging is %s, want accepted_risk", c.State)
		}
	}

	// A database with anything else in it is refused.
	other, err := store.Open(ctx, testdb.New(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	if _, err := other.UpsertResource(ctx, "github", "repository", "someone/real-repo", "operator", now); err != nil {
		t.Fatal(err)
	}
	if _, err := demo.Seeded(ctx, other); !errors.Is(err, demo.ErrNotEmpty) {
		t.Errorf("a database holding other data: err = %v, want ErrNotEmpty", err)
	}
}
