package assurance_test

import (
	"context"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aelasmar01Lab/control-assurance/internal/assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/authz"
	"github.com/aelasmar01Lab/control-assurance/internal/aws"
	"github.com/aelasmar01Lab/control-assurance/internal/aws/awstest"
	"github.com/aelasmar01Lab/control-assurance/internal/check"
	"github.com/aelasmar01Lab/control-assurance/internal/evidence"
	"github.com/aelasmar01Lab/control-assurance/internal/github"
	"github.com/aelasmar01Lab/control-assurance/internal/github/githubtest"
	"github.com/aelasmar01Lab/control-assurance/internal/pack"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
	"github.com/aelasmar01Lab/control-assurance/internal/testdb"
	"github.com/aelasmar01Lab/control-assurance/packs"
)

// harness is one service wired to a fake GitHub, a temporary evidence store
// and a private database schema. All data in it is synthetic.
type harness struct {
	t     *testing.T
	svc   *assurance.Service
	st    *store.Store
	fake  *githubtest.Fake
	gh    *github.Client
	aws   *awstest.Fake
	repos []string
	clock time.Time

	// The four lab users.
	operator, owner, reviewer, auditor authz.Actor
	dbURL                              string
}

// advance moves the service's clock forward.
func (h *harness) advance(d time.Duration) { h.clock = h.clock.Add(d) }

// rawConn is a direct connection to the test's database, for statements the
// store has no method for because the product never makes them.
func (h *harness) rawConn() *pgx.Conn {
	h.t.Helper()
	conn, err := pgx.Connect(context.Background(), h.dbURL)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	dbURL := testdb.New(t)
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fake := githubtest.NewFake()
	t.Cleanup(fake.Server.Close)
	gh := fake.Client()
	h := &harness{
		t: t, st: st, fake: fake, gh: gh, dbURL: dbURL,
		repos: []string{githubtest.FakeRepository},
		clock: time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC),
	}
	h.aws = awstest.New(h.clock)
	collectors := gh.Collectors()
	maps.Copy(collectors, (&aws.Collector{
		API:   h.aws,
		Sleep: func(context.Context, time.Duration) error { return nil },
	}).Collectors())
	h.svc = &assurance.Service{Store: st, Evidence: ev, Collectors: collectors, Now: func() time.Time { return h.clock }}

	if _, err := h.svc.SeedLabUsers(ctx); err != nil {
		t.Fatalf("SeedLabUsers: %v", err)
	}
	for name, dst := range map[string]*authz.Actor{
		"operator": &h.operator, "control-owner": &h.owner, "reviewer": &h.reviewer, "auditor": &h.auditor,
	} {
		if *dst, err = h.svc.ActorByUsername(ctx, name); err != nil {
			t.Fatalf("lab user %s: %v", name, err)
		}
	}
	return h
}

// collect makes one attempt to collect branch rules and returns its summary.
func (h *harness) collect() assurance.RunSummary {
	h.t.Helper()
	runs := h.collectKinds("github", h.repos, github.BranchRulesKind)
	if len(runs) != 1 {
		h.t.Fatalf("runs = %d, want 1", len(runs))
	}
	return runs[0]
}

// collectKinds queues the given kinds for the targets and runs what is due.
// With no kinds it collects everything the integration offers.
func (h *harness) collectKinds(provider string, targets []string, kinds ...string) []assurance.RunSummary {
	h.t.Helper()
	ctx := context.Background()
	if _, err := h.svc.RequestCollection(ctx, h.operator, provider, targets, kinds); err != nil {
		h.t.Fatalf("RequestCollection: %v", err)
	}
	return h.work()
}

// work runs every attempt that is due.
func (h *harness) work() []assurance.RunSummary {
	h.t.Helper()
	runs, err := h.svc.Work(context.Background(), h.operator, 3)
	if err != nil {
		h.t.Fatalf("Work: %v", err)
	}
	return runs
}

// collectEverything collects every kind from the fake repository and the
// fake account.
func (h *harness) collectEverything() []assurance.RunSummary {
	h.t.Helper()
	ctx := context.Background()
	if _, err := h.svc.RequestCollection(ctx, h.operator, "github", h.repos, nil); err != nil {
		h.t.Fatalf("RequestCollection: %v", err)
	}
	if _, err := h.svc.RequestCollection(ctx, h.operator, "aws", []string{awstest.FakeAccount}, nil); err != nil {
		h.t.Fatalf("RequestCollection: %v", err)
	}
	return h.work()
}

func (h *harness) evaluate() []assurance.EvaluationSummary {
	h.t.Helper()
	out, err := h.svc.Evaluate(context.Background(), h.operator)
	if err != nil {
		h.t.Fatalf("Evaluate: %v", err)
	}
	return out
}

// result returns the current result for a check, or "" if there is none.
func (h *harness) result(key string) store.EvaluationRow {
	h.t.Helper()
	rows, err := h.st.LatestResults(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	for _, r := range rows {
		if r.CheckKey == key {
			return r
		}
	}
	return store.EvaluationRow{}
}

func (h *harness) findings(key string) []store.FindingRow {
	h.t.Helper()
	all, err := h.st.Findings(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	var out []store.FindingRow
	for _, f := range all {
		if f.CheckKey == key {
			out = append(out, f)
		}
	}
	return out
}

func (h *harness) evaluationCount(key string) int {
	h.t.Helper()
	rows, err := h.st.Evaluations(context.Background(), 1000)
	if err != nil {
		h.t.Fatal(err)
	}
	n := 0
	for _, r := range rows {
		if r.CheckKey == key {
			n++
		}
	}
	return n
}

// Scenario: disabling the rule yields a fail and one finding; re-enabling it
// closes the finding, and both evaluations are still listed.
func TestFailFindingPassLoop(t *testing.T) {
	h := newHarness(t)

	// The rule is in place: pass, no finding.
	h.fake.SetRules(true, githubtest.PullRequestRule(1), githubtest.StatusChecksRule("ci"))
	h.collect()
	h.evaluate()
	if got := h.result("GH-01").Result; got != "pass" {
		t.Fatalf("initial GH-01 = %q, want pass", got)
	}
	if n := len(h.findings("GH-01")); n != 0 {
		t.Fatalf("findings before the change = %d, want 0", n)
	}

	// The rule is disabled: fail and exactly one finding.
	h.fake.SetRules(false)
	h.collect()
	evals := h.evaluate()
	if got := h.result("GH-01").Result; got != "fail" {
		t.Fatalf("GH-01 after disabling = %q, want fail", got)
	}
	opened := 0
	for _, e := range evals {
		if e.CheckKey == "GH-01" && e.Finding == store.FindingOpened {
			opened++
		}
	}
	if opened != 1 {
		t.Errorf("findings opened = %d, want 1", opened)
	}

	// Collecting the same failing state again must not open a second finding.
	h.collect()
	h.evaluate()
	fs := h.findings("GH-01")
	if len(fs) != 1 || !fs[0].Open() {
		t.Fatalf("findings after a repeat failure = %+v, want one open finding", fs)
	}
	failingEvaluation := fs[0].OpeningEvaluationID

	// The rule is restored: pass, and the finding is closed by that pass.
	h.fake.SetRules(true, githubtest.PullRequestRule(1), githubtest.StatusChecksRule("ci"))
	h.collect()
	h.evaluate()
	current := h.result("GH-01")
	if current.Result != "pass" {
		t.Fatalf("GH-01 after re-enabling = %q, want pass", current.Result)
	}
	fs = h.findings("GH-01")
	if len(fs) != 1 || fs[0].Open() {
		t.Fatalf("findings after the fix = %+v, want one closed finding", fs)
	}
	if fs[0].OpeningEvaluationID != failingEvaluation {
		t.Errorf("opening evaluation changed from %d to %d", failingEvaluation, fs[0].OpeningEvaluationID)
	}
	if *fs[0].ClosingEvaluationID != current.EvaluationID {
		t.Errorf("closing evaluation = %d, want the passing evaluation %d", *fs[0].ClosingEvaluationID, current.EvaluationID)
	}

	// History is intact: pass, fail, fail, pass.
	if n := h.evaluationCount("GH-01"); n != 4 {
		t.Errorf("GH-01 evaluations = %d, want 4", n)
	}

	// Evaluating again with nothing new adds nothing.
	if extra := h.evaluate(); len(extra) != 0 {
		t.Errorf("a repeat evaluate produced %d evaluations, want 0", len(extra))
	}

	// A second failure after the fix opens a new finding; the old one stays closed.
	h.fake.SetRules(false)
	h.collect()
	h.evaluate()
	fs = h.findings("GH-01")
	if len(fs) != 2 || !fs[0].Open() || fs[1].Open() {
		t.Errorf("findings after a regression = %+v, want one open and one closed", fs)
	}
}

// Scenario: an invalid token yields a collection error and no change of result.
func TestInvalidTokenIsACollectionErrorNotAResult(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRules(true, githubtest.PullRequestRule(1), githubtest.StatusChecksRule("ci"))
	h.collect()
	h.evaluate()
	before01, before02 := h.result("GH-01"), h.result("GH-02")
	if before01.Result != "pass" || before02.Result != "pass" {
		t.Fatalf("setup: GH-01 = %q, GH-02 = %q", before01.Result, before02.Result)
	}

	// The token stops working, and at the same time the rule is removed.
	// Neither may show up as a result: nothing was observed.
	h.gh.Token = "expired-token"
	h.fake.SetRules(false)
	run := h.collect()
	if run.Succeeded || run.ErrorClass != string(github.ClassAuth) {
		t.Fatalf("run = %+v, want a failed run with class auth", run)
	}
	if run.ObservationID != 0 {
		t.Errorf("a failed run recorded observation %d", run.ObservationID)
	}
	if evals := h.evaluate(); len(evals) != 0 {
		t.Errorf("a failed run led to %d evaluations, want 0", len(evals))
	}
	if after := h.result("GH-01"); after != before01 {
		t.Errorf("GH-01 changed after a failed run:\n before %+v\n after  %+v", before01, after)
	}
	if after := h.result("GH-02"); after != before02 {
		t.Errorf("GH-02 changed after a failed run")
	}
	if n := len(h.findings("GH-01")); n != 0 {
		t.Errorf("a failed run opened %d findings", n)
	}

	runs, err := h.st.Runs(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0].Outcome != "failed" || runs[0].ErrorClass != "auth" || runs[0].InventoryComplete {
		t.Errorf("runs = %+v, want the newest to be a failed auth run", runs)
	}
}

// Every failure class is recorded on the run and none produces a result.
func TestNoFaultProducesAResult(t *testing.T) {
	faults := []struct {
		name      string
		inject    func(h *harness)
		wantClass github.ErrorClass
	}{
		{"forbidden", func(h *harness) { h.fake.SetFailure(http.StatusForbidden, nil) }, github.ClassPermission},
		{"rate limited", func(h *harness) {
			h.fake.SetFailure(http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"})
		}, github.ClassRateLimited},
		{"server error", func(h *harness) { h.fake.SetFailure(http.StatusServiceUnavailable, nil) }, github.ClassServer},
		{"malformed response", func(h *harness) { h.fake.SetMalformed(true) }, github.ClassMalformed},
		{"repository not found", func(h *harness) { h.repos = []string{"lab-org/missing"} }, github.ClassNotFound},
		{"network failure", func(h *harness) { h.fake.Server.Close() }, github.ClassNetwork},
	}
	for _, f := range faults {
		t.Run(f.name, func(t *testing.T) {
			h := newHarness(t)
			h.fake.SetRules(true, githubtest.PullRequestRule(1))
			f.inject(h)
			run := h.collect()
			if run.Succeeded || run.ErrorClass != string(f.wantClass) {
				t.Fatalf("run = %+v, want a failed run with class %s", run, f.wantClass)
			}
			if evals := h.evaluate(); len(evals) != 0 {
				t.Errorf("fault produced %d evaluations, want 0", len(evals))
			}
			if got := h.result("GH-01").Result; got != "" {
				t.Errorf("fault produced result %q", got)
			}
		})
	}
}

// Scenario: a truncated-pagination fixture yields incomplete coverage.
func TestTruncatedPaginationIsIncompleteCoverage(t *testing.T) {
	h := newHarness(t)

	// A complete listing with no qualifying rule is a real fail, with a finding.
	h.fake.SetRules(true, githubtest.FillerRule(1))
	h.collect()
	h.evaluate()
	if got := h.result("GH-01").Result; got != "fail" {
		t.Fatalf("setup: GH-01 = %q, want fail", got)
	}

	// Now the qualifying rule exists but sits on a page the collector never
	// reads. That must not be a pass, and must not be a fail either.
	h.fake.SetRules(true, githubtest.FillerRule(1), githubtest.FillerRule(2), githubtest.PullRequestRule(1))
	h.fake.SetPageSize(1)
	h.gh.MaxPages = 2
	run := h.collect()
	if !run.Succeeded || run.InventoryComplete {
		t.Fatalf("run = %+v, want a succeeded run with incomplete inventory", run)
	}
	h.evaluate()
	got := h.result("GH-01")
	if got.Result != string(check.NotEvaluated) {
		t.Fatalf("GH-01 = %q, want not_evaluated", got.Result)
	}
	if !strings.Contains(got.Explanation, "Incomplete coverage") {
		t.Errorf("explanation = %q, want it to say incomplete coverage", got.Explanation)
	}
	// The earlier finding is neither closed nor duplicated by an unknown.
	fs := h.findings("GH-01")
	if len(fs) != 1 || !fs[0].Open() {
		t.Errorf("findings = %+v, want the one open finding untouched", fs)
	}
}

// Re-running a recorded check version over stored evidence reproduces the
// original result exactly.
func TestStoredEvaluationsReproduce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.fake.SetRules(true, githubtest.PullRequestRule(1))
	h.collect()
	h.fake.SetRules(false)
	h.collect()
	h.evaluate()

	rows, err := h.st.Evaluations(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("evaluations = %d, want 4", len(rows))
	}
	for _, r := range rows {
		c, ok := check.Lookup(r.CheckKey, r.CheckVersion)
		if !ok {
			t.Fatalf("check %s version %s is no longer registered", r.CheckKey, r.CheckVersion)
		}
		payload, err := h.svc.Evidence.Get(ctx, r.PayloadSHA256)
		if err != nil {
			t.Fatal(err)
		}
		result, explanation, err := c.Eval(check.Input{Payload: payload, AsOf: r.AsOf})
		if err != nil {
			t.Fatal(err)
		}
		if string(result) != r.Result || explanation != r.Explanation {
			t.Errorf("evaluation %d does not reproduce: stored %s %q, got %s %q",
				r.EvaluationID, r.Result, r.Explanation, result, explanation)
		}
	}
}

// Identical evidence is stored once, and every observation is kept.
func TestIdenticalEvidenceSharesOnePayload(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRules(true, githubtest.PullRequestRule(1))
	first := h.collect()
	second := h.collect()
	if first.PayloadSHA256 != second.PayloadSHA256 {
		t.Errorf("same state, different payload hashes: %s and %s", first.PayloadSHA256, second.PayloadSHA256)
	}
	if first.ObservationID == second.ObservationID {
		t.Error("two collections share one observation; every observation must be kept")
	}
}

func TestImportPack(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	all, err := pack.LoadFS(packs.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range all {
		imported, err := h.st.ImportPack(ctx, p)
		if err != nil || !imported {
			t.Fatalf("first import = %v, %v; want true, nil", imported, err)
		}
		// Importing the same pack again changes nothing.
		imported, err = h.st.ImportPack(ctx, p)
		if err != nil || imported {
			t.Fatalf("second import = %v, %v; want false, nil", imported, err)
		}
		// Different content under the same key and version is refused.
		changed := *p
		changed.ContentSHA256 = strings.Repeat("0", 64)
		if _, err := h.st.ImportPack(ctx, &changed); err == nil {
			t.Error("a changed pack was accepted under an existing version")
		}
	}
	counts, err := h.st.RequirementCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := counts["mvsp v3.0-20231109"]; got != 25 {
		t.Errorf("imported MVSP requirements = %d, want 25 (all: %v)", got, counts)
	}
}
