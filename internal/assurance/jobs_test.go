package assurance_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/smithy-go"

	"github.com/aelasmar01Lab/control-assurance/internal/assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/aws"
	"github.com/aelasmar01Lab/control-assurance/internal/aws/awstest"
	"github.com/aelasmar01Lab/control-assurance/internal/check"
	"github.com/aelasmar01Lab/control-assurance/internal/collect"
	"github.com/aelasmar01Lab/control-assurance/internal/control"
	"github.com/aelasmar01Lab/control-assurance/internal/github"
	"github.com/aelasmar01Lab/control-assurance/internal/github/githubtest"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
)

var allChecks = []string{"GH-01", "GH-02", "GH-03", "GH-04", "AWS-01", "AWS-02", "AWS-03", "AWS-04"}

// healthy puts the fake sources in a state every check passes on.
func (h *harness) healthy() {
	h.fake.SetRules(true, githubtest.PullRequestRule(1), githubtest.StatusChecksRule("ci"))
	h.fake.SetAlerts()
	h.fake.SetFiles("SECURITY.md")
}

// unhealthy puts the fake sources in a state every check fails on.
func (h *harness) unhealthy() {
	old := h.clock.Add(-200 * 24 * time.Hour).Format(time.RFC3339)
	h.fake.SetRules(false)
	h.fake.SetAlerts(githubtest.Alert{Number: 1, Severity: "high", Created: old})
	h.fake.SetFiles()
	h.aws.Set(func(f *awstest.Fake) {
		f.RootMFA = false
		f.Users = []awstest.User{{Name: "synthetic-stale", Key1Active: true, Key1LastUsed: old, Key1LastRotated: old}}
		f.TrailList = nil
		f.BedrockBucket = ""
	})
}

// results returns the current result of every check, by key.
func (h *harness) results() map[string]string {
	h.t.Helper()
	rows, err := h.st.LatestResults(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.CheckKey] = r.Result
	}
	return out
}

func (h *harness) run(id int64) store.RunRow {
	h.t.Helper()
	run, err := h.st.RunByID(context.Background(), id)
	if err != nil {
		h.t.Fatal(err)
	}
	return run
}

// Done-when: all eight checks run, each against its own evidence.
func TestAllEightChecksRun(t *testing.T) {
	h := newHarness(t)
	h.healthy()

	runs := h.collectEverything()
	if len(runs) != 6 {
		t.Fatalf("runs = %d, want 6 (three kinds from each source)", len(runs))
	}
	for _, r := range runs {
		if !r.Succeeded || !r.InventoryComplete {
			t.Errorf("run %+v did not succeed with complete coverage", r)
		}
	}
	if evals := h.evaluate(); len(evals) != len(allChecks) {
		t.Fatalf("evaluations = %d, want %d", len(evals), len(allChecks))
	}
	got := h.results()
	for _, key := range allChecks {
		if got[key] != "pass" {
			t.Errorf("%s = %q, want pass on a healthy source", key, got[key])
		}
	}
	for _, c := range control.All {
		if len(c.Checks) > 0 {
			h.wantBest(c.Key)
		}
	}

	// The same sources in a bad state: every check fails, each with a finding.
	h.unhealthy()
	h.advance(time.Hour)
	h.collectEverything()
	h.evaluate()
	got = h.results()
	for _, key := range allChecks {
		if got[key] != "fail" {
			t.Errorf("%s = %q, want fail on an unhealthy source", key, got[key])
		}
		if n := len(h.findings(key)); n != 1 {
			t.Errorf("%s has %d findings, want 1", key, n)
		}
	}
}

// Ages are measured to the moment the evidence describes, so an evaluation
// reproduces whenever it is repeated.
func TestAgesAreMeasuredToTheSourceTimestamp(t *testing.T) {
	h := newHarness(t)
	generated := h.clock.Add(-3 * time.Hour)
	lastUsed := generated.Add(-100 * 24 * time.Hour).Format(time.RFC3339)
	h.aws.Set(func(f *awstest.Fake) {
		f.ReportGenerated = generated
		f.Users = []awstest.User{{Name: "synthetic-stale", Key1Active: true, Key1LastUsed: lastUsed, Key1LastRotated: lastUsed}}
	})
	h.collectKinds("aws", []string{awstest.FakeAccount}, aws.IAMCredentialsKind)
	h.evaluate()

	r := h.result("AWS-02")
	if r.Result != "fail" || !strings.Contains(r.Explanation, "idle 100 days") {
		t.Fatalf("AWS-02 = %s %q, want a fail naming 100 idle days", r.Result, r.Explanation)
	}
	if !r.AsOf.Equal(generated) || !r.CollectedAt.Equal(h.clock) {
		t.Errorf("as-of %s, collected %s; want the report time %s and the clock %s", r.AsOf, r.CollectedAt, generated, h.clock)
	}

	// A year later the stored evaluation still reproduces exactly.
	h.advance(365 * 24 * time.Hour)
	ctx := context.Background()
	rows, err := h.st.Evaluations(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		c, _ := check.Lookup(row.CheckKey, row.CheckVersion)
		payload, err := h.svc.Evidence.Get(ctx, row.PayloadSHA256)
		if err != nil {
			t.Fatal(err)
		}
		result, explanation, err := c.Eval(check.Input{Payload: payload, AsOf: row.AsOf})
		if err != nil || string(result) != row.Result || explanation != row.Explanation {
			t.Errorf("evaluation %d does not reproduce: %s %q (%v)", row.EvaluationID, result, explanation, err)
		}
	}
}

// awsError is the classified form of an AWS API error code, as the SDK
// adapter would return it.
func awsError(code string, fault smithy.ErrorFault) error {
	return aws.Classify("synthetic:Operation", &smithy.GenericAPIError{Code: code, Message: "synthetic", Fault: fault})
}

// brokenStore is an evidence store that refuses every write.
type brokenStore struct{}

func (brokenStore) Put(context.Context, []byte) (string, string, error) {
	return "", "", errors.New("synthetic: disk full")
}
func (brokenStore) Get(context.Context, string) ([]byte, error) {
	return nil, errors.New("synthetic: disk full")
}

// injection says how a fault is injected and where it is expected to show.
type injection struct {
	provider string
	kind     string
	// check is the check whose result an evidence fault must decide.
	check  string
	inject func(h *harness)
	// attempt replaces the default "collect the kind once" when set, and
	// returns the id of the run that must carry the fault's class.
	attempt func(h *harness) int64
	// reruns is true when recovery from the fault collects again.
	reruns bool
}

var injections = map[string]injection{
	"github-invalid-token": {provider: "github", kind: github.BranchRulesKind, inject: func(h *harness) { h.gh.Token = "expired-token" }},
	"github-forbidden":     {provider: "github", kind: github.AlertsKind, inject: func(h *harness) { h.fake.SetFailure(http.StatusForbidden, nil) }},
	"github-rate-limited": {provider: "github", kind: github.BranchRulesKind, inject: func(h *harness) {
		h.fake.SetFailure(http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0", "Retry-After": "120"})
	}},
	"github-not-found":    {provider: "github", kind: github.SecurityPolicyKind, inject: func(h *harness) { h.repos = []string{"lab-org/missing"} }},
	"github-server-error": {provider: "github", kind: github.BranchRulesKind, inject: func(h *harness) { h.fake.SetFailure(http.StatusServiceUnavailable, nil) }},
	"github-malformed":    {provider: "github", kind: github.AlertsKind, inject: func(h *harness) { h.fake.SetMalformed(true) }},
	"github-unreachable":  {provider: "github", kind: github.SecurityPolicyKind, inject: func(h *harness) { h.fake.Server.Close() }},
	"github-teapot":       {provider: "github", kind: github.BranchRulesKind, inject: func(h *harness) { h.fake.SetFailure(http.StatusTeapot, nil) }},

	"aws-expired-credentials": {provider: "aws", kind: aws.IAMCredentialsKind, inject: func(h *harness) {
		h.aws.Set(func(f *awstest.Fake) { f.Err = awsError("ExpiredToken", smithy.FaultClient) })
	}},
	"aws-access-denied": {provider: "aws", kind: aws.BedrockLoggingKind, inject: func(h *harness) {
		h.aws.Set(func(f *awstest.Fake) { f.Err = awsError("AccessDenied", smithy.FaultClient) })
	}},
	"aws-throttled": {provider: "aws", kind: aws.TrailsKind, inject: func(h *harness) {
		h.aws.Set(func(f *awstest.Fake) { f.Err = awsError("ThrottlingException", smithy.FaultClient) })
	}},
	"aws-server-fault": {provider: "aws", kind: aws.TrailsKind, inject: func(h *harness) {
		h.aws.Set(func(f *awstest.Fake) { f.Err = awsError("SyntheticFault", smithy.FaultServer) })
	}},
	"aws-unreachable": {provider: "aws", kind: aws.IAMCredentialsKind, inject: func(h *harness) {
		h.aws.Set(func(f *awstest.Fake) {
			f.Err = aws.Classify("synthetic:Operation", errors.New("dial tcp: connection refused"))
		})
	}},
	"aws-wrong-account": {provider: "aws", kind: aws.TrailsKind, inject: func(h *harness) {
		h.aws.Set(func(f *awstest.Fake) { f.Account = "111111111111" })
	}},
	"aws-report-malformed": {provider: "aws", kind: aws.IAMCredentialsKind, inject: func(h *harness) {
		h.aws.Set(func(f *awstest.Fake) { f.ReportCSV = "user,arn\nsynthetic,arn:aws:iam::000000000000:user/synthetic\n" })
	}},
	"aws-report-never-ready": {provider: "aws", kind: aws.IAMCredentialsKind, inject: func(h *harness) {
		h.aws.Set(func(f *awstest.Fake) { f.ReportReadyAfter = 1 << 30 })
	}},

	"evidence-store-down": {provider: "github", kind: github.BranchRulesKind, inject: func(h *harness) { h.svc.Evidence = brokenStore{} }},
	"collector-hangs": {provider: "github", kind: github.BranchRulesKind, inject: func(h *harness) {
		h.svc.RunTimeout = 20 * time.Millisecond
		h.svc.Collectors[github.BranchRulesKind] = func(ctx context.Context, _ string) (*collect.Snapshot, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}},
	"worker-killed": {provider: "github", kind: github.BranchRulesKind, reruns: true, attempt: func(h *harness) int64 {
		ctx := context.Background()
		if _, err := h.svc.RequestCollection(ctx, h.operator, "github", h.repos, []string{github.BranchRulesKind}); err != nil {
			h.t.Fatal(err)
		}
		// A worker claims the run and is killed: nothing finishes it.
		claimed, err := h.st.ClaimRun(ctx, []string{github.BranchRulesKind}, h.clock, h.clock.Add(5*time.Minute))
		if err != nil || claimed == nil {
			h.t.Fatalf("ClaimRun = %+v, %v", claimed, err)
		}
		// While the lease holds, the run belongs to the dead worker.
		if runs := h.work(); len(runs) != 0 {
			h.t.Fatalf("a live lease was taken over: %+v", runs)
		}
		h.advance(6 * time.Minute)
		runs := h.work()
		if len(runs) != 1 || !runs[0].Succeeded || runs[0].Attempt != 2 {
			h.t.Fatalf("recovery runs = %+v, want one successful second attempt", runs)
		}
		if retry := h.run(runs[0].RunID); retry.RetryOf == nil || *retry.RetryOf != claimed.ID || retry.Cause != "retry" {
			h.t.Errorf("recovery run = %+v, want a retry of run %d", retry, claimed.ID)
		}
		return claimed.ID
	}},

	"github-truncated-rules": {provider: "github", kind: github.BranchRulesKind, check: "GH-01", inject: func(h *harness) {
		h.fake.SetRules(true, githubtest.FillerRule(1), githubtest.FillerRule(2), githubtest.FillerRule(3), githubtest.PullRequestRule(1))
		h.fake.SetPageSize(1)
		h.gh.MaxPages = 2
	}},
	"github-truncated-alerts": {provider: "github", kind: github.AlertsKind, check: "GH-03", inject: func(h *harness) {
		recent := h.clock.Add(-time.Hour).Format(time.RFC3339)
		h.fake.SetAlerts(
			githubtest.Alert{Number: 1, Severity: "high", Created: recent},
			githubtest.Alert{Number: 2, Severity: "high", Created: recent},
			githubtest.Alert{Number: 3, Severity: "high", Created: h.clock.Add(-200 * 24 * time.Hour).Format(time.RFC3339)})
		h.fake.SetPageSize(1)
		h.gh.MaxPages = 2
	}},
	"github-alerts-disabled":    {provider: "github", kind: github.AlertsKind, check: "GH-03", inject: func(h *harness) { h.fake.DisableAlerts() }},
	"github-protected-no-rules": {provider: "github", kind: github.BranchRulesKind, check: "GH-01", inject: func(h *harness) { h.fake.SetRules(true) }},
	"aws-trail-status-denied": {provider: "aws", kind: aws.TrailsKind, check: "AWS-03", inject: func(h *harness) {
		h.aws.Set(func(f *awstest.Fake) { f.StatusErr = awsError("AccessDenied", smithy.FaultClient) })
	}},
}

// Done-when: each injected fault is classified correctly and none produces
// a pass. Every entry of the published fault table is exercised here.
func TestEveryFault(t *testing.T) {
	for name := range injections {
		found := false
		for _, f := range assurance.Faults {
			found = found || f.Name == name
		}
		if !found {
			t.Errorf("injection %q is not in the fault table", name)
		}
	}
	for _, f := range assurance.Faults {
		t.Run(f.Name, func(t *testing.T) {
			inj, ok := injections[f.Name]
			if !ok {
				t.Fatalf("fault %q is in the fault table but the suite does not inject it", f.Name)
			}
			if (f.Class == "") == (f.Result == "") || f.Result == "pass" {
				t.Fatalf("fault %q must name an error class or a result that is not pass", f.Name)
			}
			h := newHarness(t)
			targets := func() []string {
				if inj.provider == "aws" {
					return []string{awstest.FakeAccount}
				}
				return h.repos
			}

			if f.Class == "" {
				// A fault that is evidence: collection succeeds, the check declines.
				inj.inject(h)
				runs := h.collectKinds(inj.provider, targets(), inj.kind)
				if len(runs) != 1 || !runs[0].Succeeded {
					t.Fatalf("runs = %+v, want one successful run", runs)
				}
				h.evaluate()
				if got := h.results()[inj.check]; got != f.Result {
					t.Errorf("%s = %q, want %q", inj.check, got, f.Result)
				}
				return
			}

			// A fault that stops collection. Start from sources on which
			// every check fails, so a fault that produced a pass would show.
			h.unhealthy()
			h.collectEverything()
			h.evaluate()
			before := h.results()
			for _, key := range allChecks {
				if before[key] != "fail" {
					t.Fatalf("setup: %s = %q, want fail", key, before[key])
				}
			}
			findingsBefore, _ := h.st.Findings(context.Background())
			h.advance(time.Hour)

			if inj.inject != nil {
				inj.inject(h)
			}
			var failed store.RunRow
			if inj.attempt != nil {
				failed = h.run(inj.attempt(h))
			} else {
				runs := h.collectKinds(inj.provider, targets(), inj.kind)
				if len(runs) != 1 {
					t.Fatalf("runs = %+v, want 1", runs)
				}
				if runs[0].Succeeded || runs[0].ObservationID != 0 {
					t.Fatalf("run = %+v, want a failed run with no observation", runs[0])
				}
				failed = h.run(runs[0].RunID)

				_, wantRetry := assurance.NextAttempt(f.Class, 1, 0)
				if (runs[0].RetryRunID != 0) != wantRetry {
					t.Errorf("retry queued = %v, want %v for class %s", runs[0].RetryRunID != 0, wantRetry, f.Class)
				}
			}
			if failed.Outcome != "failed" || failed.ErrorClass != string(f.Class) {
				t.Errorf("run %d ended %s with class %q (%s), want failed with class %q",
					failed.ID, failed.Outcome, failed.ErrorClass, failed.ErrorDetail, f.Class)
			}
			if failed.InventoryComplete {
				t.Error("a failed run claims complete coverage")
			}

			// Nothing was observed, so nothing may be concluded.
			evals := h.evaluate()
			if !inj.reruns && len(evals) != 0 {
				t.Errorf("the fault led to %d evaluations, want 0", len(evals))
			}
			for _, e := range evals {
				if e.Result == check.Pass {
					t.Errorf("the fault produced a pass: %+v", e)
				}
			}
			after := h.results()
			for _, key := range allChecks {
				if after[key] != before[key] {
					t.Errorf("%s changed from %q to %q", key, before[key], after[key])
				}
			}
			if findingsAfter, _ := h.st.Findings(context.Background()); len(findingsAfter) != len(findingsBefore) {
				t.Errorf("findings went from %d to %d", len(findingsBefore), len(findingsAfter))
			}
		})
	}
}

func TestRetriesFollowThePolicy(t *testing.T) {
	h := newHarness(t)
	h.healthy()
	h.fake.SetFailure(http.StatusBadGateway, nil)

	// Attempt 1 fails; each retry waits its turn and is its own run.
	first := h.collect()
	if first.ErrorClass != "server" || first.Attempt != 1 {
		t.Fatalf("first attempt = %+v", first)
	}
	previous := first
	for _, step := range []struct {
		attempt int
		wait    time.Duration
	}{{2, time.Minute}, {3, 5 * time.Minute}, {4, 25 * time.Minute}} {
		if !previous.RetryAt.Equal(h.clock.Add(step.wait)) {
			t.Fatalf("attempt %d is due at %s, want %s after the failure", step.attempt, previous.RetryAt, step.wait)
		}
		// Not yet due: nothing runs.
		h.advance(step.wait - time.Second)
		if runs := h.work(); len(runs) != 0 {
			t.Fatalf("attempt %d ran early: %+v", step.attempt, runs)
		}
		h.advance(time.Second)
		runs := h.work()
		if len(runs) != 1 || runs[0].Attempt != step.attempt || runs[0].ErrorClass != "server" {
			t.Fatalf("attempt %d = %+v", step.attempt, runs)
		}
		if row := h.run(runs[0].RunID); row.RetryOf == nil || *row.RetryOf != previous.RunID || row.Cause != "retry" {
			t.Errorf("attempt %d = %+v, want a retry of run %d", step.attempt, row, previous.RunID)
		}
		previous = runs[0]
	}
	// The fourth failure is the last attempt.
	if previous.RetryRunID != 0 {
		t.Errorf("a fifth attempt was queued: %+v", previous)
	}
	h.advance(24 * time.Hour)
	if runs := h.work(); len(runs) != 0 {
		t.Errorf("runs after the last attempt: %+v", runs)
	}
	if got := h.result("GH-01").Result; got != "" {
		t.Errorf("four failed attempts produced result %q", got)
	}

	// The source recovers; the next request is a fresh first attempt.
	h.fake.SetFailure(http.StatusOK, nil)
	if run := h.collect(); !run.Succeeded || run.Attempt != 1 {
		t.Errorf("after recovery: %+v", run)
	}
}

func TestRateLimitWaitsAsLongAsTheSourceAsks(t *testing.T) {
	h := newHarness(t)
	h.fake.SetFailure(http.StatusTooManyRequests, map[string]string{"Retry-After": "600"})
	run := h.collect()
	if run.ErrorClass != "rate_limited" || !run.RetryAt.Equal(h.clock.Add(10*time.Minute)) {
		t.Errorf("run = %+v, want a retry ten minutes on", run)
	}

	// A source cannot park a job for longer than the cap.
	if d, ok := assurance.NextAttempt(collect.RateLimited, 1, 48*time.Hour); !ok || d != time.Hour {
		t.Errorf("NextAttempt with a two-day Retry-After = %s, %v; want 1h", d, ok)
	}
	// Classes that need a person are never retried.
	for _, class := range []collect.Class{collect.Auth, collect.Permission, collect.NotFound, collect.Unexpected} {
		if _, ok := assurance.NextAttempt(class, 1, 0); ok {
			t.Errorf("%s is retried", class)
		}
	}
	for _, class := range collect.Classes {
		if _, ok := assurance.RetryPolicies[class]; !ok {
			t.Errorf("error class %s has no retry policy", class)
		}
	}
}

// A person asking again does not wait out the retry delay, and does not
// queue a second attempt beside the waiting one.
func TestManualRequestBringsAWaitingRetryForward(t *testing.T) {
	h := newHarness(t)
	h.healthy()
	h.fake.SetFailure(http.StatusBadGateway, nil)
	failed := h.collect()
	h.fake.SetFailure(http.StatusOK, nil)

	run := h.collect()
	if !run.Succeeded || run.Attempt != 2 || run.RunID != failed.RetryRunID {
		t.Errorf("run = %+v, want the waiting retry (run %d) to succeed now", run, failed.RetryRunID)
	}
}

// Done-when: running the same job twice creates no duplicate finding.
func TestSameJobTwiceCreatesNoDuplicate(t *testing.T) {
	h := newHarness(t)
	h.unhealthy()
	ctx := context.Background()

	// Asked twice before any worker runs: one attempt per job is queued.
	first, err := h.svc.RequestCollection(ctx, h.operator, "github", h.repos, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.svc.RequestCollection(ctx, h.operator, "github", h.repos, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range first {
		if !first[i].Queued || second[i].Queued || first[i].RunID != second[i].RunID {
			t.Errorf("job %s: first %+v, second %+v; want one queued attempt", first[i].Kind, first[i], second[i])
		}
	}
	if runs := h.work(); len(runs) != len(github.Kinds) {
		t.Fatalf("runs = %d, want %d", len(runs), len(github.Kinds))
	}
	h.evaluate()

	// The whole job again, twice more, on the same failing source.
	for range 2 {
		h.advance(time.Hour)
		h.collectKinds("github", h.repos)
		h.evaluate()
		// Evaluating again with nothing new does nothing.
		if evals := h.evaluate(); len(evals) != 0 {
			t.Errorf("a second evaluation pass recorded %d evaluations", len(evals))
		}
	}
	for _, key := range []string{"GH-01", "GH-02", "GH-03", "GH-04"} {
		findings := h.findings(key)
		if len(findings) != 1 || !findings[0].Open() {
			t.Errorf("%s has %d findings, want one open finding", key, len(findings))
		}
		if n := h.evaluationCount(key); n != 3 {
			t.Errorf("%s has %d evaluations, want 3 (one per collection)", key, n)
		}
	}
}

// Workers never take the same attempt, within a process or across two.
func TestWorkersNeverShareAnAttempt(t *testing.T) {
	h := newHarness(t)
	var mu sync.Mutex
	collected := map[string]int{}
	h.svc.Collectors = map[string]assurance.CollectFunc{
		github.BranchRulesKind: func(_ context.Context, target string) (*collect.Snapshot, error) {
			mu.Lock()
			collected[target]++
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			return &collect.Snapshot{
				Kind: github.BranchRulesKind, Normalizer: "synthetic/1", Complete: true,
				Payload: []byte(`{"synthetic":"` + target + `"}`),
			}, nil
		},
	}
	var targets []string
	for i := range 24 {
		targets = append(targets, fmt.Sprintf("lab-org/repo-%02d", i))
	}
	ctx := context.Background()
	if _, err := h.svc.RequestCollection(ctx, h.operator, "github", targets, []string{github.BranchRulesKind}); err != nil {
		t.Fatal(err)
	}

	// Two pools at once, as two worker processes would be.
	var wg sync.WaitGroup
	total := make([]int, 2)
	for i := range total {
		wg.Go(func() {
			runs, err := h.svc.Work(ctx, h.operator, 4)
			if err != nil {
				t.Errorf("Work: %v", err)
			}
			total[i] = len(runs)
		})
	}
	wg.Wait()

	if total[0]+total[1] != len(targets) {
		t.Errorf("the pools made %d + %d runs, want %d in all", total[0], total[1], len(targets))
	}
	for _, target := range targets {
		if collected[target] != 1 {
			t.Errorf("%s was collected %d times, want once", target, collected[target])
		}
	}
}

func TestScheduleQueuesOnlyWhatIsDue(t *testing.T) {
	h := newHarness(t)
	h.healthy()
	ctx := context.Background()
	const day = 24 * time.Hour
	queuedBy := func() int {
		t.Helper()
		queued, err := h.svc.ScheduleDue(ctx, h.operator, day)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, q := range queued {
			if q.Queued {
				n++
			}
		}
		return n
	}

	// Nothing is in scope until a resource has been registered.
	if n := queuedBy(); n != 0 {
		t.Fatalf("scheduled %d runs with no resource in scope", n)
	}
	h.collectEverything()

	h.advance(23 * time.Hour)
	if n := queuedBy(); n != 0 {
		t.Errorf("scheduled %d runs an hour early", n)
	}
	h.advance(time.Hour)
	if n := queuedBy(); n != 6 {
		t.Errorf("scheduled %d runs, want 6", n)
	}
	// Scheduling again before the work is done queues nothing more.
	if n := queuedBy(); n != 0 {
		t.Errorf("scheduled %d runs twice", n)
	}
	if runs := h.work(); len(runs) != 6 {
		t.Errorf("worked %d runs, want 6", len(runs))
	}
}

func TestIntegrationHealth(t *testing.T) {
	h := newHarness(t)
	h.healthy()
	ctx := context.Background()
	job := func(kind string) assurance.JobView {
		t.Helper()
		health, err := h.svc.Health(ctx, h.auditor)
		if err != nil {
			t.Fatal(err)
		}
		if health.MayCollect {
			t.Error("the auditor is offered collection")
		}
		for _, j := range health.Jobs {
			if j.Kind == kind {
				return j
			}
		}
		t.Fatalf("no job for %s", kind)
		return assurance.JobView{}
	}
	problems := func() int {
		t.Helper()
		ov, err := h.svc.Overview(ctx, h.auditor)
		if err != nil {
			t.Fatal(err)
		}
		return ov.IntegrationProblems
	}

	h.collectEverything()
	h.evaluate()
	if j := job(github.BranchRulesKind); j.Status != assurance.JobHealthy || j.Stale || problems() != 0 {
		t.Fatalf("after a clean collection: %+v, %d problems", j, problems())
	}

	// A fault that is retried: the job is retrying, and the result stands.
	h.advance(time.Hour)
	h.fake.SetFailure(http.StatusBadGateway, nil)
	h.collect()
	j := job(github.BranchRulesKind)
	if j.Status != assurance.JobRetrying || j.FailuresSinceSuccess != 1 || j.PendingID == nil || j.Stale {
		t.Errorf("after a server error: %+v", j)
	}
	if problems() != 1 {
		t.Errorf("problems = %d, want 1", problems())
	}
	if got := h.result("GH-01").Result; got != "pass" {
		t.Errorf("GH-01 = %q after a failed run, want the earlier pass", got)
	}
	h.wantBest("change-management")

	// A fault that is not retried: the job is failing.
	h.fake.SetFailure(http.StatusOK, nil)
	h.gh.Token = "expired-token"
	h.collect()
	if j := job(github.BranchRulesKind); j.Status != assurance.JobFailing || j.FailuresSinceSuccess != 2 || *j.LastErrorClass != "auth" {
		t.Errorf("after an auth failure: %+v", j)
	}

	// Failed attempts do not keep evidence fresh: it ages to stale.
	h.advance(48 * time.Hour)
	if j := job(github.BranchRulesKind); !j.Stale || j.EvidenceAgeHours != 49 {
		t.Errorf("49 hours after the last success: %+v", j)
	}
	h.wantState("change-management", control.Stale)
	if got := h.result("GH-01").Result; got != "pass" {
		t.Errorf("GH-01 = %q; staleness must not rewrite the result", got)
	}

	// The operator may queue everything from the page.
	health, err := h.svc.Health(ctx, h.operator)
	if err != nil || !health.MayCollect {
		t.Errorf("operator health: MayCollect = %v, %v", health != nil && health.MayCollect, err)
	}
	h.gh.Token = githubtest.FakeToken
	if queued, err := h.svc.RequestAll(ctx, h.operator); err != nil || len(queued) != 6 {
		t.Fatalf("RequestAll = %d, %v; want 6", len(queued), err)
	}
	h.work()
	if j := job(github.BranchRulesKind); j.Status != assurance.JobHealthy || j.Stale || j.FailuresSinceSuccess != 0 || problems() != 0 {
		t.Errorf("after recovery: %+v, %d problems", j, problems())
	}
}

// A finished run is history: the database refuses to change or delete it.
func TestFinishedRunsCannotChange(t *testing.T) {
	h := newHarness(t)
	h.healthy()
	ok := h.collect()
	h.gh.Token = "expired-token"
	failed := h.collect()
	ctx := context.Background()

	for _, id := range []int64{ok.RunID, failed.RunID} {
		for _, stmt := range []string{
			`UPDATE collection_runs SET outcome = 'succeeded', error_class = '', inventory_complete = true WHERE id = $1`,
			`UPDATE collection_runs SET error_detail = 'rewritten' WHERE id = $1`,
			`DELETE FROM collection_runs WHERE id = $1`,
		} {
			if _, err := h.st.Pool().Exec(ctx, stmt, id); err == nil {
				t.Errorf("run %d: %q was allowed", id, stmt)
			}
		}
	}
	// A failed run can never be recorded as having read everything.
	if _, err := h.st.FailRun(ctx, ok.RunID, h.clock, "auth", "x", nil); !errors.Is(err, store.ErrRunNotRunning) {
		t.Errorf("failing a finished run: %v, want ErrRunNotRunning", err)
	}
}

func TestRequestCollectionValidatesTargets(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, tt := range []struct {
		provider string
		target   string
		kinds    []string
	}{
		{"github", "not-a-repository", nil},
		{"github", "../../etc/passwd", nil},
		{"aws", "12345", nil},
		{"aws", awstest.FakeAccount, []string{github.BranchRulesKind}},
		{"gitlab", "lab-org/lab-repo", nil},
	} {
		if _, err := h.svc.RequestCollection(ctx, h.operator, tt.provider, []string{tt.target}, tt.kinds); !errors.Is(err, assurance.ErrInvalid) {
			t.Errorf("RequestCollection(%s, %s, %v) = %v, want ErrInvalid", tt.provider, tt.target, tt.kinds, err)
		}
	}
	if runs, err := h.st.Runs(ctx, 10); err != nil || len(runs) != 0 {
		t.Errorf("invalid requests queued %d runs (%v)", len(runs), err)
	}
}

// The committed fault table must match the fault list and retry policies.
func TestFaultTableIsInSync(t *testing.T) {
	const path = "../../docs/faults.md"
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with `make guide`)", path, err)
	}
	if string(onDisk) != assurance.FaultTableMarkdown() {
		t.Errorf("%s is out of date; regenerate with `make guide`", path)
	}
}
