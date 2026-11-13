package assurance_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/authz"
	"github.com/aelasmar01Lab/control-assurance/internal/check"
	"github.com/aelasmar01Lab/control-assurance/internal/github/githubtest"
	"github.com/aelasmar01Lab/control-assurance/internal/pack"
	"github.com/aelasmar01Lab/control-assurance/packs"
)

// The verification scenarios of the discovery document that no earlier
// test asserted in full. docs/verification.md maps all eleven to tests.

// Scenario 1: valid source data and a satisfied assertion. The passing
// result names the observation that was just collected, the bytes that
// observation stored, the resource they came from and the check version
// that judged them. An older observation of a different state is not it.
func TestPassLinksToItsEvidenceAndCheckVersion(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// An earlier, failing state, so that there is wrong evidence to link to.
	h.fake.SetRules(false)
	earlier := h.collect()
	h.evaluate()
	h.advance(time.Hour)
	h.fake.SetRules(true, githubtest.PullRequestRule(1), githubtest.StatusChecksRule("ci"))
	run := h.collect()
	h.evaluate()
	if !run.Succeeded || run.PayloadSHA256 == earlier.PayloadSHA256 {
		t.Fatalf("setup: run %+v, earlier %+v", run, earlier)
	}

	got := h.result("GH-01")
	if got.Result != "pass" {
		t.Fatalf("GH-01 = %q, want pass", got.Result)
	}
	if got.ObservationID != run.ObservationID || got.PayloadSHA256 != run.PayloadSHA256 {
		t.Errorf("the pass rests on observation %d (%s), want the one just collected, %d (%s)",
			got.ObservationID, got.PayloadSHA256, run.ObservationID, run.PayloadSHA256)
	}
	if got.Resource != githubtest.FakeRepository || !got.CollectedAt.Equal(h.clock) {
		t.Errorf("the pass is for %s collected at %s, want %s at %s", got.Resource, got.CollectedAt, githubtest.FakeRepository, h.clock)
	}

	// The hash is the hash of the bytes held, and those bytes describe the
	// passing state.
	payload, err := h.svc.Evidence.Get(ctx, got.PayloadSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(payload); hex.EncodeToString(sum[:]) != got.PayloadSHA256 {
		t.Errorf("the stored evidence does not match the hash the result names")
	}
	if !strings.Contains(string(payload), githubtest.FakeRepository) || !strings.Contains(string(payload), "pull_request") {
		t.Errorf("the evidence behind the pass does not show the repository and its rule: %s", payload)
	}

	// The version named is the one in force, and it gives the same answer
	// on that evidence.
	var current check.Check
	for _, c := range check.Current() {
		if c.Key == "GH-01" {
			current = c
		}
	}
	if got.CheckVersion == "" || got.CheckVersion != current.Version {
		t.Fatalf("the pass names check version %q, want the current one, %q", got.CheckVersion, current.Version)
	}
	result, explanation, err := current.Eval(check.Input{Payload: payload, AsOf: got.AsOf})
	if err != nil || string(result) != got.Result || explanation != got.Explanation {
		t.Errorf("version %s on that evidence gives %s %q (%v), stored %s %q", current.Version, result, explanation, err, got.Result, got.Explanation)
	}
}

// Scenario 2: a genuinely failing assertion. The finding names the
// resource; the explanation it carries names the branch and the condition
// that was not met. The explanation does not repeat the repository's name:
// it is read beside the finding, never apart from it.
func TestFailureNamesTheResourceAndTheCondition(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRules(false)
	run := h.collect()
	h.evaluate()

	got := h.result("GH-01")
	if got.Result != "fail" || got.ObservationID != run.ObservationID {
		t.Fatalf("GH-01 = %+v, want a fail on observation %d", got, run.ObservationID)
	}
	findings := h.findings("GH-01")
	if len(findings) != 1 || !findings[0].Open() {
		t.Fatalf("findings = %+v, want one open finding", findings)
	}
	f := findings[0]
	if f.Resource != githubtest.FakeRepository || f.CheckKey != "GH-01" || f.OpeningEvaluationID != got.EvaluationID {
		t.Errorf("finding = %+v, want it on %s, for GH-01, opened by evaluation %d", f, githubtest.FakeRepository, got.EvaluationID)
	}
	if f.OpeningExplanation != got.Explanation {
		t.Errorf("the finding explains %q, the evaluation %q", f.OpeningExplanation, got.Explanation)
	}
	for _, want := range []string{"No active rule on main", "requires an approving review", "listing complete"} {
		if !strings.Contains(f.OpeningExplanation, want) {
			t.Errorf("explanation %q does not name %q", f.OpeningExplanation, want)
		}
	}

	// A person reading the findings sees the same resource and reason.
	views, err := h.svc.Findings(context.Background(), h.auditor)
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, v := range views {
		if v.ID == f.ID {
			seen = v.Resource == f.Resource && v.OpeningExplanation == f.OpeningExplanation
		}
	}
	if !seen {
		t.Errorf("the findings view does not show finding %d with its resource and explanation", f.ID)
	}
}

// Scenario 7: an unchanged payload across collections. The bytes are held
// once; each collection keeps its own observation, with its own time and
// run, and each is evaluated.
func TestUnchangedPayloadKeepsEveryObservation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.fake.SetRules(true, githubtest.PullRequestRule(1), githubtest.StatusChecksRule("ci"))
	start := h.clock
	const collections = 3
	var runs []assurance.RunSummary
	for i := range collections {
		if i > 0 {
			h.advance(time.Hour)
		}
		runs = append(runs, h.collect())
		h.evaluate()
	}

	hashes, err := h.st.PayloadHashes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 1 || hashes[0] != runs[0].PayloadSHA256 {
		t.Errorf("payloads on record = %v, want the one, %s", hashes, runs[0].PayloadSHA256)
	}
	observations, err := h.st.Observations(ctx, start, h.clock.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != collections {
		t.Fatalf("%d observations for %d collections", len(observations), collections)
	}
	for i, o := range observations {
		if o.ID != runs[i].ObservationID || o.RunID != runs[i].RunID || o.PayloadSHA256 != hashes[0] ||
			!o.CollectedAt.Equal(start.Add(time.Duration(i)*time.Hour)) {
			t.Errorf("observation %d = %+v, want run %d's, an hour after the last, on the shared payload", i, o, runs[i].RunID)
		}
	}
	// One evaluation per observation, not one per payload.
	if n := h.evaluationCount("GH-01"); n != collections {
		t.Errorf("GH-01 has %d evaluations, want %d", n, collections)
	}
}

// Scenario 10: an unauthorized request. Whoever has no role, or a role the
// matrix does not know, reaches nothing: every method of the service that
// takes an actor refuses them, the exports and the background work
// included, and the refusals leave no trace.
func TestActorWithoutARoleReachesNothing(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.failing()
	xid, err := h.svc.RequestException(ctx, h.owner, f.ID, "Pending decision.", h.clock.Add(day))
	if err != nil {
		t.Fatal(err)
	}
	sid, err := h.svc.SubmitEvidence(ctx, h.owner, h.upload())
	if err != nil {
		t.Fatal(err)
	}
	all, err := pack.LoadFS(packs.FS)
	if err != nil {
		t.Fatal(err)
	}
	h.advance(2 * day)
	from, to := h.clock.Add(-2*day), h.clock.Add(-day)

	calls := map[string]func(a authz.Actor) error{
		"Evaluate":     func(a authz.Actor) error { _, err := h.svc.Evaluate(ctx, a); return err },
		"Requirements": func(a authz.Actor) error { _, err := h.svc.Requirements(ctx, a); return err },
		"Frameworks":   func(a authz.Actor) error { _, _, err := h.svc.Frameworks(ctx, a); return err },
		"LoadCatalog":  func(a authz.Actor) error { _, err := h.svc.LoadCatalog(ctx, a, all); return err },
		"LoadContent":  func(a authz.Actor) error { _, err := h.svc.LoadContent(ctx, a); return err },
		"Overview":     func(a authz.Actor) error { _, err := h.svc.Overview(ctx, a); return err },
		"OpenFindings": func(a authz.Actor) error { _, err := h.svc.OpenFindings(ctx, a); return err },
		"Findings":     func(a authz.Actor) error { _, err := h.svc.Findings(ctx, a); return err },
		"ManualEvidence": func(a authz.Actor) error {
			_, err := h.svc.ManualEvidence(ctx, a)
			return err
		},
		"EvidenceFile": func(a authz.Actor) error { _, _, err := h.svc.EvidenceFile(ctx, a, sid); return err },
		"DecisionLog":  func(a authz.Actor) error { _, err := h.svc.DecisionLog(ctx, a); return err },
		"Export":       func(a authz.Actor) error { _, err := h.svc.Export(ctx, a); return err },
		"SubmitEvidence": func(a authz.Actor) error {
			_, err := h.svc.SubmitEvidence(ctx, a, h.upload())
			return err
		},
		"ReviewEvidence": func(a authz.Actor) error { return h.svc.ReviewEvidence(ctx, a, sid, true, "ok") },
		"RequestException": func(a authz.Actor) error {
			_, err := h.svc.RequestException(ctx, a, f.ID, "x", h.clock.Add(day))
			return err
		},
		"DecideException": func(a authz.Actor) error { return h.svc.DecideException(ctx, a, xid, true, "ok") },
		"AddRemediationNote": func(a authz.Actor) error {
			_, err := h.svc.AddRemediationNote(ctx, a, f.ID, "note")
			return err
		},
		"BuildPackage": func(a authz.Actor) error { _, err := h.svc.BuildPackage(ctx, a, from, to); return err },
		"Reproduce":    func(a authz.Actor) error { _, err := h.svc.Reproduce(ctx, a); return err },
		"RequestCollection": func(a authz.Actor) error {
			_, err := h.svc.RequestCollection(ctx, a, "github", h.repos, nil)
			return err
		},
		"RequestAll":  func(a authz.Actor) error { _, err := h.svc.RequestAll(ctx, a); return err },
		"ScheduleDue": func(a authz.Actor) error { _, err := h.svc.ScheduleDue(ctx, a, time.Hour); return err },
		"Work":        func(a authz.Actor) error { _, err := h.svc.Work(ctx, a, 1); return err },
		"Health":      func(a authz.Actor) error { _, err := h.svc.Health(ctx, a); return err },
		"ReviewQueue": func(a authz.Actor) error { _, err := h.svc.ReviewQueue(ctx, a); return err },
	}

	// Every method that takes an actor is in the list above: one added
	// later without a test here fails this.
	actorType := reflect.TypeFor[authz.Actor]()
	svcType := reflect.TypeFor[*assurance.Service]()
	for i := range svcType.NumMethod() {
		m := svcType.Method(i)
		takesActor := false
		for j := range m.Type.NumIn() {
			takesActor = takesActor || m.Type.In(j) == actorType
		}
		if _, ok := calls[m.Name]; takesActor != ok {
			t.Errorf("Service.%s: takes an actor = %v, tested here = %v", m.Name, takesActor, ok)
		}
	}

	strangers := map[string]authz.Actor{
		"nobody":                {},
		"a role with no user":   {Role: authz.Operator},
		"a role nobody defined": {UserID: h.operator.UserID, Username: "operator", Role: "admin"},
	}
	logBefore := h.logCount()
	runsBefore, err := h.st.Runs(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for who, actor := range strangers {
		for name, call := range calls {
			if err := call(actor); !errors.Is(err, authz.ErrDenied) {
				t.Errorf("%s calling %s: err = %v, want permission denied", who, name, err)
			}
		}
	}
	if got := h.logCount(); got != logBefore {
		t.Errorf("refused requests added %d decision log entries", got-logBefore)
	}
	if runsAfter, _ := h.st.Runs(ctx, 1000); len(runsAfter) != len(runsBefore) {
		t.Errorf("refused requests queued %d collection runs", len(runsAfter)-len(runsBefore))
	}
}

// docs/verification.md maps the eleven scenarios to tests. Every test it
// names exists, and it names each scenario.
func TestVerificationDocumentNamesRealTests(t *testing.T) {
	const root = "../.."
	doc, err := os.ReadFile(filepath.Join(root, "docs", "verification.md"))
	if err != nil {
		t.Fatal(err)
	}
	defined := map[string]bool{}
	decl := regexp.MustCompile(`(?m)^func (Test\w+)\(`)
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path) //nolint:gosec // a test file of this repository
		if err != nil {
			return err
		}
		for _, m := range decl.FindAllSubmatch(src, -1) {
			defined[string(m[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	named := regexp.MustCompile("`(Test\\w+)`").FindAllSubmatch(doc, -1)
	if len(named) < 11 {
		t.Fatalf("the document names %d tests", len(named))
	}
	for _, m := range named {
		if !defined[string(m[1])] {
			t.Errorf("docs/verification.md names %s, which is not a test in this repository", m[1])
		}
	}
	for n := 1; n <= 11; n++ {
		if !regexp.MustCompile(`(?m)^\| ` + strconv.Itoa(n) + ` \| .*\x60Test`).Match(doc) {
			t.Errorf("scenario %d has no row naming a test", n)
		}
	}
}
