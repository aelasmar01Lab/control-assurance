package assurance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/authz"
	"github.com/aelasmar01Lab/control-assurance/internal/check"
	"github.com/aelasmar01Lab/control-assurance/internal/control"
	"github.com/aelasmar01Lab/control-assurance/internal/github"
	"github.com/aelasmar01Lab/control-assurance/internal/github/githubtest"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
)

func (h *harness) pack(from, to time.Time) *assurance.Package {
	h.t.Helper()
	p, err := h.svc.BuildPackage(context.Background(), h.auditor, from, to)
	if err != nil {
		h.t.Fatalf("BuildPackage: %v", err)
	}
	return p
}

// decode reads one JSON file of a package.
func decode[T any](t *testing.T, p *assurance.Package, path string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(p.Files[path], &v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return v
}

func controlState(t *testing.T, p *assurance.Package, key string) control.State {
	t.Helper()
	for _, c := range decode[[]assurance.PackageControl](t, p, "controls.json") {
		if c.Key == key {
			return c.StateAtPeriodEnd
		}
	}
	t.Fatalf("control %s is not in the package", key)
	return ""
}

// history plays out a fail, an exception and a later pass, and returns the
// moments between the steps.
type history struct {
	start, requested, approved, fixed, end time.Time
}

func (h *harness) history() history {
	h.t.Helper()
	ctx := context.Background()
	var m history
	m.start = h.clock.Add(-time.Hour)

	// Day 0: the rules are missing. Two fails, and two findings.
	h.failing()
	h.advance(time.Hour)
	var requests []int64
	for _, key := range []string{"GH-01", "GH-02"} {
		finding := h.findings(key)[0]
		if _, err := h.svc.AddRemediationNote(ctx, h.owner, finding.ID, "Ruleset change is scheduled."); err != nil {
			h.t.Fatal(err)
		}
		xid, err := h.svc.RequestException(ctx, h.owner, finding.ID, "The ruleset is being migrated.", h.clock.Add(30*day))
		if err != nil {
			h.t.Fatal(err)
		}
		requests = append(requests, xid)
	}
	h.advance(time.Hour)
	m.requested = h.clock

	// Day 1: the reviewer approves.
	h.advance(day)
	for _, xid := range requests {
		if err := h.svc.DecideException(ctx, h.reviewer, xid, true, "Accepted until the migration is done."); err != nil {
			h.t.Fatal(err)
		}
	}
	h.advance(time.Hour)
	m.approved = h.clock

	// Day 3: the rule is restored. A pass, and the finding closes.
	h.advance(2 * day)
	h.fake.SetRules(true, githubtest.PullRequestRule(1), githubtest.StatusChecksRule("ci"))
	h.collect()
	h.evaluate()
	h.advance(time.Hour)
	m.fixed = h.clock

	h.advance(day)
	m.end = h.clock
	return m
}

// Done-when: a package for a past period contains the earlier fail, the
// exception and the later pass.
func TestReviewPackageHoldsTheFailTheExceptionAndThePass(t *testing.T) {
	h := newHarness(t)
	m := h.history()
	p := h.pack(m.start, m.end)

	evals := decode[[]store.EvaluationRow](t, p, "evaluations.json")
	var sequence []string
	for _, e := range evals {
		if e.CheckKey == "GH-01" {
			sequence = append(sequence, e.Result)
		}
	}
	if strings.Join(sequence, ",") != "fail,pass" {
		t.Errorf("GH-01 evaluations = %v, want the fail then the pass", sequence)
	}

	findings := decode[[]store.FindingRow](t, p, "findings.json")
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (GH-01 and GH-02)", len(findings))
	}
	for _, f := range findings {
		if f.Open() || f.OpeningExplanation == "" || f.ClosingExplanation == nil {
			t.Errorf("finding %+v, want it closed with both evaluations named", f)
		}
	}

	exceptions := decode[[]assurance.PackageException](t, p, "exceptions.json")
	if len(exceptions) != 2 || exceptions[0].StatusAtPeriodEnd != "approved" ||
		exceptions[0].RequestedBy != "control-owner" || exceptions[0].DecidedBy == nil || *exceptions[0].DecidedBy != "reviewer" {
		t.Errorf("exceptions = %+v, want two approved exceptions with requester and approver", exceptions)
	}
	if notes := decode[[]store.NoteRow](t, p, "remediation_notes.json"); len(notes) != 2 {
		t.Errorf("notes = %d, want 2", len(notes))
	}

	actions := map[string]bool{}
	for _, l := range decode[[]store.LogRow](t, p, "decision_log.json") {
		actions[l.Action] = true
	}
	for _, want := range []string{"collection.run", "evaluation.run", "remediation.noted", "exception.requested", "exception.approved"} {
		if !actions[want] {
			t.Errorf("decision log lacks %q (has %v)", want, actions)
		}
	}
	if c, _ := control.Lookup("change-management"); controlState(t, p, "change-management") != c.BestState() {
		t.Errorf("state at period end = %s, want %s", controlState(t, p, "change-management"), c.BestState())
	}

	// The evidence for both evaluations is in the package, under its hash.
	for _, e := range evals {
		if data, ok := p.Files["evidence/"+e.PayloadSHA256]; !ok {
			t.Errorf("evidence %s is missing", e.PayloadSHA256)
		} else if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != e.PayloadSHA256 {
			t.Errorf("evidence %s does not match its hash", e.PayloadSHA256)
		}
	}
	if len(p.Manifest.Scope) != 1 || p.Manifest.Scope[0].ExternalID != githubtest.FakeRepository {
		t.Errorf("scope = %+v", p.Manifest.Scope)
	}
	for path, data := range p.Files {
		if strings.HasSuffix(path, ".json") && strings.Contains(strings.ToLower(string(data)), "compliant") {
			t.Errorf("%s uses the word compliant", path)
		}
	}
}

// A package shows the period as it stood at its end, not as things are now.
func TestReviewPackageIsAsOfThePeriodEnd(t *testing.T) {
	h := newHarness(t)
	m := h.history()

	// Ending after the request, before the approval.
	p := h.pack(m.start, m.requested)
	x := decode[[]assurance.PackageException](t, p, "exceptions.json")
	if len(x) != 2 || x[0].StatusAtPeriodEnd != "requested" || x[0].DecidedBy != nil || x[0].DecidedAt != nil || x[0].DecisionReason != "" {
		t.Errorf("before approval: %+v, want a bare request", x)
	}
	if got := controlState(t, p, "change-management"); got != control.NeedsAttention {
		t.Errorf("before approval: state %s, want needs_attention", got)
	}

	// Ending after the approval, before the fix.
	p = h.pack(m.start, m.approved)
	if x := decode[[]assurance.PackageException](t, p, "exceptions.json"); len(x) != 2 || x[0].StatusAtPeriodEnd != "approved" {
		t.Errorf("after approval: %+v", x)
	}
	if got := controlState(t, p, "change-management"); got != control.AcceptedRisk {
		t.Errorf("after approval: state %s, want accepted_risk", got)
	}
	for _, f := range decode[[]store.FindingRow](t, p, "findings.json") {
		if !f.Open() {
			t.Errorf("finding %d is closed in a period that ended before the fix", f.ID)
		}
	}
	for _, e := range decode[[]store.EvaluationRow](t, p, "evaluations.json") {
		if e.Result == "pass" {
			t.Errorf("a period that ended before the fix holds a pass: %+v", e)
		}
	}

	// A period after the findings closed does not carry them.
	h.advance(2 * day)
	p = h.pack(m.fixed, h.clock)
	if f := decode[[]store.FindingRow](t, p, "findings.json"); len(f) != 0 {
		t.Errorf("a later period holds %d findings that closed before it began", len(f))
	}
	// Nothing was collected in it, so the evidence has aged: stale, with
	// the last result still a pass.
	if got := controlState(t, p, "change-management"); got != control.Stale {
		t.Errorf("three days without evidence: state %s, want stale", got)
	}
}

// Regenerating for the same period yields the same manifest, whatever has
// happened since.
func TestReviewPackageIsTheSameWhenRegenerated(t *testing.T) {
	h := newHarness(t)
	m := h.history()
	first := h.pack(m.start, m.approved)
	ctx := context.Background()

	// Life goes on: more evidence, more decisions, a new check version.
	h.fake.SetRules(false)
	h.collect()
	h.evaluate()
	f := h.findings("GH-01")
	if _, err := h.svc.AddRemediationNote(ctx, h.owner, f[0].ID, "Again."); err != nil {
		t.Fatal(err)
	}
	remove, err := check.Register(stricterGH01)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	h.evaluate()
	h.advance(day)

	second := h.pack(m.start, m.approved)
	if first.ManifestSHA256 != second.ManifestSHA256 {
		t.Errorf("manifest changed from %s to %s", first.ManifestSHA256, second.ManifestSHA256)
	}
	if !maps.EqualFunc(first.Files, second.Files, bytes.Equal) {
		for path := range first.Files {
			if !bytes.Equal(first.Files[path], second.Files[path]) {
				t.Errorf("%s differs:\n%s\n---\n%s", path, first.Files[path], second.Files[path])
			}
		}
	}
	// Each generation is logged, with the manifest hash.
	log, err := h.svc.DecisionLog(ctx, h.auditor)
	if err != nil {
		t.Fatal(err)
	}
	logged := 0
	for _, l := range log {
		if l.Action == "package.generated" && strings.Contains(l.Reason, first.ManifestSHA256) && l.Actor == "auditor" {
			logged++
		}
	}
	if logged != 2 {
		t.Errorf("%d log entries name the manifest, want 2", logged)
	}
}

func TestReviewPackageRefusesAPeriodThatIsNotOver(t *testing.T) {
	h := newHarness(t)
	h.failing()
	ctx := context.Background()
	for name, period := range map[string][2]time.Time{
		"ends in the future":    {h.clock.Add(-day), h.clock.Add(time.Second)},
		"ends before it starts": {h.clock.Add(-day), h.clock.Add(-2 * day)},
		"empty":                 {h.clock.Add(-day), h.clock.Add(-day)},
	} {
		if _, err := h.svc.BuildPackage(ctx, h.auditor, period[0], period[1]); !errors.Is(err, assurance.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	// A period that ends exactly now is over.
	if _, err := h.svc.BuildPackage(ctx, h.auditor, h.clock.Add(-day), h.clock); err != nil {
		t.Errorf("a period ending now: %v", err)
	}
}

func TestVerifyPackage(t *testing.T) {
	h := newHarness(t)
	m := h.history()
	p := h.pack(m.start, m.end)

	// Written to a directory and to a zip, both verify.
	dir := filepath.Join(t.TempDir(), "package")
	if err := p.WriteDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := p.WriteDir(dir); err == nil {
		t.Error("WriteDir wrote into a directory that already held a package")
	}
	zipPath := filepath.Join(t.TempDir(), "package.zip")
	var buf bytes.Buffer
	if err := p.WriteZip(&buf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, zipPath} {
		fsys, err := assurance.OpenPackage(path)
		if err != nil {
			t.Fatal(err)
		}
		v, err := assurance.VerifyPackage(fsys)
		if err != nil {
			t.Fatalf("VerifyPackage(%s): %v", path, err)
		}
		if !v.OK() || v.ManifestSHA256 != p.ManifestSHA256 || v.Evaluations != 4 || v.Reproduced != 4 {
			t.Errorf("%s: %+v, want an intact package with 4 reproduced evaluations", path, v)
		}
	}

	// tampered returns the package's files with one change applied.
	tampered := func(change func(files fstest.MapFS)) *assurance.Verification {
		t.Helper()
		files := fstest.MapFS{}
		for path, data := range p.Files {
			files[path] = &fstest.MapFile{Data: bytes.Clone(data)}
		}
		change(files)
		v, err := assurance.VerifyPackage(files)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	// relist makes the manifest agree with a file that was changed.
	relist := func(files fstest.MapFS, path string) {
		var manifest assurance.Manifest
		if err := json.Unmarshal(files["manifest.json"].Data, &manifest); err != nil {
			t.Fatal(err)
		}
		for i, f := range manifest.Files {
			if f.Path == path {
				sum := sha256.Sum256(files[path].Data)
				manifest.Files[i].SHA256, manifest.Files[i].Size = hex.EncodeToString(sum[:]), int64(len(files[path].Data))
			}
		}
		files["manifest.json"].Data, _ = json.Marshal(manifest)
	}
	var anEvidenceFile string
	for path := range p.Files {
		if strings.HasPrefix(path, "evidence/") {
			anEvidenceFile = path
		}
	}

	tests := []struct {
		name   string
		change func(files fstest.MapFS)
		want   string
	}{
		{"a result edited", func(f fstest.MapFS) {
			f["evaluations.json"].Data = bytes.Replace(f["evaluations.json"].Data, []byte(`"Result": "fail"`), []byte(`"Result": "pass"`), 1)
		}, "evaluations.json: content does not match the manifest"},
		{"a result edited and the manifest made to agree", func(f fstest.MapFS) {
			f["evaluations.json"].Data = bytes.Replace(f["evaluations.json"].Data, []byte(`"Result": "fail"`), []byte(`"Result": "pass"`), 1)
			relist(f, "evaluations.json")
		}, "recorded pass, reproduced fail"},
		{"evidence edited", func(f fstest.MapFS) {
			f[anEvidenceFile].Data = append(f[anEvidenceFile].Data, ' ')
		}, "content does not match the manifest"},
		{"evidence edited and the manifest made to agree", func(f fstest.MapFS) {
			f[anEvidenceFile].Data = append(f[anEvidenceFile].Data, ' ')
			relist(f, anEvidenceFile)
		}, "not filed under the hash of its bytes"},
		{"a file removed", func(f fstest.MapFS) { delete(f, "decision_log.json") }, "decision_log.json: listed in the manifest but missing"},
		{"a file added", func(f fstest.MapFS) { f["evidence/extra"] = &fstest.MapFile{Data: []byte("x")} }, "evidence/extra: present but not listed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := tampered(tt.change)
			if v.OK() || !strings.Contains(strings.Join(v.Problems, "\n"), tt.want) {
				t.Errorf("problems = %q, want one containing %q", v.Problems, tt.want)
			}
		})
	}
}

// stricterGH01 is a second version of GH-01, for tests: it asks for two
// approving reviews where version 1 asks for one.
var stricterGH01 = check.Check{
	Key: "GH-01", Version: "2", ObservationKind: github.BranchRulesKind,
	Assertion: "An active rule on the default branch requires at least two approving reviews.",
	Source:    "synthetic", Permission: "synthetic",
	Establishes:      "The rule was active on that branch at collection time.",
	DoesNotEstablish: "That past changes were reviewed.",
	Control:          "Change management", Mapping: "synthetic",
	Eval: func(in check.Input) (check.Result, string, error) {
		var b github.BranchRules
		if err := json.Unmarshal(in.Payload, &b); err != nil {
			return "", "", err
		}
		for _, r := range b.Rules {
			var p struct {
				Approvals int `json:"required_approving_review_count"`
			}
			if r.Type == "pull_request" && json.Unmarshal(r.Parameters, &p) == nil && p.Approvals >= 2 {
				return check.Pass, "Two approving reviews are required.", nil
			}
		}
		return check.Fail, "No active rule requires two approving reviews.", nil
	},
}

// Done-when: every stored evaluation reproduces. A new check version adds
// evaluations beside the old ones and rewrites none.
func TestNewCheckVersionAddsEvaluationsAndOldOnesStillReproduce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.fake.SetRules(true, githubtest.PullRequestRule(1), githubtest.StatusChecksRule("ci"))
	h.collect()
	h.evaluate()
	h.advance(time.Hour)
	h.collect()
	h.evaluate()
	before, err := h.st.AllEvaluations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 4 || h.result("GH-01").Result != "pass" {
		t.Fatalf("setup: %d evaluations, GH-01 %s", len(before), h.result("GH-01").Result)
	}

	remove, err := check.Register(stricterGH01)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := check.Register(stricterGH01); err == nil {
		t.Error("the same version was registered twice")
	}

	// Version 2 is applied to both stored observations: two new rows.
	h.advance(time.Hour)
	added := h.evaluate()
	if len(added) != 2 {
		t.Fatalf("version 2 added %d evaluations, want 2", len(added))
	}
	for _, e := range added {
		if e.CheckVersion != "2" || e.Result != check.Fail || e.Finding != store.FindingUnchanged {
			t.Errorf("added %+v, want a version 2 fail that moves no finding", e)
		}
	}
	after, err := h.st.AllEvaluations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range before {
		if after[i] != e {
			t.Errorf("evaluation %d was rewritten:\n before %+v\n after  %+v", e.EvaluationID, e, after[i])
		}
	}
	// The current result is the newest version's, on the same evidence.
	if r := h.result("GH-01"); r.Result != "fail" || r.CheckVersion != "2" {
		t.Errorf("GH-01 = %s under version %s, want fail under version 2", r.Result, r.CheckVersion)
	}
	// Re-evaluating old evidence opened no finding; new evidence does.
	if n := len(h.findings("GH-01")); n != 0 {
		t.Errorf("re-evaluating stored evidence opened %d findings", n)
	}
	h.collect()
	for _, e := range h.evaluate() {
		if e.CheckKey == "GH-01" && (e.CheckVersion != "2" || e.Finding != store.FindingOpened) {
			t.Errorf("new evidence: %+v, want version 2 only, opening a finding", e)
		}
	}

	// Every stored evaluation reproduces, under the version that made it.
	r, err := h.svc.Reproduce(ctx, h.auditor)
	if err != nil {
		t.Fatal(err)
	}
	if r.Evaluations != 8 || r.Reproduced != 8 || len(r.Mismatches) != 0 {
		t.Errorf("reproduction = %+v, want all 8", r)
	}

	// A build without version 2 says so, rather than passing silently.
	remove()
	r, err = h.svc.Reproduce(ctx, h.auditor)
	if err != nil {
		t.Fatal(err)
	}
	if r.Reproduced != 5 || len(r.Mismatches) != 3 || !strings.Contains(r.Mismatches[0], "does not have that check version") {
		t.Errorf("without version 2: %+v, want 3 evaluations reported", r)
	}
}

// swappedStore serves different bytes for every payload.
type swappedStore struct{}

func (swappedStore) Put(context.Context, []byte) (string, string, error) {
	return "", "", errors.New("synthetic: read-only")
}
func (swappedStore) Get(context.Context, string) ([]byte, error) {
	return []byte(`{"repository":"lab-org/lab-repo","default_branch":"main","branch_protected":true,"rules_complete":true,"rules":[]}`), nil
}

func TestReproduceReportsEvidenceThatChanged(t *testing.T) {
	h := newHarness(t)
	h.healthy()
	h.collectEverything()
	h.evaluate()
	h.unhealthy()
	h.advance(time.Hour)
	h.collectEverything()
	h.evaluate()
	ctx := context.Background()

	r, err := h.svc.Reproduce(ctx, h.auditor)
	if err != nil {
		t.Fatal(err)
	}
	if r.Evaluations != 16 || r.Reproduced != 16 {
		t.Fatalf("reproduction = %+v, want all 16", r)
	}

	h.svc.Evidence = swappedStore{}
	r, err = h.svc.Reproduce(ctx, h.auditor)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Mismatches) == 0 || r.Reproduced == r.Evaluations {
		t.Errorf("swapped evidence went unnoticed: %+v", r)
	}
}

// Loading the content records each control's wording once, and the review
// package names the wording that was in force at the end of its period.
func TestControlRevisionsAreRecordedAndNamedInThePackage(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Only an operator may load content.
	if _, err := h.svc.LoadContent(ctx, h.auditor); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("an auditor loading content: err = %v, want denied", err)
	}

	// A package for a period before any wording was recorded says so.
	start := h.clock
	h.collect()
	h.advance(time.Hour)
	early := h.clock
	h.advance(time.Hour)
	before := h.pack(start, early)
	for _, c := range decode[[]assurance.PackageControl](t, before, "controls.json") {
		if c.RevisionAtPeriodEnd != nil || !c.WordingChangedSince {
			t.Errorf("%s: revision at period end = %+v, changed since = %v; want none on record", c.Key, c.RevisionAtPeriodEnd, c.WordingChangedSince)
		}
		if c.Statement == "" || c.ReviewLabel == "" || len(c.ContentSHA256) != 64 {
			t.Errorf("%s: statement %q, review %q, hash %q", c.Key, c.Statement, c.ReviewLabel, c.ContentSHA256)
		}
	}

	results, err := h.svc.LoadContent(ctx, h.operator)
	if err != nil {
		t.Fatalf("LoadContent: %v", err)
	}
	if len(results) != len(control.All) {
		t.Fatalf("loaded %d controls, want %d", len(results), len(control.All))
	}
	for _, r := range results {
		if !r.Recorded {
			t.Errorf("%s: the first load recorded nothing", r.Key)
		}
	}
	loadedAt := h.clock

	// Loading the same content again adds nothing.
	h.advance(time.Hour)
	results, err = h.svc.LoadContent(ctx, h.operator)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Recorded {
			t.Errorf("%s: loading unchanged content recorded a new revision", r.Key)
		}
	}
	revisions, err := h.st.ControlRevisions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(revisions) != len(control.All) {
		t.Errorf("%d revisions on record, want %d", len(revisions), len(control.All))
	}

	// A package whose period ends after the load names that revision.
	h.advance(time.Hour)
	end := h.clock
	h.advance(time.Hour)
	after := h.pack(start, end)
	for _, c := range decode[[]assurance.PackageControl](t, after, "controls.json") {
		rev := c.RevisionAtPeriodEnd
		if rev == nil || rev.ContentSHA256 != c.ContentSHA256 || !rev.LoadedAt.Equal(loadedAt) || c.WordingChangedSince {
			t.Errorf("%s: revision at period end = %+v, changed since = %v", c.Key, rev, c.WordingChangedSince)
		}
	}
	if got := decode[[]store.ControlRevision](t, after, "control_revisions.json"); len(got) != len(control.All) {
		t.Errorf("control_revisions.json holds %d revisions, want %d", len(got), len(control.All))
	}
	// The reading copy labels every control and mapping as reviewed or not.
	page := string(after.Files["index.html"])
	if n := strings.Count(page, "draft, not reviewed") + strings.Count(page, "reviewed by "); n < len(control.All) {
		t.Errorf("index.html carries %d review labels for %d controls", n, len(control.All))
	}

	// Revisions are history: they cannot be changed or removed.
	conn := h.rawConn()
	if _, err := conn.Exec(ctx, `UPDATE control_revisions SET review_status = 'reviewed', reviewed_by = 'x'`); err == nil {
		t.Error("a control revision was updated")
	}
	if _, err := conn.Exec(ctx, `DELETE FROM control_revisions`); err == nil {
		t.Error("a control revision was deleted")
	}
}
