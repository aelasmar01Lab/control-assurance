package assurance_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/auth"
	"github.com/aelasmar01Lab/control-assurance/internal/authz"
	"github.com/aelasmar01Lab/control-assurance/internal/control"
	"github.com/aelasmar01Lab/control-assurance/internal/github/githubtest"
	"github.com/aelasmar01Lab/control-assurance/internal/pack"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
	"github.com/aelasmar01Lab/control-assurance/packs"
)

const day = 24 * time.Hour

// state returns a control's derived state and reasons.
func (h *harness) state(key string) (control.State, string) {
	h.t.Helper()
	ov, err := h.svc.Overview(context.Background(), h.auditor)
	if err != nil {
		h.t.Fatalf("Overview: %v", err)
	}
	for _, c := range ov.Controls {
		if c.Control.Key == key {
			return c.State, strings.Join(c.Reasons, " ")
		}
	}
	h.t.Fatalf("control %s not in overview", key)
	return "", ""
}

func (h *harness) wantState(key string, want control.State) {
	h.t.Helper()
	if got, why := h.state(key); got != want {
		h.t.Fatalf("%s state = %s, want %s (%s)", key, got, want, why)
	}
}

// failing puts GH-01 and GH-02 into a failing state and returns the open
// GH-01 finding.
func (h *harness) failing() store.FindingRow {
	h.t.Helper()
	h.fake.SetRules(false)
	h.collect()
	h.evaluate()
	fs := h.findings("GH-01")
	if len(fs) != 1 || !fs[0].Open() {
		h.t.Fatalf("setup: findings = %+v, want one open GH-01 finding", fs)
	}
	return fs[0]
}

func (h *harness) logCount() int {
	h.t.Helper()
	rows, err := h.st.DecisionLog(context.Background(), 10000)
	if err != nil {
		h.t.Fatal(err)
	}
	return len(rows)
}

// secondReviewer adds another reviewer account.
func (h *harness) secondReviewer() authz.Actor {
	h.t.Helper()
	ctx := context.Background()
	hash, err := auth.HashPassword("another-reviewer-password")
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.st.CreateUser(ctx, "reviewer-two", "Second reviewer", string(authz.Reviewer), hash); err != nil {
		h.t.Fatal(err)
	}
	a, err := h.svc.ActorByUsername(ctx, "reviewer-two")
	if err != nil {
		h.t.Fatal(err)
	}
	return a
}

func (h *harness) upload() assurance.EvidenceUpload {
	return assurance.EvidenceUpload{
		ControlKey:  "backup-recovery",
		PeriodStart: h.clock.Add(-10 * day),
		PeriodEnd:   h.clock.Add(-9 * day),
		Filename:    "../../recovery exercise 2026.txt",
		Note:        "Synthetic test record.",
		Data:        []byte("Synthetic recovery exercise record. Restore completed."),
	}
}

// Done-when: a requester cannot approve their own exception.
func TestRequesterCannotApproveOwnException(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.failing()

	id, err := h.svc.RequestException(ctx, h.reviewer, f.ID, "Ruleset is being migrated.", h.clock.Add(7*day))
	if err != nil {
		t.Fatalf("RequestException: %v", err)
	}

	// The service refuses.
	if err := h.svc.DecideException(ctx, h.reviewer, id, true, "Approving my own request."); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("self-approval: err = %v, want permission denied", err)
	}
	h.wantState("change-management", control.NeedsAttention)

	// The database refuses too, for anything that bypasses the service.
	_, err = h.st.Pool().Exec(ctx, `
		UPDATE exceptions SET status = 'approved', decided_by = requested_by, decided_at = now(), decision_reason = 'bypass'
		WHERE id = $1`, id)
	if err == nil || !strings.Contains(err.Error(), "exception_approver_is_not_requester") {
		t.Fatalf("direct self-approval: err = %v, want the separation-of-duties constraint", err)
	}

	// A different reviewer can approve it.
	if err := h.svc.DecideException(ctx, h.secondReviewer(), id, true, "Risk accepted for one week."); err != nil {
		t.Fatalf("approval by another reviewer: %v", err)
	}
	h.wantState("change-management", control.NeedsAttention) // GH-02 still fails uncovered
}

// Done-when: an expired exception returns the control to needs attention
// without touching any evaluation.
func TestExpiredExceptionReturnsControlToNeedsAttention(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.failing()

	// Cover both failing checks until a week from now.
	expiry := h.clock.Add(7 * day)
	for _, key := range []string{"GH-01", "GH-02"} {
		f := h.findings(key)[0]
		id, err := h.svc.RequestException(ctx, h.owner, f.ID, "Ruleset migration in progress.", expiry)
		if err != nil {
			t.Fatalf("RequestException(%s): %v", key, err)
		}
		if err := h.svc.DecideException(ctx, h.reviewer, id, true, "Accepted for the migration window."); err != nil {
			t.Fatalf("DecideException(%s): %v", key, err)
		}
	}
	h.wantState("change-management", control.AcceptedRisk)

	before, err := h.st.Evaluations(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	beforeResult := h.result("GH-01")

	// Keep the evidence fresh while time passes, so staleness is not what
	// changes the state. The branch still fails each time.
	for i := 0; i < 4; i++ {
		h.advance(40 * time.Hour)
		h.collect()
		h.evaluate()
	}
	if !h.clock.Before(expiry) {
		t.Fatal("test setup: the exception should not have expired yet")
	}
	h.wantState("change-management", control.AcceptedRisk)
	afterCollections, err := h.st.Evaluations(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}

	// The expiry passes. Nothing runs, nothing is written.
	h.advance(expiry.Sub(h.clock) + time.Minute)
	logBefore := h.logCount()
	state, why := h.state("change-management")
	if state != control.NeedsAttention {
		t.Fatalf("state after expiry = %s, want needs_attention (%s)", state, why)
	}
	if !strings.Contains(why, "exception expired") {
		t.Errorf("reasons = %q, want them to say the exception expired", why)
	}

	// No evaluation was added, changed or removed by the expiry.
	after, err := h.st.Evaluations(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(afterCollections) {
		t.Errorf("evaluations went from %d to %d across the expiry", len(afterCollections), len(after))
	}
	byID := map[int64]store.EvaluationRow{}
	for _, e := range after {
		byID[e.EvaluationID] = e
	}
	for _, e := range before {
		if byID[e.EvaluationID] != e {
			t.Errorf("evaluation %d changed: was %+v, now %+v", e.EvaluationID, e, byID[e.EvaluationID])
		}
	}
	if got := h.result("GH-01"); got.Result != beforeResult.Result {
		t.Errorf("GH-01 result changed from %s to %s", beforeResult.Result, got.Result)
	}
	if h.logCount() != logBefore {
		t.Error("reading the state after expiry wrote to the decision log")
	}

	// The exception row itself is untouched; it only reads as expired.
	xs, err := h.st.Exceptions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range xs {
		if x.Status != "approved" || x.DisplayStatus(h.clock) != "expired" {
			t.Errorf("exception %d: stored %s, displayed %s; want approved, expired", x.ID, x.Status, x.DisplayStatus(h.clock))
		}
	}
}

// Done-when: the auditor can read and export, and every write is denied.
func TestAuditorReadsAndExportsButNeverWrites(t *testing.T) {
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

	// Reads.
	if _, err := h.svc.Overview(ctx, h.auditor); err != nil {
		t.Errorf("Overview: %v", err)
	}
	if _, err := h.svc.Findings(ctx, h.auditor); err != nil {
		t.Errorf("Findings: %v", err)
	}
	if _, err := h.svc.ManualEvidence(ctx, h.auditor); err != nil {
		t.Errorf("ManualEvidence: %v", err)
	}
	if _, _, err := h.svc.EvidenceFile(ctx, h.auditor, sid); err != nil {
		t.Errorf("EvidenceFile: %v", err)
	}
	if _, err := h.svc.DecisionLog(ctx, h.auditor); err != nil {
		t.Errorf("DecisionLog: %v", err)
	}

	// Every write is denied, and leaves no trace.
	logBefore := h.logCount()
	writes := map[string]func() error{
		"collect":         func() error { _, err := h.svc.RequestCollection(ctx, h.auditor, "github", h.repos, nil); return err },
		"evaluate":        func() error { _, err := h.svc.Evaluate(ctx, h.auditor); return err },
		"load catalog":    func() error { _, err := h.svc.LoadCatalog(ctx, h.auditor, all); return err },
		"submit evidence": func() error { _, err := h.svc.SubmitEvidence(ctx, h.auditor, h.upload()); return err },
		"review evidence": func() error { return h.svc.ReviewEvidence(ctx, h.auditor, sid, true, "ok") },
		"request exception": func() error {
			_, err := h.svc.RequestException(ctx, h.auditor, f.ID, "x", h.clock.Add(day))
			return err
		},
		"decide exception": func() error { return h.svc.DecideException(ctx, h.auditor, xid, true, "ok") },
		"remediation note": func() error { _, err := h.svc.AddRemediationNote(ctx, h.auditor, f.ID, "note"); return err },
	}
	for name, write := range writes {
		if err := write(); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("auditor %s: err = %v, want permission denied", name, err)
		}
	}
	if got := h.logCount(); got != logBefore {
		t.Errorf("denied writes added %d decision log entries", got-logBefore)
	}

	// Export is allowed, complete, and itself logged.
	exp, err := h.svc.Export(ctx, h.auditor)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if exp.GeneratedBy != "auditor" || len(exp.Controls) != len(control.All) || len(exp.Findings) != 2 ||
		len(exp.Exceptions) != 1 || len(exp.Submissions) != 1 || len(exp.Evaluations) != 2 {
		t.Errorf("export is incomplete: %d controls, %d findings, %d exceptions, %d submissions, %d evaluations",
			len(exp.Controls), len(exp.Findings), len(exp.Exceptions), len(exp.Submissions), len(exp.Evaluations))
	}
	log, err := h.st.DecisionLog(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(log) != 1 || log[0].Action != "export.generated" || log[0].Actor != "auditor" {
		t.Errorf("newest log entry = %+v, want the auditor's export", log)
	}
}

// Every action in the permission matrix is exercised through the service,
// for every role, including the export and job paths. Each has at least one
// role that is allowed and one that is denied.
func TestServiceEnforcesTheMatrix(t *testing.T) {
	all, err := pack.LoadFS(packs.FS)
	if err != nil {
		t.Fatal(err)
	}
	// attempt performs the action as actor in a fresh harness and returns its error.
	attempts := map[authz.Action]func(h *harness, a authz.Actor) error{
		authz.View: func(h *harness, a authz.Actor) error {
			_, err := h.svc.Overview(context.Background(), a)
			return err
		},
		authz.Export: func(h *harness, a authz.Actor) error {
			_, err := h.svc.Export(context.Background(), a)
			return err
		},
		authz.RunCollection: func(h *harness, a authz.Actor) error {
			// Every way of starting collection is one action.
			ctx := context.Background()
			_, errRequest := h.svc.RequestCollection(ctx, a, "github", h.repos, nil)
			_, errAll := h.svc.RequestAll(ctx, a)
			_, errDue := h.svc.ScheduleDue(ctx, a, time.Hour)
			_, errWork := h.svc.Work(ctx, a, 1)
			if (errRequest == nil) != (errAll == nil) || (errAll == nil) != (errDue == nil) || (errDue == nil) != (errWork == nil) {
				return fmt.Errorf("collection entry points disagree: %w", errors.Join(errRequest, errAll, errDue, errWork, errors.New("some allowed, some denied")))
			}
			return errRequest
		},
		authz.RunEvaluation: func(h *harness, a authz.Actor) error {
			_, err := h.svc.Evaluate(context.Background(), a)
			return err
		},
		authz.LoadCatalog: func(h *harness, a authz.Actor) error {
			_, err := h.svc.LoadCatalog(context.Background(), a, all)
			return err
		},
		authz.SubmitEvidence: func(h *harness, a authz.Actor) error {
			_, err := h.svc.SubmitEvidence(context.Background(), a, h.upload())
			return err
		},
		authz.ReviewEvidence: func(h *harness, a authz.Actor) error {
			id, err := h.svc.SubmitEvidence(context.Background(), h.owner, h.upload())
			if err != nil {
				h.t.Fatal(err)
			}
			return h.svc.ReviewEvidence(context.Background(), a, id, true, "Record is dated and complete.")
		},
		authz.RequestException: func(h *harness, a authz.Actor) error {
			f := h.failing()
			_, err := h.svc.RequestException(context.Background(), a, f.ID, "Migration window.", h.clock.Add(day))
			return err
		},
		authz.DecideException: func(h *harness, a authz.Actor) error {
			f := h.failing()
			id, err := h.svc.RequestException(context.Background(), h.owner, f.ID, "Migration window.", h.clock.Add(day))
			if err != nil {
				h.t.Fatal(err)
			}
			return h.svc.DecideException(context.Background(), a, id, true, "Accepted.")
		},
		authz.AddRemediationNote: func(h *harness, a authz.Actor) error {
			f := h.failing()
			_, err := h.svc.AddRemediationNote(context.Background(), a, f.ID, "Ruleset re-enabled in staging.")
			return err
		},
	}
	if len(attempts) != len(authz.Actions) {
		t.Fatalf("%d actions have a service test, but %d are defined", len(attempts), len(authz.Actions))
	}

	for _, action := range authz.Actions {
		allowed, denied := 0, 0
		for _, role := range authz.Roles {
			t.Run(string(action)+" as "+string(role), func(t *testing.T) {
				h := newHarness(t)
				actor := map[authz.Role]authz.Actor{
					authz.Operator: h.operator, authz.ControlOwner: h.owner,
					authz.Reviewer: h.reviewer, authz.Auditor: h.auditor,
				}[role]
				err := attempts[action](h, actor)
				if authz.RoleMay(role, action) {
					allowed++
					if err != nil {
						t.Errorf("allowed by the matrix but the service returned: %v", err)
					}
				} else {
					denied++
					if !errors.Is(err, authz.ErrDenied) {
						t.Errorf("denied by the matrix but the service returned: %v", err)
					}
				}
			})
		}
		if allowed == 0 {
			t.Errorf("%s: no allow test ran", action)
		}
		if denied == 0 && action != authz.View && action != authz.Export {
			t.Errorf("%s: no deny test ran", action)
		}
	}
}

func TestManualEvidenceReview(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.wantState("backup-recovery", control.NeedsAttention) // nothing submitted

	up := h.upload()
	id, err := h.svc.SubmitEvidence(ctx, h.owner, up)
	if err != nil {
		t.Fatalf("SubmitEvidence: %v", err)
	}
	h.wantState("backup-recovery", control.NeedsAttention) // submitted is not accepted

	// The stored file is retrievable and its name was made safe.
	data, name, err := h.svc.EvidenceFile(ctx, h.reviewer, id)
	if err != nil || string(data) != string(up.Data) {
		t.Fatalf("EvidenceFile = %q, %v", data, err)
	}
	if strings.ContainsAny(name, "/ ") || name != "recovery_exercise_2026.txt" {
		t.Errorf("stored filename = %q", name)
	}

	// The database refuses a review by the submitter, whatever their role.
	_, err = h.st.Pool().Exec(ctx, `
		UPDATE evidence_submissions
		SET review_status = 'accepted', reviewed_by = submitted_by, reviewed_at = now(), valid_until = now()
		WHERE id = $1`, id)
	if err == nil || !strings.Contains(err.Error(), "evidence_reviewer_is_not_submitter") {
		t.Fatalf("self-review: err = %v, want the separation-of-duties constraint", err)
	}

	// Rejection needs a reason.
	if err := h.svc.ReviewEvidence(ctx, h.reviewer, id, false, "  "); !errors.Is(err, assurance.ErrInvalid) {
		t.Errorf("rejection without a reason: err = %v", err)
	}

	if err := h.svc.ReviewEvidence(ctx, h.reviewer, id, true, "Dated record, restore verified."); err != nil {
		t.Fatalf("ReviewEvidence: %v", err)
	}
	h.wantState("backup-recovery", control.Supported)

	// A review happens once.
	if err := h.svc.ReviewEvidence(ctx, h.reviewer, id, false, "Changed my mind."); !errors.Is(err, assurance.ErrInvalid) {
		t.Errorf("second review: err = %v, want invalid", err)
	}

	// Valid for 12 months from the end of the period covered.
	sub, err := h.st.SubmissionByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	wantUntil := up.PeriodEnd.AddDate(1, 0, 0).Format("2006-01-02")
	if sub.ValidUntil == nil || sub.ValidUntil.Format("2006-01-02") != wantUntil {
		t.Errorf("valid until = %v, want %s", sub.ValidUntil, wantUntil)
	}

	// A year on, the same record no longer counts.
	h.advance(366 * day)
	h.wantState("backup-recovery", control.Stale)

	// A rejected newer submission then needs attention.
	up2 := h.upload()
	id2, err := h.svc.SubmitEvidence(ctx, h.owner, up2)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.ReviewEvidence(ctx, h.reviewer, id2, false, "Record is undated."); err != nil {
		t.Fatal(err)
	}
	h.wantState("backup-recovery", control.NeedsAttention)
}

func TestInvalidRequestsAreRefused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	f := h.failing()

	requests := map[string]func() error{
		"no justification": func() error {
			_, err := h.svc.RequestException(ctx, h.owner, f.ID, "   ", h.clock.Add(day))
			return err
		},
		"no expiry": func() error {
			_, err := h.svc.RequestException(ctx, h.owner, f.ID, "Reason.", time.Time{})
			return err
		},
		"expiry in the past": func() error {
			_, err := h.svc.RequestException(ctx, h.owner, f.ID, "Reason.", h.clock.Add(-time.Hour))
			return err
		},
		"expiry too far out": func() error {
			_, err := h.svc.RequestException(ctx, h.owner, f.ID, "Reason.", h.clock.Add(181*day))
			return err
		},
		"unknown finding": func() error {
			_, err := h.svc.RequestException(ctx, h.operator, 99999, "Reason.", h.clock.Add(day))
			return err
		},
		"empty note": func() error {
			_, err := h.svc.AddRemediationNote(ctx, h.owner, f.ID, "")
			return err
		},
		"evidence for an automated control": func() error {
			up := h.upload()
			up.ControlKey = "change-management"
			_, err := h.svc.SubmitEvidence(ctx, h.operator, up)
			return err
		},
		"evidence with no file": func() error {
			up := h.upload()
			up.Data = nil
			_, err := h.svc.SubmitEvidence(ctx, h.owner, up)
			return err
		},
		"evidence for a future period": func() error {
			up := h.upload()
			up.PeriodEnd = h.clock.Add(day)
			_, err := h.svc.SubmitEvidence(ctx, h.owner, up)
			return err
		},
	}
	for name, request := range requests {
		if err := request(); !errors.Is(err, assurance.ErrInvalid) {
			t.Errorf("%s: err = %v, want invalid", name, err)
		}
	}

	// Only one undecided request per finding.
	if _, err := h.svc.RequestException(ctx, h.owner, f.ID, "First.", h.clock.Add(day)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.RequestException(ctx, h.operator, f.ID, "Second.", h.clock.Add(day)); !errors.Is(err, assurance.ErrInvalid) {
		t.Errorf("second pending request: err = %v, want invalid", err)
	}

	// No exception on a closed finding.
	h.fake.SetRules(true, githubtest.PullRequestRule(1), githubtest.StatusChecksRule("ci"))
	h.collect()
	h.evaluate()
	if _, err := h.svc.RequestException(ctx, h.operator, f.ID, "Late.", h.clock.Add(day)); !errors.Is(err, assurance.ErrInvalid) {
		t.Errorf("exception on a closed finding: err = %v, want invalid", err)
	}
}

// The ten-step loop: a failing check becomes a finding, an approved
// exception, a fix and a verified pass, with every earlier step still visible.
func TestFullLoopKeepsEveryStep(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.fake.SetRules(true, githubtest.PullRequestRule(1), githubtest.StatusChecksRule("ci"))
	h.collect()
	h.evaluate()
	h.wantState("change-management", control.Supported) // 1. passing

	h.fake.SetRules(true, githubtest.StatusChecksRule("ci")) // 2. the review rule is removed
	h.collect()
	h.evaluate() // 3. fail, 4. finding
	h.wantState("change-management", control.NeedsAttention)
	f := h.findings("GH-01")[0]

	if _, err := h.svc.AddRemediationNote(ctx, h.owner, f.ID, "Review rule removed during ruleset migration; restoring by Friday."); err != nil {
		t.Fatal(err) // 5. remediation note
	}
	xid, err := h.svc.RequestException(ctx, h.owner, f.ID, "Migration window.", h.clock.Add(3*day))
	if err != nil {
		t.Fatal(err) // 6. exception requested
	}
	h.wantState("change-management", control.NeedsAttention) // a request alone changes nothing
	if err := h.svc.DecideException(ctx, h.reviewer, xid, true, "Accepted for three days."); err != nil {
		t.Fatal(err) // 7. approved by someone else
	}
	h.wantState("change-management", control.AcceptedRisk)

	h.advance(day)
	h.fake.SetRules(true, githubtest.PullRequestRule(1), githubtest.StatusChecksRule("ci")) // 8. fix
	h.collect()
	h.evaluate() // 9. verified pass closes the finding
	h.wantState("change-management", control.Supported)

	// 10. Every earlier step is still there.
	views, err := h.svc.Findings(ctx, h.auditor)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 {
		t.Fatalf("findings = %d, want 1", len(views))
	}
	v := views[0]
	if v.Open() || len(v.Notes) != 1 || len(v.Exceptions) != 1 || v.Exceptions[0].Status != "approved" {
		t.Errorf("finding history incomplete: open=%v notes=%d exceptions=%+v", v.Open(), len(v.Notes), v.Exceptions)
	}
	if n := h.evaluationCount("GH-01"); n != 3 {
		t.Errorf("GH-01 evaluations = %d, want 3 (pass, fail, pass)", n)
	}
	log, err := h.svc.DecisionLog(ctx, h.auditor)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for i := len(log) - 1; i >= 0; i-- {
		actions = append(actions, log[i].Action)
	}
	got := strings.Join(actions, " ")
	for _, want := range []string{"collection.run", "evaluation.run", "remediation.noted", "exception.requested", "exception.approved"} {
		if !strings.Contains(got, want) {
			t.Errorf("decision log %q is missing %s", got, want)
		}
	}
	if strings.Index(got, "exception.requested") > strings.Index(got, "exception.approved") {
		t.Errorf("decision log is out of order: %s", got)
	}
}

func TestAuthenticate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	password, err := h.svc.ResetPassword(ctx, "auditor")
	if err != nil {
		t.Fatal(err)
	}
	a, err := h.svc.Authenticate(ctx, "auditor", password)
	if err != nil || a.Role != authz.Auditor || a.UserID == 0 {
		t.Fatalf("Authenticate = %+v, %v", a, err)
	}
	for name, creds := range map[string][2]string{
		"wrong password":   {"auditor", password + "x"},
		"unknown user":     {"nobody", password},
		"empty password":   {"auditor", ""},
		"another's secret": {"operator", password},
	} {
		if _, err := h.svc.Authenticate(ctx, creds[0], creds[1]); !errors.Is(err, assurance.ErrBadCredentials) {
			t.Errorf("%s: err = %v, want bad credentials", name, err)
		}
	}
	// Seeding again creates nothing and reveals nothing.
	again, err := h.svc.SeedLabUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range again {
		if u.Password != "" {
			t.Errorf("re-seeding returned a password for %s", u.Username)
		}
	}
}
