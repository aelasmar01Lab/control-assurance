package assurance

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/auth"
	"github.com/aelasmar01Lab/control-assurance/internal/authz"
	"github.com/aelasmar01Lab/control-assurance/internal/check"
	"github.com/aelasmar01Lab/control-assurance/internal/control"
	"github.com/aelasmar01Lab/control-assurance/internal/pack"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
)

// ErrInvalid marks a request that was permitted but cannot be carried out as
// asked, such as a missing justification.
var ErrInvalid = errors.New("invalid request")

// ErrBadCredentials is returned for any failed sign-in, whatever the cause.
var ErrBadCredentials = errors.New("username or password is incorrect")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

const (
	// MaxEvidenceBytes is the largest manual evidence file accepted.
	MaxEvidenceBytes = 10 << 20
	// MaxExceptionDays is the longest an exception may run. A policy choice
	// of this project, not a framework figure.
	MaxExceptionDays = 180
	maxTextLen       = 4000
)

// --- accounts ---------------------------------------------------------------

func actorOf(u store.User) authz.Actor {
	return authz.Actor{UserID: u.ID, Username: u.Username, Role: authz.Role(u.Role)}
}

// dummyHash is verified when the username is unknown, so a failed sign-in
// costs the same whether or not the account exists.
var dummyHash, _ = auth.HashPassword("no-such-account-placeholder")

// Authenticate checks a username and password and returns the actor.
func (s *Service) Authenticate(ctx context.Context, username, password string) (authz.Actor, error) {
	u, err := s.Store.UserByUsername(ctx, strings.TrimSpace(username))
	if errors.Is(err, store.ErrNotFound) {
		_, _ = auth.VerifyPassword(dummyHash, password)
		return authz.Actor{}, ErrBadCredentials
	}
	if err != nil {
		return authz.Actor{}, err
	}
	ok, err := auth.VerifyPassword(u.PasswordHash, password)
	if err != nil || !ok {
		return authz.Actor{}, ErrBadCredentials
	}
	return actorOf(u), nil
}

// ActorByID returns the actor for a signed-in session.
func (s *Service) ActorByID(ctx context.Context, id int64) (authz.Actor, error) {
	u, err := s.Store.UserByID(ctx, id)
	if err != nil {
		return authz.Actor{}, err
	}
	return actorOf(u), nil
}

// ActorByUsername returns the actor a CLI invocation runs as. The CLI
// authenticates nobody: whoever can run it already holds the database
// credentials. The username decides which permissions apply and whose name
// is logged.
func (s *Service) ActorByUsername(ctx context.Context, username string) (authz.Actor, error) {
	u, err := s.Store.UserByUsername(ctx, username)
	if err != nil {
		return authz.Actor{}, err
	}
	return actorOf(u), nil
}

// LabUser is a seeded account and, when it was just created, its password.
type LabUser struct {
	Username string
	Role     authz.Role
	Password string // empty when the account already existed
}

var labUsers = []struct {
	username, display string
	role              authz.Role
}{
	{"operator", "Lab operator", authz.Operator},
	{"control-owner", "Lab control owner", authz.ControlOwner},
	{"reviewer", "Lab reviewer", authz.Reviewer},
	{"auditor", "Lab auditor", authz.Auditor},
}

// SeedLabUsers creates the four lab accounts that do not exist yet, each
// with a generated password that is returned once and never stored.
// It is a setup step, like applying migrations, and takes no actor.
func (s *Service) SeedLabUsers(ctx context.Context) ([]LabUser, error) {
	var out []LabUser
	for _, lu := range labUsers {
		if _, err := s.Store.UserByUsername(ctx, lu.username); err == nil {
			out = append(out, LabUser{Username: lu.username, Role: lu.role})
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			return out, err
		}
		password, err := auth.GeneratePassword()
		if err != nil {
			return out, err
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			return out, err
		}
		if _, err := s.Store.CreateUser(ctx, lu.username, lu.display, string(lu.role), hash); err != nil {
			return out, err
		}
		out = append(out, LabUser{Username: lu.username, Role: lu.role, Password: password})
	}
	return out, nil
}

// ResetPassword gives an account a new generated password and returns it.
// Like SeedLabUsers, it is a setup step and takes no actor.
func (s *Service) ResetPassword(ctx context.Context, username string) (string, error) {
	password, err := auth.GeneratePassword()
	if err != nil {
		return "", err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return "", err
	}
	if err := s.Store.SetPassword(ctx, username, hash); err != nil {
		return "", err
	}
	return password, nil
}

// --- catalog ----------------------------------------------------------------

// ImportResult says what loading one pack did.
type ImportResult struct {
	Key, Version string
	Requirements int
	Imported     bool
}

// LoadCatalog imports framework packs.
func (s *Service) LoadCatalog(ctx context.Context, actor authz.Actor, packs []*pack.Pack) ([]ImportResult, error) {
	if err := authz.Can(actor, authz.LoadCatalog, authz.Resource{}); err != nil {
		return nil, err
	}
	var out []ImportResult
	for _, p := range packs {
		imported, err := s.Store.ImportPack(ctx, p)
		if err != nil {
			return out, err
		}
		out = append(out, ImportResult{p.Framework.Key, p.Framework.Version, len(p.Requirements), imported})
	}
	return out, nil
}

// --- reads ------------------------------------------------------------------

// ControlView is a control with its derived state.
type ControlView struct {
	Control          control.Control
	State            control.State
	Reasons          []string
	Manual           control.ManualStatus
	ManualValidUntil *time.Time
}

// Overview is the front page: control states, current results and runs.
type Overview struct {
	Controls []ControlView
	Results  []store.EvaluationRow
	Runs     []store.RunRow
}

// Overview returns control states with the results and runs behind them.
func (s *Service) Overview(ctx context.Context, actor authz.Actor) (*Overview, error) {
	if err := authz.Can(actor, authz.View, authz.Resource{}); err != nil {
		return nil, err
	}
	return s.overview(ctx)
}

func (s *Service) overview(ctx context.Context) (*Overview, error) {
	now := s.now()
	results, err := s.Store.LatestResults(ctx)
	if err != nil {
		return nil, err
	}
	findings, err := s.Store.Findings(ctx)
	if err != nil {
		return nil, err
	}
	exceptions, err := s.Store.Exceptions(ctx)
	if err != nil {
		return nil, err
	}
	submissions, err := s.Store.Submissions(ctx)
	if err != nil {
		return nil, err
	}
	runs, err := s.Store.Runs(ctx, 25)
	if err != nil {
		return nil, err
	}

	// The open finding for each check and resource, and its exception cover.
	type key struct{ check, resource string }
	openFinding := map[key]int64{}
	for _, f := range findings {
		if f.Open() {
			openFinding[key{f.CheckKey, f.Resource}] = f.ID
		}
	}
	cover := func(findingID int64) (control.Cover, time.Time) {
		best, until := control.NoException, time.Time{}
		for _, x := range exceptions {
			if x.FindingID != findingID {
				continue
			}
			switch {
			case x.Active(now) && (best != control.ActiveException || x.ExpiresAt.After(until)):
				best, until = control.ActiveException, x.ExpiresAt
			case x.Expired(now) && best == control.NoException,
				x.Expired(now) && best == control.ExpiredException && x.ExpiresAt.After(until):
				best, until = control.ExpiredException, x.ExpiresAt
			}
		}
		return best, until
	}

	out := &Overview{Results: results, Runs: runs}
	for _, c := range control.All {
		in := control.Input{Now: now}
		for _, r := range results {
			applies := false
			for _, k := range c.Checks {
				applies = applies || k == r.CheckKey
			}
			if !applies {
				continue
			}
			cr := control.CheckResult{
				CheckKey: r.CheckKey, Resource: r.Resource,
				Result: check.Result(r.Result), CollectedAt: r.CollectedAt,
			}
			if cr.Result == check.Fail {
				if id, ok := openFinding[key{r.CheckKey, r.Resource}]; ok {
					cr.Cover, cr.CoverUntil = cover(id)
				}
			}
			in.Results = append(in.Results, cr)
		}
		if c.ManualCheck != "" {
			var subs []control.Submission
			for _, sub := range submissions {
				if sub.ControlKey == c.Key {
					subs = append(subs, control.Submission{ID: sub.ID, Status: sub.ReviewStatus, ValidUntil: sub.ValidUntil})
				}
			}
			in.Manual, in.ManualValidUntil = control.ManualEvidence(subs, now)
		}
		state, reasons := control.Derive(c, in)
		out.Controls = append(out.Controls, ControlView{
			Control: c, State: state, Reasons: reasons,
			Manual: in.Manual, ManualValidUntil: in.ManualValidUntil,
		})
	}
	return out, nil
}

// FindingView is a finding with its notes and exceptions, and what the
// viewer may do with it.
type FindingView struct {
	store.FindingRow
	Notes      []store.NoteRow
	Exceptions []ExceptionView
	// MayNote and MayRequest say whether the viewer may add a remediation
	// note or request an exception. They only decide which forms are shown;
	// the actions themselves are checked again when attempted.
	MayNote    bool
	MayRequest bool
}

// ExceptionView is an exception with its status at the time of viewing.
type ExceptionView struct {
	store.ExceptionRow
	DisplayStatus string
	MayDecide     bool
}

// Findings returns every finding with its notes and exceptions.
func (s *Service) Findings(ctx context.Context, actor authz.Actor) ([]FindingView, error) {
	if err := authz.Can(actor, authz.View, authz.Resource{}); err != nil {
		return nil, err
	}
	now := s.now()
	findings, err := s.Store.Findings(ctx)
	if err != nil {
		return nil, err
	}
	notes, err := s.Store.Notes(ctx)
	if err != nil {
		return nil, err
	}
	exceptions, err := s.Store.Exceptions(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]FindingView, 0, len(findings))
	for _, f := range findings {
		v := FindingView{FindingRow: f}
		res := authz.Resource{ControlOwners: control.OwnersForCheck(f.CheckKey)}
		v.MayNote = authz.Can(actor, authz.AddRemediationNote, res) == nil
		pending := false
		for _, n := range notes {
			if n.FindingID == f.ID {
				v.Notes = append(v.Notes, n)
			}
		}
		for _, x := range exceptions {
			if x.FindingID != f.ID {
				continue
			}
			pending = pending || x.Status == "requested"
			v.Exceptions = append(v.Exceptions, ExceptionView{
				ExceptionRow:  x,
				DisplayStatus: x.DisplayStatus(now),
				MayDecide: x.Status == "requested" &&
					authz.Can(actor, authz.DecideException, authz.Resource{AuthorID: x.RequestedByID}) == nil,
			})
		}
		v.MayRequest = f.Open() && !pending && authz.Can(actor, authz.RequestException, res) == nil
		out = append(out, v)
	}
	return out, nil
}

// SubmissionView is a submission and whether the viewer may review it.
type SubmissionView struct {
	store.SubmissionRow
	MayReview bool
}

// EvidencePage is the manual evidence page.
type EvidencePage struct {
	Submissions []SubmissionView
	// SubmitTo lists the controls the viewer may submit evidence for.
	SubmitTo []control.Control
}

// ManualEvidence returns the manual evidence submissions.
func (s *Service) ManualEvidence(ctx context.Context, actor authz.Actor) (*EvidencePage, error) {
	if err := authz.Can(actor, authz.View, authz.Resource{}); err != nil {
		return nil, err
	}
	subs, err := s.Store.Submissions(ctx)
	if err != nil {
		return nil, err
	}
	page := &EvidencePage{}
	for _, sub := range subs {
		page.Submissions = append(page.Submissions, SubmissionView{
			SubmissionRow: sub,
			MayReview: sub.ReviewStatus == "pending" &&
				authz.Can(actor, authz.ReviewEvidence, authz.Resource{AuthorID: sub.SubmittedByID}) == nil,
		})
	}
	for _, c := range control.All {
		if c.ManualCheck != "" && authz.Can(actor, authz.SubmitEvidence, authz.Resource{ControlOwners: []string{c.Owner}}) == nil {
			page.SubmitTo = append(page.SubmitTo, c)
		}
	}
	return page, nil
}

// EvidenceFile returns the bytes and filename of a submission's evidence.
func (s *Service) EvidenceFile(ctx context.Context, actor authz.Actor, submissionID int64) ([]byte, string, error) {
	if err := authz.Can(actor, authz.View, authz.Resource{}); err != nil {
		return nil, "", err
	}
	sub, err := s.Store.SubmissionByID(ctx, submissionID)
	if err != nil {
		return nil, "", err
	}
	data, err := s.Evidence.Get(ctx, sub.PayloadSHA256)
	return data, sub.Filename, err
}

// DecisionLog returns the most recent decision log entries.
func (s *Service) DecisionLog(ctx context.Context, actor authz.Actor) ([]store.LogRow, error) {
	if err := authz.Can(actor, authz.View, authz.Resource{}); err != nil {
		return nil, err
	}
	return s.Store.DecisionLog(ctx, 200)
}

// Export is a point-in-time export of everything the pages show. It is not
// yet the review package for a past period.
type Export struct {
	GeneratedAt time.Time
	GeneratedBy string
	Notice      string
	Controls    []ExportControl
	Results     []store.EvaluationRow
	Evaluations []store.EvaluationRow
	Findings    []store.FindingRow
	Exceptions  []ExportException
	Submissions []store.SubmissionRow
	Notes       []store.NoteRow
	Runs        []store.RunRow
	DecisionLog []store.LogRow
}

// ExportControl is a control's derived state in an export.
type ExportControl struct {
	Key, Title string
	State      control.State
	Reasons    []string
}

// ExportException is an exception with its status at export time.
type ExportException struct {
	store.ExceptionRow
	StatusAtExport string
}

// Export produces the export and logs that it was taken.
func (s *Service) Export(ctx context.Context, actor authz.Actor) (*Export, error) {
	if err := authz.Can(actor, authz.Export, authz.Resource{}); err != nil {
		return nil, err
	}
	now := s.now()
	ov, err := s.overview(ctx)
	if err != nil {
		return nil, err
	}
	e := &Export{
		GeneratedAt: now, GeneratedBy: actor.Username,
		Notice:  "Current-state export. A result describes one check applied to one stored observation; it is not a statement about any framework.",
		Results: ov.Results, Runs: ov.Runs,
	}
	for _, c := range ov.Controls {
		e.Controls = append(e.Controls, ExportControl{c.Control.Key, c.Control.Title, c.State, c.Reasons})
	}
	if e.Evaluations, err = s.Store.Evaluations(ctx, 10000); err != nil {
		return nil, err
	}
	if e.Findings, err = s.Store.Findings(ctx); err != nil {
		return nil, err
	}
	exceptions, err := s.Store.Exceptions(ctx)
	if err != nil {
		return nil, err
	}
	for _, x := range exceptions {
		e.Exceptions = append(e.Exceptions, ExportException{x, x.DisplayStatus(now)})
	}
	if e.Submissions, err = s.Store.Submissions(ctx); err != nil {
		return nil, err
	}
	if e.Notes, err = s.Store.Notes(ctx); err != nil {
		return nil, err
	}
	if e.DecisionLog, err = s.Store.DecisionLog(ctx, 10000); err != nil {
		return nil, err
	}
	if err := s.Store.LogAction(ctx, actor.UserID, "export.generated", "export", now.Unix(), "current-state export", now); err != nil {
		return nil, err
	}
	return e, nil
}

// --- writes -----------------------------------------------------------------

var unsafeFilename = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// EvidenceUpload is manual evidence being submitted.
type EvidenceUpload struct {
	ControlKey  string
	PeriodStart time.Time
	PeriodEnd   time.Time
	Filename    string
	Note        string
	Data        []byte
}

// SubmitEvidence records manual evidence for a control. It is not accepted
// until a reviewer who is not the submitter accepts it.
func (s *Service) SubmitEvidence(ctx context.Context, actor authz.Actor, up EvidenceUpload) (int64, error) {
	c, ok := control.Lookup(up.ControlKey)
	// Decide permission before saying anything about the request itself.
	if err := authz.Can(actor, authz.SubmitEvidence, authz.Resource{ControlOwners: []string{c.Owner}}); err != nil {
		return 0, err
	}
	now := s.now()
	switch {
	case !ok || c.ManualCheck == "":
		return 0, invalid("control %q does not take manual evidence", up.ControlKey)
	case up.PeriodStart.IsZero() || up.PeriodEnd.IsZero():
		return 0, invalid("the period covered needs a start and an end date")
	case up.PeriodEnd.Before(up.PeriodStart):
		return 0, invalid("the period ends before it starts")
	case up.PeriodEnd.After(now):
		return 0, invalid("the period covered cannot end in the future")
	case len(up.Data) == 0:
		return 0, invalid("an evidence file is required")
	case len(up.Data) > MaxEvidenceBytes:
		return 0, invalid("the evidence file is larger than %d MB", MaxEvidenceBytes>>20)
	case len(up.Note) > maxTextLen:
		return 0, invalid("the note is longer than %d characters", maxTextLen)
	}
	name := strings.Trim(unsafeFilename.ReplaceAllString(filepath.Base(up.Filename), "_"), "._")
	if name == "" {
		name = "evidence"
	}
	if len(name) > 120 {
		name = name[len(name)-120:]
	}

	sha, ref, err := s.Evidence.Put(ctx, up.Data)
	if err != nil {
		return 0, fmt.Errorf("store evidence: %w", err)
	}
	return s.Store.CreateSubmission(ctx, actor.UserID, store.NewSubmission{
		ControlKey: c.Key, PeriodStart: up.PeriodStart, PeriodEnd: up.PeriodEnd,
		Filename: name, Note: strings.TrimSpace(up.Note),
		PayloadSHA256: sha, PayloadSize: int64(len(up.Data)),
		PayloadMediaType: http.DetectContentType(up.Data), PayloadStorageRef: ref,
	}, now)
}

// ReviewEvidence accepts or rejects a submission. Accepted evidence is valid
// for the control's validity period, counted from the end of the period the
// evidence covers.
func (s *Service) ReviewEvidence(ctx context.Context, actor authz.Actor, submissionID int64, accept bool, reason string) error {
	sub, err := s.Store.SubmissionByID(ctx, submissionID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err := authz.Can(actor, authz.ReviewEvidence, authz.Resource{AuthorID: sub.SubmittedByID}); err != nil {
		return err
	}
	if sub.ID == 0 {
		return invalid("submission %d does not exist", submissionID)
	}
	reason = strings.TrimSpace(reason)
	if !accept && reason == "" {
		return invalid("rejecting evidence needs a reason")
	}
	if len(reason) > maxTextLen {
		return invalid("the reason is longer than %d characters", maxTextLen)
	}
	var validUntil *time.Time
	if accept {
		c, ok := control.Lookup(sub.ControlKey)
		if !ok || c.ManualValidityMonths <= 0 {
			return invalid("control %q no longer takes manual evidence", sub.ControlKey)
		}
		until := sub.PeriodEnd.AddDate(0, c.ManualValidityMonths, 0)
		validUntil = &until
	}
	err = s.Store.ReviewSubmission(ctx, submissionID, actor.UserID, accept, reason, validUntil, s.now())
	if errors.Is(err, store.ErrAlreadyDecided) {
		return invalid("submission %d has already been reviewed", submissionID)
	}
	return err
}

// RequestException asks for an open finding to be accepted until expiresAt.
// The request has no effect until someone else approves it, and it never
// changes an evaluation.
func (s *Service) RequestException(ctx context.Context, actor authz.Actor, findingID int64, justification string, expiresAt time.Time) (int64, error) {
	f, err := s.Store.FindingByID(ctx, findingID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return 0, err
	}
	if err := authz.Can(actor, authz.RequestException, authz.Resource{ControlOwners: control.OwnersForCheck(f.CheckKey)}); err != nil {
		return 0, err
	}
	now := s.now()
	justification = strings.TrimSpace(justification)
	switch {
	case f.ID == 0:
		return 0, invalid("finding %d does not exist", findingID)
	case !f.Open():
		return 0, invalid("finding %d is closed", findingID)
	case justification == "":
		return 0, invalid("an exception needs a justification")
	case len(justification) > maxTextLen:
		return 0, invalid("the justification is longer than %d characters", maxTextLen)
	case expiresAt.IsZero():
		return 0, invalid("an exception needs an expiry date")
	case !expiresAt.After(now):
		return 0, invalid("the expiry must be in the future")
	case expiresAt.After(now.AddDate(0, 0, MaxExceptionDays)):
		return 0, invalid("an exception may run for at most %d days", MaxExceptionDays)
	}
	existing, err := s.Store.Exceptions(ctx)
	if err != nil {
		return 0, err
	}
	for _, x := range existing {
		if x.FindingID == findingID && x.Status == "requested" {
			return 0, invalid("finding %d already has a request awaiting a decision", findingID)
		}
	}
	return s.Store.CreateException(ctx, findingID, actor.UserID, justification, expiresAt, now)
}

// DecideException approves or rejects an exception request. The requester
// cannot decide their own request.
func (s *Service) DecideException(ctx context.Context, actor authz.Actor, exceptionID int64, approve bool, reason string) error {
	x, err := s.Store.ExceptionByID(ctx, exceptionID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err := authz.Can(actor, authz.DecideException, authz.Resource{AuthorID: x.RequestedByID}); err != nil {
		return err
	}
	now := s.now()
	reason = strings.TrimSpace(reason)
	switch {
	case x.ID == 0:
		return invalid("exception %d does not exist", exceptionID)
	case reason == "":
		return invalid("a decision needs a reason")
	case len(reason) > maxTextLen:
		return invalid("the reason is longer than %d characters", maxTextLen)
	case approve && !x.ExpiresAt.After(now):
		return invalid("the requested expiry has already passed")
	}
	err = s.Store.DecideException(ctx, exceptionID, actor.UserID, approve, reason, now)
	if errors.Is(err, store.ErrAlreadyDecided) {
		return invalid("exception %d has already been decided", exceptionID)
	}
	return err
}

// AddRemediationNote records progress on a finding.
func (s *Service) AddRemediationNote(ctx context.Context, actor authz.Actor, findingID int64, body string) (int64, error) {
	f, err := s.Store.FindingByID(ctx, findingID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return 0, err
	}
	if err := authz.Can(actor, authz.AddRemediationNote, authz.Resource{ControlOwners: control.OwnersForCheck(f.CheckKey)}); err != nil {
		return 0, err
	}
	body = strings.TrimSpace(body)
	switch {
	case f.ID == 0:
		return 0, invalid("finding %d does not exist", findingID)
	case body == "":
		return 0, invalid("a remediation note cannot be empty")
	case len(body) > maxTextLen:
		return 0, invalid("the note is longer than %d characters", maxTextLen)
	}
	return s.Store.AddNote(ctx, findingID, actor.UserID, body, s.now())
}
