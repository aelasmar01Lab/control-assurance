// Package control holds the internal controls, read from the content files,
// and derives each control's displayed state. The state is computed on read from evaluations, evidence
// reviews and exceptions; it is never stored.
package control

import (
	"fmt"
	"sort"
	"time"

	contentfs "github.com/aelasmar01Lab/control-assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/check"
	"github.com/aelasmar01Lab/control-assurance/internal/content"
	"github.com/aelasmar01Lab/control-assurance/internal/pack"
	"github.com/aelasmar01Lab/control-assurance/packs"
)

// Mapping ties a control to a requirement of one framework version.
type Mapping struct {
	Framework   string `json:"framework"` // pack key, such as "mvsp"
	Version     string `json:"framework_version"`
	Requirement string `json:"requirement"` // requirement identifier in that pack
	// Strength is direct, partial or supporting, as written. Derived states
	// use EffectiveStrength.
	Strength   string `json:"strength"`
	Rationale  string `json:"rationale"`
	Limitation string `json:"limitation"`
	// Basis is own_analysis, published_crosswalk or derived.
	Basis       string `json:"basis"`
	BasisSource string `json:"basis_source,omitempty"`
	// Review says whether a person has reviewed the mapping. Until then it
	// is labelled a draft wherever it is shown.
	Review content.Review `json:"review"`
}

// EffectiveStrength is the strength the mapping counts as: a direct mapping
// that nobody has reviewed counts as partial.
func (m Mapping) EffectiveStrength() string {
	if m.Strength == "direct" && !m.Review.IsReviewed() {
		return "partial"
	}
	return m.Strength
}

// Control is one internal control.
type Control struct {
	Key   string
	Title string
	// Domain is the area of work the control belongs to, such as access.
	Domain string
	// Type is automated, manual, policy or hybrid.
	Type string
	// Statement says what is true when the control works.
	Statement string
	// Risk is what the control is there to prevent.
	Risk string
	// Owner is the username answerable for the control.
	Owner string
	// EvidenceExpectation says what evidence supports the control.
	EvidenceExpectation string
	// Checks are the automated checks whose results the control rests on.
	Checks []string
	// Freshness is how old automated evidence may be before the control is stale.
	Freshness time.Duration
	// ManualCheck names the control's manual evidence, if it takes any: the
	// key of its manual-evidence check, or "manual evidence".
	ManualCheck string
	// ManualExpectation says what a person submits.
	ManualExpectation string
	// ManualValidityMonths is how long accepted manual evidence counts,
	// measured from the end of the period it covers.
	ManualValidityMonths int
	// AppliesToLab is yes, no or partly, with a reason when it is not yes.
	AppliesToLab  string
	AppliesReason string
	// Review says whether a person has reviewed the control as it now reads.
	Review content.Review
	// ContentSHA256 identifies this wording of the control: its revision.
	ContentSHA256 string
	// Path is the file the control is defined in.
	Path     string
	Mappings []Mapping
}

// AutomatedFreshness is how old automated evidence may be before a control
// that rests on it is stale, unless the control says otherwise.
const AutomatedFreshness = 48 * time.Hour

// manualEvidenceLabel names the manual evidence of a control that has no
// manual-evidence check of its own.
const manualEvidenceLabel = "manual evidence"

// All is every control, and Tracked every tracking entry, read from the
// content files built into the binary. LoadErr is set, and both are empty,
// when those files are not valid; "cca content validate" says what is wrong.
var (
	All     []Control
	Tracked []Tracking
	LoadErr error
)

func init() {
	packsList, err := pack.LoadFS(packs.FS)
	if err != nil {
		LoadErr = err
		return
	}
	set, problems := content.Load(contentfs.FS, content.BuiltInRefs(packsList))
	if len(problems) > 0 {
		LoadErr = problems
		return
	}
	All, Tracked = FromSet(set)
}

// FromSet turns content files into the controls and tracking entries the
// rest of the product works with.
func FromSet(set *content.Set) ([]Control, []Tracking) {
	manual := map[string]bool{}
	for _, c := range check.All() {
		manual[c.Key] = c.Manual
	}
	var controls []Control
	for _, f := range set.Controls {
		c := Control{
			Key: f.Key, Title: f.Title, Domain: f.Domain, Type: f.Type, Statement: f.Statement,
			Risk: f.Risk, Owner: f.OwnerRole, EvidenceExpectation: f.EvidenceExpectation,
			Freshness:    time.Duration(f.FreshnessHours) * time.Hour,
			AppliesToLab: f.AppliesToLab, AppliesReason: f.AppliesReason,
			Review: f.Review, ContentSHA256: f.Hash(), Path: f.Path,
		}
		for _, k := range f.Checks {
			if manual[k] {
				c.ManualCheck = k
			} else {
				c.Checks = append(c.Checks, k)
			}
		}
		if f.ManualEvidence != nil {
			if c.ManualCheck == "" {
				c.ManualCheck = manualEvidenceLabel
			}
			c.ManualExpectation = f.ManualEvidence.Expectation
			c.ManualValidityMonths = f.ManualEvidence.ValidityMonths
		}
		for _, m := range set.Mappings {
			if m.Control == f.Key {
				c.Mappings = append(c.Mappings, Mapping{
					Framework: m.Framework, Version: m.Version, Requirement: m.Requirement,
					Strength: m.Strength, Rationale: m.Rationale, Limitation: m.Limitation,
					Basis: m.Basis, BasisSource: m.BasisSource, Review: m.Review,
				})
			}
		}
		controls = append(controls, c)
	}
	// Domain by domain, in the order the domains are listed.
	order := map[string]int{}
	for i, d := range content.Domains {
		order[d] = i
	}
	sort.SliceStable(controls, func(i, j int) bool {
		if controls[i].Domain != controls[j].Domain {
			return order[controls[i].Domain] < order[controls[j].Domain]
		}
		return controls[i].Key < controls[j].Key
	})

	var tracked []Tracking
	for _, t := range set.Tracking {
		tracked = append(tracked, Tracking{
			Framework: t.Framework, Version: t.Version, Requirement: t.Requirement,
			Status: TrackingStatus(t.Status), Owner: t.OwnerRole, Applicability: t.Applicability,
			EvidenceExpectation: t.EvidenceExpectation, Rationale: t.Rationale, Note: t.Note, Review: t.Review,
		})
	}
	return controls, tracked
}

// Lookup returns the control with the given key.
func Lookup(key string) (Control, bool) {
	for _, c := range All {
		if c.Key == key {
			return c, true
		}
	}
	return Control{}, false
}

// OwnersForCheck returns the owners of every control that rests on checkKey.
func OwnersForCheck(checkKey string) []string {
	var out []string
	for _, c := range All {
		uses := c.ManualCheck == checkKey
		for _, k := range c.Checks {
			uses = uses || k == checkKey
		}
		if uses {
			out = append(out, c.Owner)
		}
	}
	return out
}

// State is a control's displayed state.
type State string

// The five states. The product never calls anything compliant.
const (
	NotEvaluated   State = "not_evaluated"
	NeedsAttention State = "needs_attention"
	Stale          State = "stale"
	AcceptedRisk   State = "accepted_risk"
	Supported      State = "supported"
)

// Cover says whether a current failure is covered by an exception.
type Cover int

// The exception cover a failure can have.
const (
	NoException      Cover = iota // never excepted, or only requested or rejected
	ActiveException               // approved and not yet expired
	ExpiredException              // approved, but the expiry has passed
)

// CheckResult is the current result of one automated check on one resource.
type CheckResult struct {
	CheckKey    string
	Resource    string
	Result      check.Result
	CollectedAt time.Time
	// Cover applies when Result is a fail.
	Cover Cover
	// CoverUntil is when the active or expired exception ends or ended.
	CoverUntil time.Time
}

// ManualStatus summarises the reviewed manual evidence for a control.
type ManualStatus string

// The manual evidence statuses.
const (
	ManualMissing  ManualStatus = "missing"  // nothing has been submitted
	ManualPending  ManualStatus = "pending"  // submitted, not yet reviewed, nothing accepted in period
	ManualRejected ManualStatus = "rejected" // the newest submission was rejected, nothing accepted in period
	ManualAccepted ManualStatus = "accepted" // an accepted submission is still valid
	ManualExpired  ManualStatus = "expired"  // the newest accepted submission is no longer valid
)

// Submission is the part of an evidence submission the state depends on.
type Submission struct {
	ID         int64
	Status     string // pending, accepted or rejected
	ValidUntil *time.Time
}

// ManualEvidence reduces a control's submissions to one status. An accepted
// submission that is still valid wins; otherwise the newest submission decides.
func ManualEvidence(subs []Submission, now time.Time) (ManualStatus, *time.Time) {
	today := now.UTC().Truncate(24 * time.Hour)
	var best *time.Time
	for _, s := range subs {
		if s.Status == "accepted" && s.ValidUntil != nil && !s.ValidUntil.Before(today) {
			if best == nil || s.ValidUntil.After(*best) {
				best = s.ValidUntil
			}
		}
	}
	if best != nil {
		return ManualAccepted, best
	}
	if len(subs) == 0 {
		return ManualMissing, nil
	}
	newest := subs[0]
	for _, s := range subs {
		if s.ID > newest.ID {
			newest = s
		}
	}
	switch newest.Status {
	case "pending":
		return ManualPending, nil
	case "rejected":
		return ManualRejected, nil
	default:
		return ManualExpired, newest.ValidUntil
	}
}

// Input is everything a control's state is derived from.
type Input struct {
	Now time.Time
	// Results holds the current result for each of the control's automated
	// checks on each in-scope resource. A check with no evaluation is absent.
	Results []CheckResult
	// Manual and ManualValidUntil describe the control's manual evidence.
	// They are ignored for a control with no manual check.
	Manual           ManualStatus
	ManualValidUntil *time.Time
}

// Derive returns the control's state and the reasons for it. The first
// matching rule wins:
//
//  1. Not evaluated: the control has automated checks and none has ever
//     produced a result.
//  2. Needs attention: a current failure with no approved, unexpired
//     exception (including one whose exception has expired), or manual
//     evidence that is missing, rejected or still awaiting review.
//  3. Stale: the newest evidence is older than the freshness window, or the
//     accepted manual evidence is no longer valid.
//  4. Accepted risk: every current failure is covered by an approved,
//     unexpired exception.
//  5. Not evaluated: a check's current result is not_evaluated.
//  6. Supported: every check passes on current evidence and manual evidence
//     is accepted and valid.
//
// A collection failure is not an input: it adds no observation, so it leaves
// the results alone and lets freshness age.
func Derive(c Control, in Input) (State, []string) {
	results := append([]CheckResult(nil), in.Results...)
	sort.Slice(results, func(i, j int) bool {
		if results[i].CheckKey != results[j].CheckKey {
			return results[i].CheckKey < results[j].CheckKey
		}
		return results[i].Resource < results[j].Resource
	})
	hasManual := c.ManualCheck != ""

	// 1. Never evaluated.
	if len(c.Checks) > 0 && len(results) == 0 {
		return NotEvaluated, []string{"No check for this control has produced a result yet."}
	}

	// 2. Needs attention.
	var attention []string
	failures := 0
	for _, r := range results {
		if r.Result != check.Fail {
			continue
		}
		failures++
		switch r.Cover {
		case NoException:
			attention = append(attention, fmt.Sprintf("%s fails on %s and no approved exception covers it.", r.CheckKey, r.Resource))
		case ExpiredException:
			attention = append(attention, fmt.Sprintf("%s fails on %s and its exception expired on %s.",
				r.CheckKey, r.Resource, r.CoverUntil.UTC().Format("2006-01-02 15:04 UTC")))
		}
	}
	if hasManual {
		switch in.Manual {
		case ManualMissing:
			attention = append(attention, fmt.Sprintf("%s: no evidence has been submitted.", c.ManualCheck))
		case ManualRejected:
			attention = append(attention, fmt.Sprintf("%s: the newest submission was rejected.", c.ManualCheck))
		case ManualPending:
			attention = append(attention, fmt.Sprintf("%s: submitted evidence is awaiting review, and nothing accepted is in period.", c.ManualCheck))
		}
	}
	if len(attention) > 0 {
		return NeedsAttention, attention
	}

	// 3. Stale.
	var stale []string
	for _, r := range results {
		if age := in.Now.Sub(r.CollectedAt); c.Freshness > 0 && age > c.Freshness {
			stale = append(stale, fmt.Sprintf("The newest evidence for %s on %s is %d hours old; the window is %d hours.",
				r.CheckKey, r.Resource, int(age.Hours()), int(c.Freshness.Hours())))
		}
	}
	if hasManual && in.Manual == ManualExpired {
		until := "an earlier date"
		if in.ManualValidUntil != nil {
			until = in.ManualValidUntil.Format("2006-01-02")
		}
		stale = append(stale, fmt.Sprintf("%s: the accepted evidence was valid until %s.", c.ManualCheck, until))
	}
	if len(stale) > 0 {
		return Stale, stale
	}

	// 4. Accepted risk.
	if failures > 0 {
		var why []string
		for _, r := range results {
			if r.Result == check.Fail {
				why = append(why, fmt.Sprintf("%s fails on %s; an approved exception covers it until %s.",
					r.CheckKey, r.Resource, r.CoverUntil.UTC().Format("2006-01-02 15:04 UTC")))
			}
		}
		return AcceptedRisk, why
	}

	// 5. A current result that could not be determined.
	var unknown []string
	for _, r := range results {
		if r.Result == check.NotEvaluated {
			unknown = append(unknown, fmt.Sprintf("%s could not be evaluated on %s.", r.CheckKey, r.Resource))
		}
	}
	if len(unknown) > 0 {
		return NotEvaluated, unknown
	}

	// 6. Supported, always shown beside what it rests on.
	var rests []string
	for _, r := range results {
		rests = append(rests, fmt.Sprintf("%s passes on %s.", r.CheckKey, r.Resource))
	}
	if hasManual && in.ManualValidUntil != nil {
		rests = append(rests, fmt.Sprintf("%s: accepted evidence is valid until %s.", c.ManualCheck, in.ManualValidUntil.Format("2006-01-02")))
	}
	return Supported, rests
}
