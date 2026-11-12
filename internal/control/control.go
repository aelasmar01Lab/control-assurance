// Package control defines the internal controls and derives each control's
// displayed state. The state is computed on read from evaluations, evidence
// reviews and exceptions; it is never stored.
package control

import (
	"fmt"
	"sort"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/check"
)

// Mapping ties a control to a framework requirement.
type Mapping struct {
	Framework   string // pack key, such as "mvsp"
	Requirement string // requirement identifier in that pack
	Strength    string // direct, partial or supporting
	Rationale   string
	Limitation  string
	// ReviewedBy is who reviewed the mapping. Empty means unreviewed, and
	// the mapping is labelled as such wherever it is shown.
	ReviewedBy string
}

// Control is one internal control.
type Control struct {
	Key   string
	Title string
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
	// ManualCheck is the manual-evidence check, if the control has one.
	ManualCheck string
	// ManualValidityMonths is how long accepted manual evidence counts,
	// measured from the end of the period it covers.
	ManualValidityMonths int
	Mappings             []Mapping
}

// All is every internal control defined so far. Controls live in code, so a
// change to one is a reviewed commit.
var All = []Control{
	{
		Key:                 "change-management",
		Title:               "Change management",
		Risk:                "A change reaches the default branch without review or without passing automated checks.",
		Owner:               "control-owner",
		EvidenceExpectation: "Active branch rules on each in-scope repository, collected at least every 48 hours.",
		Checks:              []string{"GH-01", "GH-02"},
		Freshness:           48 * time.Hour,
		Mappings: []Mapping{{
			Framework: "mvsp", Requirement: "3.5", Strength: "supporting",
			Rationale:  "Required review and required status checks support a consistent, controlled build and release process.",
			Limitation: "MVSP 3.5 asks for version control, build provenance and credentials kept out of source. It does not ask for pull-request approval, so this control does not establish 3.5.",
		}},
	},
	{
		Key:                  "backup-recovery",
		Title:                "Backup and recovery",
		Risk:                 "Data cannot be restored after loss because recovery has never been exercised.",
		Owner:                "control-owner",
		EvidenceExpectation:  "A dated recovery exercise record, accepted by a reviewer, covering a period that ended within the last 12 months.",
		ManualCheck:          check.REC01,
		ManualValidityMonths: 12,
		Mappings: []Mapping{{
			Framework: "mvsp", Requirement: "4.4", Strength: "partial",
			Rationale:  "A reviewed recovery exercise record shows that recovery is tested periodically.",
			Limitation: "It does not show a documented disaster recovery plan, backups held in a separate location, or that recovery would succeed today.",
		}},
	},
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
