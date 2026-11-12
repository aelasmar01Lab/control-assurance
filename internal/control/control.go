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

// AutomatedFreshness is how old automated evidence may be before a control
// that rests on it is stale.
const AutomatedFreshness = 48 * time.Hour

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
		Freshness:           AutomatedFreshness,
		Mappings: []Mapping{{
			Framework: "mvsp", Requirement: "3.5", Strength: "supporting",
			Rationale:  "Required review and required status checks support a consistent, controlled build and release process.",
			Limitation: "MVSP 3.5 asks for version control, build provenance and credentials kept out of source. It does not ask for pull-request approval, so this control does not establish 3.5.",
		}},
	},
	{
		Key:                 "dependency-remediation",
		Title:               "Dependency remediation",
		Risk:                "A dependency with a known vulnerability stays in use past the patch deadline.",
		Owner:               "control-owner",
		EvidenceExpectation: "Open Dependabot alerts on each in-scope repository, collected at least every 48 hours.",
		Checks:              []string{"GH-03"},
		Freshness:           AutomatedFreshness,
		Mappings: []Mapping{
			{
				Framework: "mvsp", Requirement: "2.6", Strength: "partial",
				Rationale:  "Open alerts within their deadline show that known-vulnerable third-party components are being patched.",
				Limitation: "It covers only what Dependabot knows about in manifests it can read, and says nothing about keeping components otherwise up to date.",
			},
			{
				Framework: "mvsp", Requirement: "3.4", Strength: "partial",
				Rationale:  "MVSP 3.4 sets a 90 day limit for patching application vulnerabilities; the medium deadline matches it and the high deadline is shorter.",
				Limitation: "MVSP 3.4 covers vulnerabilities in the application itself. This control sees only its dependencies.",
			},
		},
	},
	{
		Key:                 "vulnerability-disclosure",
		Title:               "Vulnerability disclosure",
		Risk:                "Someone who finds a vulnerability has no stated way to report it.",
		Owner:               "control-owner",
		EvidenceExpectation: "A security policy file on the default branch of each in-scope repository, checked at least every 48 hours.",
		Checks:              []string{"GH-04"},
		Freshness:           AutomatedFreshness,
		Mappings: []Mapping{{
			Framework: "mvsp", Requirement: "1.1", Strength: "partial",
			Rationale:  "A published security policy file is where a repository states how to report a vulnerability.",
			Limitation: "The file's content is not read, so this shows nothing about a contact, a response time or safe-harbour wording, all of which MVSP 1.1 asks for.",
		}},
	},
	{
		Key:                 "human-access",
		Title:               "Human access",
		Risk:                "A stolen password alone is enough to sign in to the AWS account.",
		Owner:               "control-owner",
		EvidenceExpectation: "The IAM credential report and account summary, collected at least every 48 hours.",
		Checks:              []string{"AWS-01"},
		Freshness:           AutomatedFreshness,
		Mappings: []Mapping{{
			Framework: "mvsp", Requirement: "4.2", Strength: "partial",
			Rationale:  "MFA on every console password limits what a stolen password allows.",
			Limitation: "MVSP 4.2 covers logical access more widely: least privilege, access review and removal of unused accounts. Federated users are not seen.",
		}},
	},
	{
		Key:                 "credential-lifecycle",
		Title:               "Credential lifecycle",
		Risk:                "A credential nobody uses stays valid until someone else finds it.",
		Owner:               "control-owner",
		EvidenceExpectation: "The IAM credential report and account summary, collected at least every 48 hours.",
		Checks:              []string{"AWS-02"},
		Freshness:           AutomatedFreshness,
		Mappings: []Mapping{{
			Framework: "mvsp", Requirement: "4.2", Strength: "partial",
			Rationale:  "Finding passwords and keys that have gone unused supports removing access that is no longer needed.",
			Limitation: "It shows last use, not whether access is still needed, and it does not see roles or federated sessions.",
		}},
	},
	{
		Key:                 "audit-logging",
		Title:               "Audit logging",
		Risk:                "Actions in the AWS account leave no trustworthy record.",
		Owner:               "control-owner",
		EvidenceExpectation: "CloudTrail trail descriptions and status, collected at least every 48 hours.",
		Checks:              []string{"AWS-03"},
		Freshness:           AutomatedFreshness,
		Mappings: []Mapping{{
			Framework: "mvsp", Requirement: "2.7", Strength: "supporting",
			Rationale:  "A validated multi-Region trail records management activity in the account that hosts the application.",
			Limitation: "MVSP 2.7 asks for application logs of user and security events. CloudTrail records AWS API activity, which is a different thing.",
		}},
	},
	{
		Key:                 "ai-usage-logging",
		Title:               "AI usage logging",
		Risk:                "Model invocations in the account cannot be reviewed afterwards.",
		Owner:               "control-owner",
		EvidenceExpectation: "The Bedrock model invocation logging configuration in the lab Region, collected at least every 48 hours.",
		Checks:              []string{"AWS-04"},
		Freshness:           AutomatedFreshness,
		// No framework in this release has a requirement this control maps to.
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
