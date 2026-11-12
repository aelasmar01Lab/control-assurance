package control

import "sort"

// Tracking says how a framework requirement that no control covers is
// tracked. Every requirement of the catalog is either mapped by a control or
// has a Tracking entry; none is left out.
type Tracking struct {
	Framework   string
	Requirement string
	// Status is manual, not_implemented or out_of_scope.
	Status TrackingStatus
	Owner  string
	// Applicability says whether the requirement applies to the lab, and why.
	Applicability string
	// EvidenceExpectation is what evidence would support the requirement.
	EvidenceExpectation string
	// Rationale explains the status. Out of scope always has one.
	Rationale string
	// Note records anything a reader must know about the requirement itself.
	Note string
}

// TrackingStatus is how an uncovered requirement is tracked.
type TrackingStatus string

// The tracking statuses. None of them is a positive state.
const (
	// TrackedManually means the work is done or judged outside this
	// system, and no evidence of it is held here.
	TrackedManually TrackingStatus = "manual"
	// NotImplemented means nothing addresses the requirement.
	NotImplemented TrackingStatus = "not_implemented"
	// OutOfScope means the requirement does not apply to the lab.
	OutOfScope TrackingStatus = "out_of_scope"
)

// LabScope describes what the tracked organization is. Every applicability
// statement below is about this.
const LabScope = "The lab is two public, nonsensitive repositories and one AWS account. It has no product, customers, staff or premises."

// Tracked lists the MVSP requirements that no control covers.
var Tracked = []Tracking{
	{Framework: "mvsp", Requirement: "1.2", Status: OutOfScope, Owner: "control-owner",
		Applicability:       "Not applicable.",
		EvidenceExpectation: "None.",
		Rationale:           "The lab offers no application to customers, so there is nothing for a customer to test."},
	{Framework: "mvsp", Requirement: "1.3", Status: TrackedManually, Owner: "control-owner",
		Applicability:       "Applicable.",
		EvidenceExpectation: "A dated self-assessment against the latest MVSP release, repeated at least yearly.",
		Rationale:           "The project's own self-assessment is in docs/self-assessment.md. It is not submitted or reviewed as evidence in this system."},
	{Framework: "mvsp", Requirement: "1.4", Status: NotImplemented, Owner: "control-owner",
		Applicability:       "Applicable.",
		EvidenceExpectation: "A penetration test report from an outside vendor, dated within a year.",
		Rationale:           "No external test has been contracted."},
	{Framework: "mvsp", Requirement: "1.5", Status: NotImplemented, Owner: "control-owner",
		Applicability:       "Applicable once the lab has personnel.",
		EvidenceExpectation: "Training records by role.",
		Rationale:           "There is no training programme and no record of any."},
	{Framework: "mvsp", Requirement: "1.6", Status: NotImplemented, Owner: "control-owner",
		Applicability:       "Applicable.",
		EvidenceExpectation: "A list of the standards and laws that apply, and an assessment against each.",
		Rationale:           "No standard or legal obligation has been assessed."},
	{Framework: "mvsp", Requirement: "1.7", Status: NotImplemented, Owner: "control-owner",
		Applicability:       "Applicable.",
		EvidenceExpectation: "A documented incident process, and records of its use or exercise.",
		Rationale:           "No incident handling process is documented."},
	{Framework: "mvsp", Requirement: "1.8", Status: OutOfScope, Owner: "control-owner",
		Applicability:       "Not applicable.",
		EvidenceExpectation: "None.",
		Rationale:           "The lab holds no production data and controls no storage media; all storage is the cloud providers'."},
	{Framework: "mvsp", Requirement: "2.1", Status: NotImplemented, Owner: "control-owner",
		Applicability:       "Applicable to any application the lab runs, including this one.",
		EvidenceExpectation: "Sign-in configuration showing single sign-on over a standard protocol.",
		Rationale:           "This application signs users in with local accounts. No check reads sign-in configuration.",
		Note: "The pinned upstream catalog file gives requirement 2.1 the statement text of requirement 1.1. " +
			"The text is shown as upstream published it; the title, Single sign-on, is what the requirement is about."},
	{Framework: "mvsp", Requirement: "2.2", Status: NotImplemented, Owner: "control-owner",
		Applicability:       "Applicable once an application is hosted.",
		EvidenceExpectation: "A redirect from HTTP to HTTPS and a Strict-Transport-Security header, observed from outside.",
		Rationale:           "Nothing is hosted. A check for this is planned for when a hosted demo exists."},
	{Framework: "mvsp", Requirement: "2.3", Status: NotImplemented, Owner: "control-owner",
		Applicability:       "Applicable once an application is hosted.",
		EvidenceExpectation: "Response headers observed from outside.",
		Rationale:           "This application sets a content security policy and related headers, and tests them, but no check collects them as evidence."},
	{Framework: "mvsp", Requirement: "2.4", Status: NotImplemented, Owner: "control-owner",
		Applicability:       "Applicable to any application with password sign-in, including this one.",
		EvidenceExpectation: "The password policy in force, and tests of it.",
		Rationale:           "No check reads a password policy. This application's own sign-in has no lockout or rate limit."},
	{Framework: "mvsp", Requirement: "2.5", Status: TrackedManually, Owner: "control-owner",
		Applicability:       "Applicable.",
		EvidenceExpectation: "A record of the frameworks and libraries relied on for escaping output and handling input.",
		Rationale:           "Judged in code review. No evidence of it is held in this system."},
	{Framework: "mvsp", Requirement: "2.8", Status: NotImplemented, Owner: "control-owner",
		Applicability:       "Applicable.",
		EvidenceExpectation: "Encryption settings for data in transit and at rest, read from each store.",
		Rationale:           "No check reads encryption settings."},
	{Framework: "mvsp", Requirement: "3.1", Status: TrackedManually, Owner: "control-owner",
		Applicability:       "Applicable.",
		EvidenceExpectation: "A maintained list of the sensitive data types handled.",
		Rationale:           "The data this application handles is listed in docs/operations.md. The list is not submitted or reviewed as evidence in this system."},
	{Framework: "mvsp", Requirement: "3.2", Status: NotImplemented, Owner: "control-owner",
		Applicability:       "Applicable.",
		EvidenceExpectation: "A current data flow diagram.",
		Rationale:           "No data flow diagram is maintained."},
	{Framework: "mvsp", Requirement: "3.3", Status: NotImplemented, Owner: "control-owner",
		Applicability:       "Applicable.",
		EvidenceExpectation: "Development guidelines and training records covering the listed vulnerability classes.",
		Rationale:           "There are no written guidelines and no training records."},
	{Framework: "mvsp", Requirement: "4.1", Status: OutOfScope, Owner: "control-owner",
		Applicability:       "Not applicable.",
		EvidenceExpectation: "None.",
		Rationale:           "The lab has no facilities. Physical security of the data centres is the cloud providers'."},
	{Framework: "mvsp", Requirement: "4.3", Status: OutOfScope, Owner: "control-owner",
		Applicability:       "Not applicable.",
		EvidenceExpectation: "None.",
		Rationale:           "The lab holds no customer data, so no third party has access to any."},
}

// MappedControls returns the controls that map to a requirement, with the
// mapping each uses, ordered by control key.
func MappedControls(framework, requirement string) []MappedControl {
	var out []MappedControl
	for _, c := range All {
		for _, m := range c.Mappings {
			if m.Framework == framework && m.Requirement == requirement {
				out = append(out, MappedControl{Control: c, Mapping: m})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Control.Key < out[j].Control.Key })
	return out
}

// MappedControl is a control and the mapping that ties it to a requirement.
type MappedControl struct {
	Control Control
	Mapping Mapping
}

// TrackingFor returns the tracking entry for a requirement, if it has one.
func TrackingFor(framework, requirement string) (Tracking, bool) {
	for _, t := range Tracked {
		if t.Framework == framework && t.Requirement == requirement {
			return t, true
		}
	}
	return Tracking{}, false
}

// RequirementState is the state shown for a framework requirement.
type RequirementState string

// The requirement states. The only positive one, partly evidenced, needs
// every mapped control to be supported by current evidence, and no mapping
// in this release is strong enough to say more than "partly".
const (
	ReqPartlyEvidenced RequirementState = "partly_evidenced"
	ReqAcceptedRisk    RequirementState = "accepted_risk"
	ReqNotEvaluated    RequirementState = "not_evaluated"
	ReqStale           RequirementState = "stale"
	ReqNeedsAttention  RequirementState = "needs_attention"
	ReqManual          RequirementState = "tracked_manually"
	ReqNotImplemented  RequirementState = "not_implemented"
	ReqOutOfScope      RequirementState = "out_of_scope"
	// ReqUntracked marks a requirement with neither a control nor a
	// tracking entry. The tests keep it from occurring.
	ReqUntracked RequirementState = "untracked"
)

// severity orders control states from best to worst for a requirement.
var severity = map[State]int{Supported: 0, AcceptedRisk: 1, NotEvaluated: 2, Stale: 3, NeedsAttention: 4}

// DeriveRequirement returns a requirement's state from the states of the
// controls mapped to it, or from its tracking entry when there is none.
// The worst control state decides.
func DeriveRequirement(states []State, tracking *Tracking) RequirementState {
	if len(states) == 0 {
		if tracking == nil {
			return ReqUntracked
		}
		switch tracking.Status {
		case TrackedManually:
			return ReqManual
		case OutOfScope:
			return ReqOutOfScope
		default:
			return ReqNotImplemented
		}
	}
	worst := Supported
	for _, s := range states {
		if severity[s] > severity[worst] {
			worst = s
		}
	}
	switch worst {
	case NeedsAttention:
		return ReqNeedsAttention
	case Stale:
		return ReqStale
	case NotEvaluated:
		return ReqNotEvaluated
	case AcceptedRisk:
		return ReqAcceptedRisk
	default:
		return ReqPartlyEvidenced
	}
}
