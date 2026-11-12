package control

import (
	"sort"

	"github.com/aelasmar01Lab/control-assurance/internal/content"
)

// Tracking says how a framework requirement that no control covers is
// tracked. Every requirement of the catalog is either mapped by a control or
// has a Tracking entry; none is left out.
type Tracking struct {
	Framework   string
	Version     string
	Requirement string
	// Status is manual, not_implemented, out_of_scope or not_assessed.
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
	// Review says whether a person has reviewed the entry.
	Review content.Review
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
	// NotAssessed means nobody has looked at the requirement yet. The
	// entry says nothing else and is not reviewed.
	NotAssessed TrackingStatus = content.NotAssessed
)

// MappedControls returns the controls that map to a requirement, with the
// mapping each uses, ordered by control key.
func MappedControls(framework, requirement string) []MappedControl {
	return mappedIn(All, framework, requirement)
}

func mappedIn(controls []Control, framework, requirement string) []MappedControl {
	var out []MappedControl
	for _, c := range controls {
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
	// ReqNotAssessed marks a requirement nobody has looked at yet.
	ReqNotAssessed RequirementState = "not_assessed"
	// ReqNotApplicable marks a requirement whose every mapped control is
	// excluded, by a reviewed exclusion, for the organization being shown.
	ReqNotApplicable RequirementState = "not_applicable"
	// ReqUntracked marks a requirement with neither a control nor a
	// tracking entry. The tests keep it from occurring.
	ReqUntracked RequirementState = "untracked"
)

// severity orders control states from best to worst for a requirement.
var severity = map[State]int{Supported: 0, AcceptedRisk: 1, NotEvaluated: 2, Stale: 3, NeedsAttention: 4}

// DeriveRequirement returns a requirement's state from the states of the
// controls mapped to it, or from its tracking entry when there is none.
// The worst control state decides. A control that does not apply to the
// organization is left out; when none is left, the requirement does not
// apply either.
func DeriveRequirement(states []State, tracking *Tracking) RequirementState {
	mapped := len(states)
	applicable := states[:0:0]
	for _, s := range states {
		if s != NotApplicable {
			applicable = append(applicable, s)
		}
	}
	states = applicable
	if mapped > 0 && len(states) == 0 {
		return ReqNotApplicable
	}
	if len(states) == 0 {
		if tracking == nil {
			return ReqUntracked
		}
		switch tracking.Status {
		case TrackedManually:
			return ReqManual
		case OutOfScope:
			return ReqOutOfScope
		case NotAssessed:
			return ReqNotAssessed
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
