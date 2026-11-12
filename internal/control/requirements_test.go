package control

import (
	"os"
	"strings"
	"testing"

	"github.com/aelasmar01Lab/control-assurance/internal/content"
	"github.com/aelasmar01Lab/control-assurance/internal/pack"
	"github.com/aelasmar01Lab/control-assurance/packs"
)

// Every requirement of the catalog is covered by a control or tracked with
// a reason, never both and never neither.
func TestEveryRequirementIsMappedOrTracked(t *testing.T) {
	all, err := pack.LoadFS(packs.FS)
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	total := 0
	for _, p := range all {
		// Headings give the hierarchy and are not assessed.
		for _, r := range p.Assessed() {
			total++
			known[p.Framework.Key+" "+r.ID] = true
			mapped := len(MappedControls(p.Framework.Key, r.ID)) > 0
			tr, tracked := TrackingFor(p.Framework.Key, r.ID)
			switch {
			case mapped == tracked:
				t.Errorf("%s %s: mapped = %v, tracked = %v; want exactly one", p.Framework.Key, r.ID, mapped, tracked)
			case tracked && tr.Status == NotAssessed:
				// Nobody has looked: the entry says nothing else, by rule.
				if tr.Owner != "" || tr.Applicability != "" || tr.EvidenceExpectation != "" || tr.Rationale != "" || tr.Review.Status != "" {
					t.Errorf("%s %s: a not assessed entry says more than that: %+v", p.Framework.Key, r.ID, tr)
				}
			case tracked && (tr.Owner == "" || tr.Applicability == "" || tr.EvidenceExpectation == "" || tr.Rationale == ""):
				t.Errorf("%s %s: tracking entry is incomplete: %+v", p.Framework.Key, r.ID, tr)
			}
		}
	}
	if total < 25 {
		t.Errorf("catalog has %d requirements, want at least MVSP's 25", total)
	}
	// Nothing points at a requirement that does not exist.
	for _, tr := range Tracked {
		if !known[tr.Framework+" "+tr.Requirement] {
			t.Errorf("tracking entry for unknown requirement %s %s", tr.Framework, tr.Requirement)
		}
	}
	for _, c := range All {
		for _, m := range c.Mappings {
			if !known[m.Framework+" "+m.Requirement] {
				t.Errorf("control %s maps to unknown requirement %s %s", c.Key, m.Framework, m.Requirement)
			}
		}
	}
	if len(All) < 8 {
		t.Errorf("%d controls are defined, want at least the first release's 8", len(All))
	}
}

// No requirement shows a positive state without evidence behind it.
func TestRequirementStateIsNeverPositiveWithoutEvidence(t *testing.T) {
	for _, tr := range Tracked {
		if got := DeriveRequirement(nil, &tr); got == ReqPartlyEvidenced || got == ReqAcceptedRisk {
			t.Errorf("%s is tracked as %s but shows %s", tr.Requirement, tr.Status, got)
		}
	}
	if got := DeriveRequirement(nil, &Tracking{Status: NotAssessed}); got != ReqNotAssessed {
		t.Errorf("a requirement nobody has assessed shows %s", got)
	}
	if got := DeriveRequirement(nil, nil); got != ReqUntracked {
		t.Errorf("an untracked requirement shows %s", got)
	}
	tests := []struct {
		states []State
		want   RequirementState
	}{
		{[]State{Supported}, ReqPartlyEvidenced},
		{[]State{Supported, Supported}, ReqPartlyEvidenced},
		{[]State{Supported, NotEvaluated}, ReqNotEvaluated},
		{[]State{Supported, Stale}, ReqStale},
		{[]State{Supported, AcceptedRisk}, ReqAcceptedRisk},
		{[]State{AcceptedRisk, NeedsAttention, Supported}, ReqNeedsAttention},
		{[]State{NotEvaluated}, ReqNotEvaluated},
	}
	for _, tt := range tests {
		if got := DeriveRequirement(tt.states, nil); got != tt.want {
			t.Errorf("DeriveRequirement(%v) = %s, want %s", tt.states, got, tt.want)
		}
	}
}

// A reviewed exclusion makes a control not applicable in its organization
// and nowhere else. A draft exclusion changes nothing: a draft may not take
// a failing control out of view.
func TestOnlyAReviewedExclusionChangesAState(t *testing.T) {
	saved := Scopes
	t.Cleanup(func() { Scopes = saved })
	draft := content.Exclusion{Control: "a", Reason: "No such thing here.", Review: content.Review{Status: content.Draft}}
	reviewed := content.Exclusion{Control: "b", Reason: "No such thing here.", Review: content.Review{Status: content.Reviewed, ReviewedBy: "ali", ReviewedOn: "2026-11-12"}}
	Scopes = []content.Scope{{Organization: "one", Exclusions: []content.Exclusion{draft, reviewed}}, {Organization: "two"}}

	why := []string{"GH-01 fails."}
	if st, r := ApplyScope("one", "a", NeedsAttention, why); st != NeedsAttention || r[0] != why[0] {
		t.Errorf("a draft exclusion changed the state to %s (%v)", st, r)
	}
	if st, r := ApplyScope("one", "b", NeedsAttention, why); st != NotApplicable || !strings.Contains(r[0], "No such thing here.") {
		t.Errorf("a reviewed exclusion gave %s (%v)", st, r)
	}
	if st, _ := ApplyScope("two", "b", NeedsAttention, why); st != NeedsAttention {
		t.Errorf("an exclusion in one organization changed another: %s", st)
	}
	if _, ok := ExclusionFor("one", "a"); !ok {
		t.Error("the draft exclusion is not reported, so it could not be shown")
	}

	// A requirement ignores controls that do not apply, and does not apply
	// itself when none is left. It is never positive for that reason.
	tests := []struct {
		states []State
		want   RequirementState
	}{
		{[]State{NotApplicable}, ReqNotApplicable},
		{[]State{NotApplicable, NotApplicable}, ReqNotApplicable},
		{[]State{NotApplicable, NeedsAttention}, ReqNeedsAttention},
		{[]State{NotApplicable, Supported}, ReqPartlyEvidenced},
	}
	for _, tt := range tests {
		if got := DeriveRequirement(tt.states, nil); got != tt.want {
			t.Errorf("DeriveRequirement(%v) = %s, want %s", tt.states, got, tt.want)
		}
	}
}

// The built-in organizations are the lab, which is real, and the demo,
// which is not.
func TestBuiltInOrganizations(t *testing.T) {
	lab, ok := ScopeFor(DefaultOrganization)
	if !ok || lab.Synthetic {
		t.Errorf("lab = %+v, %v", lab, ok)
	}
	demo, ok := ScopeFor("demo")
	if !ok || !demo.Synthetic {
		t.Errorf("demo = %+v, %v", demo, ok)
	}
}

// The committed guide must match the definitions in force.
func TestControlGuideIsInSync(t *testing.T) {
	all, err := pack.LoadFS(packs.FS)
	if err != nil {
		t.Fatal(err)
	}
	const path = "../../docs/controls.md"
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with `make content`)", path, err)
	}
	if string(onDisk) != Guide(all) {
		t.Errorf("%s is out of date; regenerate with `make content`", path)
	}
}
