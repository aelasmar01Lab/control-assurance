package control

import (
	"os"
	"testing"

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
		for _, r := range p.Requirements {
			total++
			known[p.Framework.Key+" "+r.ID] = true
			mapped := len(MappedControls(p.Framework.Key, r.ID)) > 0
			tr, tracked := TrackingFor(p.Framework.Key, r.ID)
			switch {
			case mapped == tracked:
				t.Errorf("%s %s: mapped = %v, tracked = %v; want exactly one", p.Framework.Key, r.ID, mapped, tracked)
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
