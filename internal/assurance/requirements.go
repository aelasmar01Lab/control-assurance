package assurance

import (
	"context"
	"sync"

	"github.com/aelasmar01Lab/control-assurance/internal/authz"
	"github.com/aelasmar01Lab/control-assurance/internal/control"
	"github.com/aelasmar01Lab/control-assurance/internal/pack"
	"github.com/aelasmar01Lab/control-assurance/packs"
)

// RequirementControl is a control mapped to a requirement, with its state.
type RequirementControl struct {
	Key        string        `json:"key"`
	Title      string        `json:"title"`
	State      control.State `json:"state"`
	Strength   string        `json:"strength"`
	Limitation string        `json:"limitation"`
	// Reviewed is false until someone has reviewed the mapping.
	Reviewed bool `json:"mapping_reviewed"`
}

// RequirementView is one framework requirement and where it stands.
type RequirementView struct {
	Framework           string                   `json:"framework"`
	FrameworkVersion    string                   `json:"framework_version"`
	ID                  string                   `json:"id"`
	Group               string                   `json:"group"`
	Title               string                   `json:"title"`
	Text                string                   `json:"text"`
	State               control.RequirementState `json:"state"`
	Owner               string                   `json:"owner"`
	Applicability       string                   `json:"applicability"`
	EvidenceExpectation string                   `json:"evidence_expectation"`
	// Rationale explains a requirement no control covers.
	Rationale string               `json:"rationale,omitempty"`
	Note      string               `json:"note,omitempty"`
	Controls  []RequirementControl `json:"controls"`
}

var builtInPacks = sync.OnceValues(func() ([]*pack.Pack, error) { return pack.LoadFS(packs.FS) })

// deriveRequirements gives every requirement of every built-in pack a
// state, from the control states given.
func deriveRequirements(controls []ControlView) ([]RequirementView, error) {
	all, err := builtInPacks()
	if err != nil {
		return nil, err
	}
	state := map[string]control.State{}
	for _, c := range controls {
		state[c.Control.Key] = c.State
	}
	var out []RequirementView
	for _, p := range all {
		for _, r := range p.Requirements {
			v := RequirementView{
				Framework: p.Framework.Key, FrameworkVersion: p.Framework.Version,
				ID: r.ID, Group: r.Group, Title: r.Title, Text: r.Text, Controls: []RequirementControl{},
			}
			var states []control.State
			for _, m := range control.MappedControls(p.Framework.Key, r.ID) {
				st := state[m.Control.Key]
				states = append(states, st)
				v.Controls = append(v.Controls, RequirementControl{
					Key: m.Control.Key, Title: m.Control.Title, State: st, Strength: m.Mapping.Strength,
					Limitation: m.Mapping.Limitation, Reviewed: m.Mapping.ReviewedBy != "",
				})
				// The mapped controls answer for the requirement.
				v.Owner, v.Applicability = m.Control.Owner, "Applicable."
				if v.EvidenceExpectation != "" {
					v.EvidenceExpectation += " "
				}
				v.EvidenceExpectation += m.Control.EvidenceExpectation
			}
			var tracking *control.Tracking
			if t, ok := control.TrackingFor(p.Framework.Key, r.ID); ok {
				tracking = &t
				if len(states) == 0 {
					v.Owner, v.Applicability, v.EvidenceExpectation = t.Owner, t.Applicability, t.EvidenceExpectation
					v.Rationale = t.Rationale
				}
				v.Note = t.Note
			}
			v.State = control.DeriveRequirement(states, tracking)
			out = append(out, v)
		}
	}
	return out, nil
}

// Requirements returns every requirement of the catalog with its current
// state. A requirement is positive only through controls with evidence
// behind them; one that no control covers shows how it is tracked instead.
func (s *Service) Requirements(ctx context.Context, actor authz.Actor) ([]RequirementView, error) {
	if err := authz.Can(actor, authz.View, authz.Resource{}); err != nil {
		return nil, err
	}
	ov, err := s.overview(ctx)
	if err != nil {
		return nil, err
	}
	return deriveRequirements(ov.Controls)
}
