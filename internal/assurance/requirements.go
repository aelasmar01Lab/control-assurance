package assurance

import (
	"context"
	"sync"

	contentfs "github.com/aelasmar01Lab/control-assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/authz"
	"github.com/aelasmar01Lab/control-assurance/internal/content"
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
	// Strength is the strength the mapping counts as. WrittenStrength is
	// what the file says; a draft direct mapping counts as partial.
	WrittenStrength string `json:"written_strength"`
	// Reviewed is false until the maintainer has signed the mapping, and
	// Review is the label shown beside it.
	Reviewed bool   `json:"mapping_reviewed"`
	Review   string `json:"mapping_review"`
	// ControlReviewed and ControlReview say the same of the control itself.
	ControlReviewed bool   `json:"control_reviewed"`
	ControlReview   string `json:"control_review"`
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
	Rationale string `json:"rationale,omitempty"`
	Note      string `json:"note,omitempty"`
	// TrackingReview is the review label of the tracking entry, when the
	// requirement has one.
	TrackingReview string `json:"tracking_review,omitempty"`
	// Basis says what the requirement's state rests on: "reviewed" when
	// every mapping to it and every control behind them is reviewed (or its
	// tracking entry is), "none" when nobody has assessed the requirement,
	// otherwise "draft".
	Basis    string               `json:"basis"`
	Controls []RequirementControl `json:"controls"`
}

// basisNone is the basis of a requirement nobody has assessed.
const basisNone = "none"

var builtInPacks = sync.OnceValues(func() ([]*pack.Pack, error) { return pack.LoadFS(packs.FS) })

// builtInContent is the content files built into the binary, as read.
var builtInContent = sync.OnceValues(func() (*content.Set, error) {
	all, err := builtInPacks()
	if err != nil {
		return nil, err
	}
	set, problems := content.Load(contentfs.FS, content.BuiltInRefs(all))
	if len(problems) > 0 {
		return nil, problems
	}
	return set, nil
})

// deriveRequirements gives every requirement of every built-in pack a
// state for one organization, from the control states given and that
// organization's tracking entries.
func deriveRequirements(organization string, controls []ControlView) ([]RequirementView, error) {
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
		for _, r := range p.Assessed() {
			v := RequirementView{
				Framework: p.Framework.Key, FrameworkVersion: p.Framework.Version,
				ID: r.ID, Group: r.Group, Title: r.Name(), Text: r.Text, Controls: []RequirementControl{},
			}
			var states []control.State
			for _, m := range control.MappedControls(p.Framework.Key, r.ID) {
				st := state[m.Control.Key]
				states = append(states, st)
				v.Controls = append(v.Controls, RequirementControl{
					Key: m.Control.Key, Title: m.Control.Title, State: st,
					Strength: m.Mapping.EffectiveStrength(), WrittenStrength: m.Mapping.Strength,
					Limitation: m.Mapping.Limitation,
					Reviewed:   m.Mapping.Review.IsReviewed(), Review: m.Mapping.Review.Label(),
					ControlReviewed: m.Control.Review.IsReviewed(), ControlReview: m.Control.Review.Label(),
				})
				// The mapped controls answer for the requirement.
				v.Owner, v.Applicability = m.Control.Owner, "Applicable."
				if v.EvidenceExpectation != "" {
					v.EvidenceExpectation += " "
				}
				v.EvidenceExpectation += m.Control.EvidenceExpectation
			}
			var tracking *control.Tracking
			if t, ok := control.TrackingFor(organization, p.Framework.Key, r.ID); ok {
				tracking = &t
				if len(states) == 0 {
					v.Owner, v.Applicability, v.EvidenceExpectation = t.Owner, t.Applicability, t.EvidenceExpectation
					v.Rationale = t.Rationale
				}
				v.Note = t.Note
				if t.Status == control.NotAssessed {
					// Nothing was assessed: there is no draft to label and
					// nothing a review could rest on.
					v.Basis = basisNone
				} else {
					v.TrackingReview = t.Review.Label()
					if t.Review.IsReviewed() && len(states) == 0 {
						v.Basis = content.Reviewed
					}
				}
			}
			if len(v.Controls) > 0 {
				v.Basis = content.Reviewed
				for _, c := range v.Controls {
					if !c.Reviewed || !c.ControlReviewed {
						v.Basis = content.Draft
					}
				}
			}
			if v.Basis == "" {
				v.Basis = content.Draft
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
	return deriveRequirements(s.organization(), ov.Controls)
}

// FrameworkView is one framework pack and how much of it rests on what.
type FrameworkView struct {
	Key         string `json:"key"`
	Title       string `json:"title"`
	Version     string `json:"version"`
	TextRights  string `json:"text_rights"`
	License     string `json:"license"`
	Attribution string `json:"attribution,omitempty"`
	Source      string `json:"source"`
	ProfileOf   string `json:"profile_of,omitempty"`
	// Requirements is how many requirements the pack has.
	Requirements int `json:"requirements"`
	// OnReviewed and OnDrafts split the requirements a control maps to:
	// those whose every mapping and control has been reviewed, and those
	// resting on at least one draft. The two are never added together.
	OnReviewed int `json:"mapped_on_reviewed"`
	OnDrafts   int `json:"mapped_on_drafts"`
	// Tracked is how many requirements no control covers; TrackedReviewed
	// is how many of those tracking entries have been reviewed.
	Tracked         int `json:"tracked"`
	TrackedReviewed int `json:"tracked_reviewed"`
	// NotAssessed is how many requirements nobody has looked at yet. They
	// are not counted in Tracked.
	NotAssessed int `json:"not_assessed"`
	// States counts the requirements by state.
	States map[string]int `json:"states"`
}

// Frameworks returns every built-in framework pack with its counts.
func (s *Service) Frameworks(ctx context.Context, actor authz.Actor) ([]FrameworkView, []RequirementView, error) {
	reqs, err := s.Requirements(ctx, actor)
	if err != nil {
		return nil, nil, err
	}
	all, err := builtInPacks()
	if err != nil {
		return nil, nil, err
	}
	var out []FrameworkView
	for _, p := range all {
		f := p.Framework
		v := FrameworkView{
			Key: f.Key, Title: f.Title, Version: f.Version, TextRights: f.TextRights, License: f.License,
			Attribution: f.Attribution, Source: f.Source.Ref(), ProfileOf: f.ProfileOf, States: map[string]int{},
		}
		for _, r := range reqs {
			if r.Framework != f.Key || r.FrameworkVersion != f.Version {
				continue
			}
			v.Requirements++
			v.States[string(r.State)]++
			switch {
			case r.State == control.ReqNotAssessed:
				v.NotAssessed++
			case len(r.Controls) == 0:
				v.Tracked++
				if r.Basis == content.Reviewed {
					v.TrackedReviewed++
				}
			case r.Basis == content.Reviewed:
				v.OnReviewed++
			default:
				v.OnDrafts++
			}
		}
		out = append(out, v)
	}
	return out, reqs, nil
}

// ReviewQueue returns what is waiting for the maintainer's review in the
// content built into this binary.
func (s *Service) ReviewQueue(_ context.Context, actor authz.Actor) (content.Queue, error) {
	if err := authz.Can(actor, authz.View, authz.Resource{}); err != nil {
		return content.Queue{}, err
	}
	set, err := builtInContent()
	if err != nil {
		return content.Queue{}, err
	}
	return content.BuildQueue(set), nil
}
