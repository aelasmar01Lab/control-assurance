// Package assurance is the service layer: collection jobs, evaluation and
// decisions. The CLI, the worker and the web handlers all go through it, and
// it checks permission first.
package assurance

import (
	"context"
	"fmt"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/authz"
	"github.com/aelasmar01Lab/control-assurance/internal/check"
	"github.com/aelasmar01Lab/control-assurance/internal/collect"
	"github.com/aelasmar01Lab/control-assurance/internal/control"
	"github.com/aelasmar01Lab/control-assurance/internal/evidence"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
)

// CollectFunc collects one kind of evidence from one target: a repository
// or an account.
type CollectFunc = func(ctx context.Context, target string) (*collect.Snapshot, error)

// Service ties the collectors, evidence store, checks and database together.
type Service struct {
	Store    *store.Store
	Evidence evidence.Store
	// Organization is the organization this process shows: a key of a file
	// under scope/. It decides which controls do not apply. Empty means
	// the lab.
	Organization string
	// Collectors are the collectors this process can run, keyed by the
	// kind of observation each produces. A worker claims only these kinds.
	Collectors map[string]CollectFunc
	// Now is the clock; it defaults to time.Now.
	Now func() time.Time
	// RunTimeout bounds one collection attempt. It defaults to 90 seconds.
	RunTimeout time.Duration
	// Lease is how long a claimed attempt belongs to its worker. It must
	// be longer than RunTimeout, and defaults to 5 minutes.
	Lease time.Duration
}

func (s *Service) organization() string {
	if s.Organization != "" {
		return s.Organization
	}
	return control.DefaultOrganization
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// EvaluationSummary describes one new evaluation.
type EvaluationSummary struct {
	EvaluationID  int64
	ObservationID int64
	CheckKey      string
	CheckVersion  string
	Result        check.Result
	Explanation   string
	Finding       store.FindingChange
}

// Evaluate applies the current version of every check to each observation
// that version has not yet evaluated, oldest first. Running it again with
// nothing new does nothing. When a check gains a new version, every stored
// observation of its kind is evaluated under it, which adds evaluations and
// rewrites none.
func (s *Service) Evaluate(ctx context.Context, actor authz.Actor) ([]EvaluationSummary, error) {
	if err := authz.Can(actor, authz.RunEvaluation, authz.Resource{}); err != nil {
		return nil, err
	}
	out, err := s.evaluate(ctx)
	if len(out) > 0 {
		last := out[len(out)-1].EvaluationID
		if logErr := s.Store.LogAction(ctx, actor.UserID, "evaluation.run", "evaluation", last,
			fmt.Sprintf("%d evaluations recorded, ending with this one", len(out)), s.now()); logErr != nil && err == nil {
			err = logErr
		}
	}
	return out, err
}

func (s *Service) evaluate(ctx context.Context) ([]EvaluationSummary, error) {
	var out []EvaluationSummary
	for _, c := range check.Current() {
		if err := s.Store.SyncCheckVersion(ctx, c); err != nil {
			return out, err
		}
		pending, err := s.Store.PendingObservations(ctx, c)
		if err != nil {
			return out, fmt.Errorf("list observations for %s: %w", c.Key, err)
		}
		for _, o := range pending {
			// Read through the evidence store so the bytes are verified
			// against the hash the observation recorded.
			payload, err := s.Evidence.Get(ctx, o.PayloadSHA256)
			if err != nil {
				return out, fmt.Errorf("%s on observation %d: %w", c.Key, o.ID, err)
			}
			result, explanation, err := c.Eval(check.Input{Payload: payload, AsOf: o.AsOf})
			if err != nil {
				return out, fmt.Errorf("%s on observation %d: %w", c.Key, o.ID, err)
			}
			id, change, err := s.Store.RecordEvaluation(ctx, o, c, result, explanation, s.now())
			if err != nil {
				return out, fmt.Errorf("record %s on observation %d: %w", c.Key, o.ID, err)
			}
			out = append(out, EvaluationSummary{
				EvaluationID: id, ObservationID: o.ID,
				CheckKey: c.Key, CheckVersion: c.Version,
				Result: result, Explanation: explanation, Finding: change,
			})
		}
	}
	return out, nil
}
