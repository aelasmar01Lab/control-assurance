// Package assurance runs the collect and evaluate steps of the loop. The CLI,
// and later the scheduler and web handlers, all go through it.
package assurance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/authz"
	"github.com/aelasmar01Lab/control-assurance/internal/check"
	"github.com/aelasmar01Lab/control-assurance/internal/evidence"
	"github.com/aelasmar01Lab/control-assurance/internal/github"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
)

// classStorage is the error class for a run whose evidence was read from the
// source but could not be saved.
const classStorage = "storage"

// BranchRulesCollector reads the rules on a repository's default branch.
type BranchRulesCollector interface {
	CollectBranchRules(ctx context.Context, repo string) (*github.BranchRules, error)
}

// Service ties the collectors, evidence store, checks and database together.
type Service struct {
	Store    *store.Store
	Evidence evidence.Store
	GitHub   BranchRulesCollector
	// Now is the clock; it defaults to time.Now.
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// RunSummary describes one collection attempt.
type RunSummary struct {
	Repository        string
	RunID             int64
	Succeeded         bool
	ErrorClass        string
	ErrorDetail       string
	InventoryComplete bool
	ObservationID     int64
	PayloadSHA256     string
}

// CollectGitHub makes one collection attempt per repository and records each
// as a run. A failed attempt is recorded with its error class and produces no
// observation. The returned error is for failures to record, not to collect.
func (s *Service) CollectGitHub(ctx context.Context, actor authz.Actor, repos []string) ([]RunSummary, error) {
	if err := authz.Can(actor, authz.RunCollection, authz.Resource{}); err != nil {
		return nil, err
	}
	var out []RunSummary
	for _, repo := range repos {
		if !github.ValidRepository(repo) {
			return out, fmt.Errorf("%q is not an owner/name repository", repo)
		}
		resourceID, err := s.Store.UpsertResource(ctx, "github", "repository", repo, actor.Username)
		if err != nil {
			return out, fmt.Errorf("record resource %s: %w", repo, err)
		}
		runID, err := s.Store.StartRun(ctx, "github", resourceID, s.now())
		if err != nil {
			return out, fmt.Errorf("start run for %s: %w", repo, err)
		}
		sum := RunSummary{Repository: repo, RunID: runID}
		if err := s.Store.LogAction(ctx, actor.UserID, "collection.run", "collection_run", runID, "github "+repo, s.now()); err != nil {
			return out, fmt.Errorf("log run for %s: %w", repo, err)
		}

		obs, complete, class, detail := s.collectBranchRules(ctx, repo, resourceID)
		if class != "" {
			if err := s.Store.FailRun(ctx, runID, s.now(), class, detail); err != nil {
				return out, fmt.Errorf("record failed run for %s: %w", repo, err)
			}
			sum.ErrorClass, sum.ErrorDetail = class, detail
			out = append(out, sum)
			continue
		}

		obsID, err := s.Store.CompleteRun(ctx, runID, s.now(), complete, obs)
		if err != nil {
			return out, fmt.Errorf("record observation for %s: %w", repo, err)
		}
		sum.Succeeded, sum.InventoryComplete = true, complete
		sum.ObservationID, sum.PayloadSHA256 = obsID, obs.PayloadSHA256
		out = append(out, sum)
	}
	return out, nil
}

// collectBranchRules reads and stores the evidence for one repository. A
// non-empty class means the attempt failed.
func (s *Service) collectBranchRules(ctx context.Context, repo string, resourceID int64) (obs store.NewObservation, complete bool, class, detail string) {
	snapshot, err := s.GitHub.CollectBranchRules(ctx, repo)
	if err != nil {
		var ce *github.Error
		if errors.As(err, &ce) {
			return obs, false, string(ce.Class), ce.Detail
		}
		return obs, false, string(github.ClassUnexpected), "collector returned an unclassified error"
	}
	collectedAt := s.now()

	payload, err := snapshot.Payload()
	if err != nil {
		return obs, false, classStorage, "evidence could not be encoded"
	}
	sha, ref, err := s.Evidence.Put(ctx, payload)
	if err != nil {
		return obs, false, classStorage, "evidence could not be written to the evidence store"
	}
	return store.NewObservation{
		ResourceID:        resourceID,
		Kind:              github.BranchRulesKind,
		CollectedAt:       collectedAt,
		PayloadSHA256:     sha,
		PayloadSize:       int64(len(payload)),
		PayloadMediaType:  "application/json",
		PayloadStorageRef: ref,
		NormalizerVersion: github.BranchRulesNormalizer,
	}, snapshot.RulesComplete, "", ""
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

// Evaluate applies every registered check to each observation it has not
// yet evaluated, oldest first. Running it again with nothing new does nothing.
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
	for _, c := range check.Automated() {
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
			result, explanation, err := c.Eval(payload)
			if err != nil {
				return out, fmt.Errorf("%s on observation %d: %w", c.Key, o.ID, err)
			}
			id, change, err := s.Store.RecordEvaluation(ctx, o, c, result, explanation)
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
