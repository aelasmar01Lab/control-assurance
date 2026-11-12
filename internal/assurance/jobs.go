package assurance

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/authz"
	"github.com/aelasmar01Lab/control-assurance/internal/aws"
	"github.com/aelasmar01Lab/control-assurance/internal/collect"
	"github.com/aelasmar01Lab/control-assurance/internal/control"
	"github.com/aelasmar01Lab/control-assurance/internal/github"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
)

// Integration is one external source and what is collected from it.
type Integration struct {
	// Provider names the source and the resources' provider.
	Provider string
	// ResourceKind is the kind of resource collected from: a repository
	// or an account.
	ResourceKind string
	// Kinds are the kinds of observation collected from each resource.
	Kinds []string
	// ValidTarget reports whether a string names a resource of this kind.
	ValidTarget func(string) bool
	// TargetForm describes a valid target, for error messages.
	TargetForm string
}

// Integrations are the sources the first release collects from.
var Integrations = []Integration{
	{Provider: "github", ResourceKind: "repository", Kinds: github.Kinds, ValidTarget: github.ValidRepository, TargetForm: "an owner/name repository"},
	{Provider: "aws", ResourceKind: "account", Kinds: aws.Kinds, ValidTarget: aws.ValidAccount, TargetForm: "a twelve-digit account ID"},
}

func integration(provider string) (Integration, bool) {
	for _, i := range Integrations {
		if i.Provider == provider {
			return i, true
		}
	}
	return Integration{}, false
}

// RetryPolicy says how a failed attempt of one error class is retried.
type RetryPolicy struct {
	// MaxAttempts is the most attempts made, counting the first.
	MaxAttempts int
	// Delays are the waits before the second and later attempts. The
	// last one is reused if there are more attempts than delays.
	Delays []time.Duration
	// Why explains the choice.
	Why string
}

// RetryPolicies is the retry behaviour for each error class. A class that
// needs a person to act is never retried automatically: the next scheduled
// collection tries again.
var RetryPolicies = map[collect.Class]RetryPolicy{
	collect.Auth:        {MaxAttempts: 1, Why: "A missing, invalid or expired credential stays that way until someone replaces it."},
	collect.Permission:  {MaxAttempts: 1, Why: "A refusal stays a refusal until someone changes the grant."},
	collect.NotFound:    {MaxAttempts: 1, Why: "The resource is missing or hidden; asking again does not change that."},
	collect.Unexpected:  {MaxAttempts: 1, Why: "The cause is not understood, so repeating the request is not known to be safe or useful."},
	collect.RateLimited: {MaxAttempts: 4, Delays: []time.Duration{15 * time.Minute}, Why: "Wait as long as the source asks, up to an hour, or 15 minutes when it does not say."},
	collect.Network:     {MaxAttempts: 4, Delays: []time.Duration{time.Minute, 5 * time.Minute, 25 * time.Minute}, Why: "Connection failures and timeouts are usually brief."},
	collect.Server:      {MaxAttempts: 4, Delays: []time.Duration{time.Minute, 5 * time.Minute, 25 * time.Minute}, Why: "A fault on the source's side is usually brief."},
	collect.Malformed:   {MaxAttempts: 2, Delays: []time.Duration{5 * time.Minute}, Why: "One more attempt covers a response cut short; a lasting change of format needs a code change."},
	collect.Storage:     {MaxAttempts: 2, Delays: []time.Duration{time.Minute}, Why: "One more attempt covers a brief fault in the evidence store."},
	collect.Interrupted: {MaxAttempts: 3, Delays: []time.Duration{0}, Why: "The worker stopped; the source was not at fault, so the next worker tries at once."},
}

// maxRetryAfter caps how long a source can make a retry wait.
const maxRetryAfter = time.Hour

// NextAttempt says whether a failed attempt is retried, and after how long.
// attempt is the number of the attempt that failed, starting at 1.
func NextAttempt(class collect.Class, attempt int, retryAfter time.Duration) (time.Duration, bool) {
	p, ok := RetryPolicies[class]
	if !ok || attempt >= p.MaxAttempts || len(p.Delays) == 0 {
		return 0, false
	}
	delay := p.Delays[min(attempt-1, len(p.Delays)-1)]
	if class == collect.RateLimited && retryAfter > 0 {
		delay = min(retryAfter, maxRetryAfter)
	}
	return delay, true
}

func (s *Service) runTimeout() time.Duration {
	if s.RunTimeout > 0 {
		return s.RunTimeout
	}
	return 90 * time.Second
}

func (s *Service) lease() time.Duration {
	if s.Lease > 0 {
		return s.Lease
	}
	return 5 * time.Minute
}

// QueuedRun is one job's unfinished attempt after a request.
type QueuedRun struct {
	RunID  int64
	Kind   string
	Target string
	// Queued is false when the job already had an unfinished attempt, so
	// nothing was added.
	Queued bool
}

// RequestCollection queues collection of the given kinds from each target,
// registering the target as an in-scope resource if it is new. With no kinds
// it queues every kind the integration collects. A job that already has an
// unfinished attempt is not queued twice.
func (s *Service) RequestCollection(ctx context.Context, actor authz.Actor, provider string, targets, kinds []string) ([]QueuedRun, error) {
	if err := authz.Can(actor, authz.RunCollection, authz.Resource{}); err != nil {
		return nil, err
	}
	in, ok := integration(provider)
	if !ok {
		return nil, invalid("%q is not an integration", provider)
	}
	if len(kinds) == 0 {
		kinds = in.Kinds
	}
	for _, k := range kinds {
		known := false
		for _, have := range in.Kinds {
			known = known || have == k
		}
		if !known {
			return nil, invalid("%s does not collect %q", provider, k)
		}
	}
	for _, t := range targets {
		if !in.ValidTarget(t) {
			return nil, invalid("%q is not %s", t, in.TargetForm)
		}
	}
	var out []QueuedRun
	for _, t := range targets {
		resourceID, err := s.Store.UpsertResource(ctx, in.Provider, in.ResourceKind, t, actor.Username, s.now())
		if err != nil {
			return out, fmt.Errorf("record resource %s: %w", t, err)
		}
		queued, err := s.enqueue(ctx, actor, in.Provider, store.Resource{ID: resourceID, ExternalID: t}, kinds, "manual")
		out = append(out, queued...)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// RequestAll queues every kind of collection for every in-scope resource.
func (s *Service) RequestAll(ctx context.Context, actor authz.Actor) ([]QueuedRun, error) {
	return s.requestKnown(ctx, actor, "manual", 0)
}

// ScheduleDue queues collection for every job whose newest attempt was
// queued at least interval ago, or that has never been attempted.
func (s *Service) ScheduleDue(ctx context.Context, actor authz.Actor, interval time.Duration) ([]QueuedRun, error) {
	return s.requestKnown(ctx, actor, "schedule", interval)
}

func (s *Service) requestKnown(ctx context.Context, actor authz.Actor, cause string, interval time.Duration) ([]QueuedRun, error) {
	if err := authz.Can(actor, authz.RunCollection, authz.Resource{}); err != nil {
		return nil, err
	}
	resources, err := s.Store.InScopeResources(ctx)
	if err != nil {
		return nil, err
	}
	last, err := s.Store.LastQueued(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	var out []QueuedRun
	for _, r := range resources {
		in, ok := integration(r.Provider)
		if !ok || in.ResourceKind != r.Kind {
			continue
		}
		var due []string
		for _, k := range in.Kinds {
			if at, attempted := last[k][r.ID]; cause == "manual" || !attempted || !at.Add(interval).After(now) {
				due = append(due, k)
			}
		}
		queued, err := s.enqueue(ctx, actor, in.Provider, r, due, cause)
		out = append(out, queued...)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func (s *Service) enqueue(ctx context.Context, actor authz.Actor, provider string, r store.Resource, kinds []string, cause string) ([]QueuedRun, error) {
	now := s.now()
	var out []QueuedRun
	for _, k := range kinds {
		id, queued, err := s.Store.EnqueueRun(ctx, actor.UserID, store.NewRun{
			Integration: provider, Kind: k, ResourceID: r.ID, Cause: cause, RunAfter: now,
		}, now)
		if err != nil {
			return out, fmt.Errorf("queue %s for %s: %w", k, r.ExternalID, err)
		}
		out = append(out, QueuedRun{RunID: id, Kind: k, Target: r.ExternalID, Queued: queued})
	}
	return out, nil
}

// RunSummary describes one finished collection attempt.
type RunSummary struct {
	RunID   int64
	Kind    string
	Target  string
	Attempt int

	Succeeded         bool
	InventoryComplete bool
	ObservationID     int64
	PayloadSHA256     string

	ErrorClass  string
	ErrorDetail string
	// RetryRunID and RetryAt describe the next attempt, when one was queued.
	RetryRunID int64
	RetryAt    time.Time
}

// Work runs every attempt that is due, on the given number of workers, and
// returns when none is left. It first recovers attempts abandoned by a
// worker that stopped. A failed attempt is recorded with its error class and
// produces no observation; it is retried according to RetryPolicies. The
// returned error is for failures to record, not failures to collect.
func (s *Service) Work(ctx context.Context, actor authz.Actor, workers int) ([]RunSummary, error) {
	if err := authz.Can(actor, authz.RunCollection, authz.Resource{}); err != nil {
		return nil, err
	}
	if err := s.recoverExpired(ctx); err != nil {
		return nil, fmt.Errorf("recover abandoned runs: %w", err)
	}
	kinds := make([]string, 0, len(s.Collectors))
	for k := range s.Collectors {
		kinds = append(kinds, k)
	}
	if len(kinds) == 0 {
		return nil, nil
	}
	sort.Strings(kinds)

	var (
		mu       sync.Mutex
		out      []RunSummary
		firstErr error
		wg       sync.WaitGroup
	)
	for range max(workers, 1) {
		wg.Go(func() {
			for ctx.Err() == nil {
				now := s.now()
				run, err := s.Store.ClaimRun(ctx, kinds, now, now.Add(s.lease()))
				if err == nil && run == nil {
					return
				}
				var sum RunSummary
				if err == nil {
					sum, err = s.execute(ctx, actor, run)
				}
				mu.Lock()
				if run != nil {
					out = append(out, sum)
				}
				if err != nil && firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				if err != nil {
					return
				}
			}
		})
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].RunID < out[j].RunID })
	return out, firstErr
}

// recoverExpired fails every running attempt whose lease has passed and
// queues its retry. The attempt's worker stopped without finishing it.
func (s *Service) recoverExpired(ctx context.Context) error {
	now := s.now()
	expired, err := s.Store.ExpiredRuns(ctx, now)
	if err != nil {
		return err
	}
	for _, run := range expired {
		var retryAt *time.Time
		if delay, ok := NextAttempt(collect.Interrupted, run.Attempt, 0); ok {
			at := now.Add(delay)
			retryAt = &at
		}
		_, err := s.Store.FailRun(ctx, run.ID, now, string(collect.Interrupted),
			"the worker stopped before the run finished, and its lease expired", retryAt)
		// Another worker may have recovered it first.
		if err != nil && !errors.Is(err, store.ErrRunNotRunning) {
			return err
		}
	}
	return nil
}

// execute makes one claimed attempt and records how it ended.
func (s *Service) execute(ctx context.Context, actor authz.Actor, run *store.ClaimedRun) (RunSummary, error) {
	sum := RunSummary{RunID: run.ID, Kind: run.Kind, Target: run.Target, Attempt: run.Attempt}
	if err := s.Store.LogAction(ctx, actor.UserID, "collection.run", "collection_run", run.ID,
		fmt.Sprintf("%s %s, attempt %d", run.Kind, run.Target, run.Attempt), s.now()); err != nil {
		return sum, fmt.Errorf("log run %d: %w", run.ID, err)
	}

	obs, complete, failure := s.collect(ctx, run)
	// Record the ending even if the worker is being stopped.
	record := context.WithoutCancel(ctx)
	if failure == nil {
		obsID, err := s.Store.CompleteRun(record, run.ID, s.now(), complete, obs)
		if err != nil {
			return sum, fmt.Errorf("record observation for run %d: %w", run.ID, err)
		}
		sum.Succeeded, sum.InventoryComplete = true, complete
		sum.ObservationID, sum.PayloadSHA256 = obsID, obs.PayloadSHA256
		return sum, nil
	}

	now := s.now()
	var retryAt *time.Time
	if delay, ok := NextAttempt(failure.Class, run.Attempt, failure.RetryAfter); ok {
		at := now.Add(delay)
		retryAt = &at
	}
	retryID, err := s.Store.FailRun(record, run.ID, now, string(failure.Class), failure.Detail, retryAt)
	if err != nil {
		return sum, fmt.Errorf("record failed run %d: %w", run.ID, err)
	}
	sum.ErrorClass, sum.ErrorDetail = string(failure.Class), failure.Detail
	if retryAt != nil {
		sum.RetryRunID, sum.RetryAt = retryID, *retryAt
	}
	return sum, nil
}

// collect reads and stores the evidence for one attempt. A non-nil error
// means the attempt failed; it is always classified.
func (s *Service) collect(ctx context.Context, run *store.ClaimedRun) (store.NewObservation, bool, *collect.Error) {
	var obs store.NewObservation
	collector, ok := s.Collectors[run.Kind]
	if !ok {
		return obs, false, &collect.Error{Class: collect.Unexpected, Detail: "this worker has no collector for " + run.Kind}
	}
	runCtx, cancel := context.WithTimeout(ctx, s.runTimeout())
	defer cancel()
	snapshot, err := collector(runCtx, run.Target)
	if err != nil {
		var ce *collect.Error
		switch {
		case ctx.Err() != nil:
			return obs, false, &collect.Error{Class: collect.Interrupted, Detail: "the worker was stopped during the run"}
		case errors.As(err, &ce):
			return obs, false, ce
		case errors.Is(err, context.DeadlineExceeded):
			return obs, false, &collect.Error{Class: collect.Network, Detail: fmt.Sprintf("the run did not finish within %s", s.runTimeout())}
		default:
			return obs, false, &collect.Error{Class: collect.Unexpected, Detail: "the collector returned an unclassified error"}
		}
	}
	if snapshot == nil || snapshot.Kind != run.Kind || len(snapshot.Payload) == 0 {
		return obs, false, &collect.Error{Class: collect.Malformed, Detail: "the collector returned no evidence of the kind asked for"}
	}
	collectedAt := s.now()

	sha, ref, err := s.Evidence.Put(ctx, snapshot.Payload)
	if err != nil {
		return obs, false, &collect.Error{Class: collect.Storage, Detail: "evidence could not be written to the evidence store"}
	}
	return store.NewObservation{
		ResourceID:        run.ResourceID,
		Kind:              snapshot.Kind,
		CollectedAt:       collectedAt,
		SourceTimestamp:   snapshot.SourceTimestamp,
		PayloadSHA256:     sha,
		PayloadSize:       int64(len(snapshot.Payload)),
		PayloadMediaType:  "application/json",
		PayloadStorageRef: ref,
		NormalizerVersion: snapshot.Normalizer,
	}, snapshot.Complete, nil
}

// JobStatus is the state of one job on the integration health page.
type JobStatus string

// The job statuses.
const (
	JobHealthy  JobStatus = "healthy"  // the newest finished attempt succeeded
	JobRetrying JobStatus = "retrying" // the newest finished attempt failed and a retry is waiting
	JobFailing  JobStatus = "failing"  // the newest finished attempt failed and nothing more is queued
	JobPending  JobStatus = "pending"  // no attempt has finished yet
)

// JobView is one job's health.
type JobView struct {
	store.JobHealth
	Status JobStatus
	// Stale is true when there is no evidence, or the newest evidence is
	// older than the freshness window. Failed attempts never reset it.
	Stale bool
	// EvidenceAgeHours is the age of the newest evidence, or -1 for none.
	EvidenceAgeHours int
}

// Health is the integration health page.
type Health struct {
	Jobs []JobView
	Runs []store.RunRow
	// Problems counts jobs that are failing, retrying or stale.
	Problems int
	// FreshnessHours is the window after which evidence is stale.
	FreshnessHours int
	// MayCollect says whether the viewer may queue collection.
	MayCollect bool
}

// Health returns the state of every job and the most recent attempts. A
// problem here is a problem with collection; it is never a check result.
func (s *Service) Health(ctx context.Context, actor authz.Actor) (*Health, error) {
	if err := authz.Can(actor, authz.View, authz.Resource{}); err != nil {
		return nil, err
	}
	jobs, problems, err := s.jobs(ctx)
	if err != nil {
		return nil, err
	}
	runs, err := s.Store.Runs(ctx, 50)
	if err != nil {
		return nil, err
	}
	return &Health{
		Jobs: jobs, Runs: runs, Problems: problems,
		FreshnessHours: int(control.AutomatedFreshness.Hours()),
		MayCollect:     authz.Can(actor, authz.RunCollection, authz.Resource{}) == nil,
	}, nil
}

func (s *Service) jobs(ctx context.Context) ([]JobView, int, error) {
	rows, err := s.Store.JobsHealth(ctx)
	if err != nil {
		return nil, 0, err
	}
	now := s.now()
	problems := 0
	out := make([]JobView, 0, len(rows))
	for _, j := range rows {
		v := JobView{JobHealth: j, EvidenceAgeHours: -1, Stale: true}
		switch {
		case j.LastOutcome == nil:
			v.Status = JobPending
		case *j.LastOutcome == "succeeded":
			v.Status = JobHealthy
		case j.PendingID != nil:
			v.Status = JobRetrying
		default:
			v.Status = JobFailing
		}
		if j.LastSuccessAt != nil {
			age := now.Sub(*j.LastSuccessAt)
			v.EvidenceAgeHours = int(age.Hours())
			v.Stale = age > control.AutomatedFreshness
		}
		if v.Status == JobFailing || v.Status == JobRetrying || (v.Stale && v.Status != JobPending) {
			problems++
		}
		out = append(out, v)
	}
	return out, problems, nil
}
