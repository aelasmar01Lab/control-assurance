// Package demo seeds a database with a labelled synthetic history: the full
// loop from a failing check to a verified fix, played out against synthetic
// sources. Nothing in it touches GitHub or AWS.
package demo

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/auth"
	"github.com/aelasmar01Lab/control-assurance/internal/authz"
	"github.com/aelasmar01Lab/control-assurance/internal/aws"
	"github.com/aelasmar01Lab/control-assurance/internal/aws/awstest"
	"github.com/aelasmar01Lab/control-assurance/internal/github/githubtest"
	"github.com/aelasmar01Lab/control-assurance/internal/pack"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
	"github.com/aelasmar01Lab/control-assurance/packs"
)

// Repository and Account are the synthetic resources the demo collects from.
const (
	Repository = "synthetic-org/demo-service"
	Account    = awstest.FakeAccount
)

// Days is how far back the seeded history starts.
const Days = 12

// Organization is the key of the fictional company the demo shows; its
// scope is scope/demo.yaml.
const Organization = "demo"

// Password returns the demo password for a username. Demo passwords are
// published: the demo holds only synthetic data and listens on loopback.
func Password(username string) string { return "demo-" + username + "-password" }

// Users are the demo accounts, in the order they are listed.
var Users = []string{"operator", "control-owner", "reviewer", "auditor"}

// ErrNotEmpty means the database already holds data that the demo did not put there.
var ErrNotEmpty = errors.New("the database holds data that is not the demo's; the demo needs a database of its own")

// Seeded reports whether the database already holds the demo, and returns
// ErrNotEmpty if it holds anything else.
func Seeded(ctx context.Context, st *store.Store) (bool, error) {
	resources, err := st.InScopeResources(ctx)
	if err != nil {
		return false, err
	}
	users, err := st.Users(ctx)
	if err != nil {
		return false, err
	}
	if len(resources) == 0 && len(users) == 0 {
		return false, nil
	}
	for _, r := range resources {
		if r.ExternalID != Repository && r.ExternalID != Account {
			return false, ErrNotEmpty
		}
	}
	if len(resources) != 2 {
		return false, ErrNotEmpty
	}
	return true, nil
}

// Step is one thing the seeded history did, for the caller to print.
type Step struct {
	At   time.Time
	Text string
}

// Seed plays out the demo history, ending one hour before now. svc must
// have a store and an evidence store; its clock and collectors are replaced
// for the duration and restored afterwards.
func Seed(ctx context.Context, svc *assurance.Service, now time.Time) ([]Step, error) {
	clock := now.UTC().Truncate(time.Hour).Add(-Days * 24 * time.Hour)
	savedNow, savedCollectors := svc.Now, svc.Collectors
	defer func() { svc.Now, svc.Collectors = savedNow, savedCollectors }()
	svc.Now = func() time.Time { return clock }

	gh := githubtest.NewFake()
	defer gh.Server.Close()
	gh.Repository = Repository
	client := gh.Client()
	account := awstest.New(clock)
	collectors := client.Collectors()
	maps.Copy(collectors, (&aws.Collector{API: account, Sleep: func(context.Context, time.Duration) error { return nil }}).Collectors())
	svc.Collectors = collectors

	var steps []Step
	say := func(format string, args ...any) { steps = append(steps, Step{clock, fmt.Sprintf(format, args...)}) }

	// Accounts, with published demo passwords.
	if _, err := svc.SeedLabUsers(ctx); err != nil {
		return nil, err
	}
	actors := map[string]authz.Actor{}
	for _, name := range Users {
		hash, err := auth.HashPassword(Password(name))
		if err != nil {
			return nil, err
		}
		if err := svc.Store.SetPassword(ctx, name, hash); err != nil {
			return nil, err
		}
		if actors[name], err = svc.ActorByUsername(ctx, name); err != nil {
			return nil, err
		}
	}
	operator, owner, reviewer := actors["operator"], actors["control-owner"], actors["reviewer"]

	all, err := pack.LoadFS(packs.FS)
	if err != nil {
		return nil, err
	}
	if _, err := svc.LoadCatalog(ctx, operator, all); err != nil {
		return nil, err
	}
	// Record the controls as they are worded now, so the history that
	// follows can say which wording was in force.
	if _, err := svc.LoadContent(ctx, operator); err != nil {
		return nil, err
	}

	// collect gathers everything and evaluates it. The AWS report is
	// always fresh and its credentials in recent use.
	collect := func() error {
		recent := clock.Add(-6 * time.Hour).Format(time.RFC3339)
		account.Set(func(f *awstest.Fake) {
			f.ReportGenerated = clock.Add(-20 * time.Minute)
			f.Users = []awstest.User{
				{Name: "synthetic-admin", PasswordEnabled: true, MFA: true, PasswordLastUsed: recent},
				{Name: "synthetic-deployer", Key1Active: true, Key1LastUsed: recent, Key1LastRotated: recent},
			}
		})
		if _, err := svc.RequestCollection(ctx, operator, "github", []string{Repository}, nil); err != nil {
			return err
		}
		if _, err := svc.RequestCollection(ctx, operator, "aws", []string{Account}, nil); err != nil {
			return err
		}
		if _, err := svc.Work(ctx, operator, 1); err != nil {
			return err
		}
		_, err := svc.Evaluate(ctx, operator)
		return err
	}
	finding := func(checkKey string) (int64, error) {
		findings, err := svc.Store.Findings(ctx)
		if err != nil {
			return 0, err
		}
		for _, f := range findings {
			if f.CheckKey == checkKey && f.Open() {
				return f.ID, nil
			}
		}
		return 0, fmt.Errorf("the demo expected an open %s finding", checkKey)
	}
	day := func(n int, hour int) {
		clock = now.UTC().Truncate(24 * time.Hour).Add(time.Duration(n-Days)*24*time.Hour + time.Duration(hour)*time.Hour)
	}

	// Day 0. The repository has no branch rules and no security policy,
	// and Bedrock invocation logging has no destination.
	day(0, 9)
	gh.SetRules(false)
	gh.SetAlerts()
	gh.SetFiles()
	account.Set(func(f *awstest.Fake) { f.BedrockBucket = "" })
	if err := collect(); err != nil {
		return nil, err
	}
	say("First collection. GH-01, GH-02, GH-04 and AWS-04 fail; each opens a finding.")

	day(0, 11)
	exceptions := map[string]int64{}
	for _, key := range []string{"GH-01", "GH-02", "AWS-04"} {
		id, err := finding(key)
		if err != nil {
			return nil, err
		}
		note := "Branch ruleset is being rolled out to this repository this week."
		justification := "The ruleset rollout is scheduled; the repository has one maintainer until then."
		expires := clock.Add(10 * 24 * time.Hour)
		if key == "AWS-04" {
			note = "Waiting on a log bucket from the platform team."
			justification = "No model is invoked in this account yet."
			expires = clock.Add(5 * 24 * time.Hour) // this one will lapse
		}
		if _, err := svc.AddRemediationNote(ctx, owner, id, note); err != nil {
			return nil, err
		}
		if exceptions[key], err = svc.RequestException(ctx, owner, id, justification, expires); err != nil {
			return nil, err
		}
	}
	say("The control owner notes remediation plans and requests three exceptions. Nothing changes state yet.")

	// Day 1. Decisions by someone other than the requester.
	day(1, 10)
	for _, key := range []string{"GH-01", "GH-02", "AWS-04"} {
		if err := svc.DecideException(ctx, reviewer, exceptions[key], true, "Accepted for the stated period."); err != nil {
			return nil, err
		}
	}
	say("The reviewer approves them. Change management reads accepted risk; the checks still read fail.")
	record := []byte("SYNTHETIC RECORD\n\nRecovery exercise: restored the demo database from the nightly backup to a scratch host.\nResult: restore completed; row counts matched.\nThis file is synthetic demo data.\n")
	submission, err := svc.SubmitEvidence(ctx, owner, assurance.EvidenceUpload{
		ControlKey: "backup-recovery", PeriodStart: clock.AddDate(0, -1, 0), PeriodEnd: clock.AddDate(0, 0, -1),
		Filename: "recovery-exercise.txt", Note: "Quarterly restore test.", Data: record,
	})
	if err != nil {
		return nil, err
	}
	day(1, 15)
	if err := svc.ReviewEvidence(ctx, reviewer, submission, true, "Record is dated and describes a completed restore."); err != nil {
		return nil, err
	}
	say("Manual evidence for backup and recovery is submitted by the owner and accepted by the reviewer.")

	// Day 2. The GitHub credential stops working: a collection failure,
	// not a result.
	day(2, 9)
	client.Token = "expired-token"
	if err := collect(); err != nil {
		return nil, err
	}
	client.Token = githubtest.FakeToken
	say("The GitHub token is rejected. Three runs fail with class auth; no result changes.")

	// Day 3. A brief outage: the first attempt fails, the retry succeeds.
	day(3, 9)
	gh.SetFailure(http.StatusServiceUnavailable, nil)
	if err := collect(); err != nil {
		return nil, err
	}
	gh.SetFailure(http.StatusOK, nil)
	clock = clock.Add(2 * time.Minute)
	if err := collect(); err != nil {
		return nil, err
	}
	say("GitHub answers 503. The runs fail with class server and are retried a minute later, successfully.")

	// Day 4. The fix.
	day(4, 9)
	gh.SetRules(true, githubtest.PullRequestRule(1), githubtest.StatusChecksRule("ci"))
	gh.SetFiles("SECURITY.md")
	if err := collect(); err != nil {
		return nil, err
	}
	say("The ruleset and a security policy are in place. GH-01, GH-02 and GH-04 pass and their findings close.")

	// Days 5 to 11. Daily collection. From day 8 Dependabot alerts are
	// turned off, which is not the same as having none.
	for n := 5; n < Days; n++ {
		day(n, 9)
		if n == 8 {
			gh.DisableAlerts()
			say("Dependabot alerts are turned off on the repository. GH-03 reads not evaluated, not pass.")
		}
		if err := collect(); err != nil {
			return nil, err
		}
	}
	// One last collection an hour ago, so nothing is stale on arrival.
	clock = now.UTC().Add(-time.Hour)
	if err := collect(); err != nil {
		return nil, err
	}
	say("Latest collection. The AWS-04 exception lapsed on day 5, so AI usage logging needs attention again.")
	return steps, nil
}
