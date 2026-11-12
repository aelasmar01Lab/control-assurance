package github_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aelasmar01Lab/control-assurance/internal/github"
	"github.com/aelasmar01Lab/control-assurance/internal/github/githubtest"
)

func TestCollectBranchRules(t *testing.T) {
	ctx := context.Background()
	f := githubtest.NewFake()
	defer f.Server.Close()
	// Served out of order, to prove the payload is sorted.
	f.SetRules(true, githubtest.StatusChecksRule("ci"), githubtest.PullRequestRule(1))

	got, err := f.Client().CollectBranchRules(ctx, githubtest.FakeRepository)
	if err != nil {
		t.Fatalf("CollectBranchRules: %v", err)
	}
	if !got.RulesComplete || !got.BranchProtected || got.DefaultBranch != "main" {
		t.Errorf("unexpected snapshot: %+v", got)
	}
	if len(got.Rules) != 2 || got.Rules[0].Type != "pull_request" {
		t.Errorf("rules = %+v, want pull_request first", got.Rules)
	}

	payload, err := got.Payload()
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"repository":"lab-org/lab-repo","default_branch":"main","branch_protected":true,"rules_complete":true,"rules":[` +
		`{"type":"pull_request","ruleset_id":1,"ruleset_source":"lab-org/lab-repo","ruleset_source_type":"Repository","parameters":{"required_approving_review_count":1}},` +
		`{"type":"required_status_checks","ruleset_id":1,"ruleset_source":"lab-org/lab-repo","ruleset_source_type":"Repository","parameters":{"required_status_checks":[{"context":"ci"}]}}]}`
	if string(payload) != want {
		t.Errorf("payload =\n%s\nwant\n%s", payload, want)
	}

	// The same state collected again yields identical bytes.
	again, err := f.Client().CollectBranchRules(ctx, githubtest.FakeRepository)
	if err != nil {
		t.Fatal(err)
	}
	payload2, _ := again.Payload()
	if string(payload) != string(payload2) {
		t.Error("two collections of the same state produced different payloads")
	}
}

func TestCollectBranchRulesNoRules(t *testing.T) {
	f := githubtest.NewFake()
	defer f.Server.Close()
	got, err := f.Client().CollectBranchRules(context.Background(), githubtest.FakeRepository)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 0 || !got.RulesComplete || got.BranchProtected {
		t.Errorf("unexpected snapshot: %+v", got)
	}
}

func TestPagination(t *testing.T) {
	ctx := context.Background()
	f := githubtest.NewFake()
	defer f.Server.Close()
	f.SetRules(true, githubtest.FillerRule(1), githubtest.FillerRule(2), githubtest.FillerRule(3), githubtest.FillerRule(4), githubtest.PullRequestRule(1))
	f.SetPageSize(2)

	// Every page read: complete.
	got, err := f.Client().CollectBranchRules(ctx, githubtest.FakeRepository)
	if err != nil {
		t.Fatal(err)
	}
	if !got.RulesComplete || len(got.Rules) != 5 {
		t.Errorf("complete = %v, rules = %d; want true, 5", got.RulesComplete, len(got.Rules))
	}

	// Page cap reached with more pages remaining: reported as incomplete.
	c := f.Client()
	c.MaxPages = 2
	got, err = c.CollectBranchRules(ctx, githubtest.FakeRepository)
	if err != nil {
		t.Fatal(err)
	}
	if got.RulesComplete || len(got.Rules) != 4 {
		t.Errorf("complete = %v, rules = %d; want false, 4", got.RulesComplete, len(got.Rules))
	}
}

func TestErrorClasses(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(f *githubtest.Fake, c *github.Client)
		repo   string
		wantCl github.ErrorClass
	}{
		{"invalid token", func(_ *githubtest.Fake, c *github.Client) { c.Token = "expired" }, githubtest.FakeRepository, github.ClassAuth},
		{"no token", func(_ *githubtest.Fake, c *github.Client) { c.Token = "" }, githubtest.FakeRepository, github.ClassAuth},
		{"forbidden", func(f *githubtest.Fake, _ *github.Client) { f.SetFailure(http.StatusForbidden, nil) }, githubtest.FakeRepository, github.ClassPermission},
		{"primary rate limit", func(f *githubtest.Fake, _ *github.Client) {
			f.SetFailure(http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"})
		}, githubtest.FakeRepository, github.ClassRateLimited},
		{"secondary rate limit", func(f *githubtest.Fake, _ *github.Client) {
			f.SetFailure(http.StatusTooManyRequests, map[string]string{"Retry-After": "60"})
		}, githubtest.FakeRepository, github.ClassRateLimited},
		{"server error", func(f *githubtest.Fake, _ *github.Client) { f.SetFailure(http.StatusBadGateway, nil) }, githubtest.FakeRepository, github.ClassServer},
		{"unknown repository", func(_ *githubtest.Fake, _ *github.Client) {}, "lab-org/missing", github.ClassNotFound},
		{"not a repository name", func(_ *githubtest.Fake, _ *github.Client) {}, "../etc", github.ClassNotFound},
		{"malformed body", func(f *githubtest.Fake, _ *github.Client) { f.SetMalformed(true) }, githubtest.FakeRepository, github.ClassMalformed},
		{"server unreachable", func(f *githubtest.Fake, _ *github.Client) { f.Server.Close() }, githubtest.FakeRepository, github.ClassNetwork},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := githubtest.NewFake()
			defer f.Server.Close()
			f.SetRules(true, githubtest.PullRequestRule(1))
			c := f.Client()
			tt.setup(f, c)

			got, err := c.CollectBranchRules(context.Background(), tt.repo)
			if got != nil {
				t.Errorf("a failed collection returned a snapshot: %+v", got)
			}
			var ce *github.Error
			if !errors.As(err, &ce) {
				t.Fatalf("err = %v, want *Error", err)
			}
			if ce.Class != tt.wantCl {
				t.Errorf("class = %s, want %s (%s)", ce.Class, tt.wantCl, ce.Detail)
			}
		})
	}
}

func TestErrorsNeverContainTheToken(t *testing.T) {
	f := githubtest.NewFake()
	f.Server.Close() // force a transport error
	c := f.Client()
	c.Token = "super-secret-token"
	_, err := c.CollectBranchRules(context.Background(), githubtest.FakeRepository)
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := err.Error(); len(got) == 0 || strings.Contains(got, "super-secret-token") {
		t.Errorf("error leaks the token: %s", got)
	}
}
