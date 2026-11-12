// Package githubtest provides a synthetic GitHub API for tests.
package githubtest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"

	"github.com/aelasmar01Lab/control-assurance/internal/github"
)

// Fake is an in-memory stand-in for the GitHub API, for tests. It serves one
// repository whose state a test can change between collections. Everything it
// returns is synthetic.
type Fake struct {
	Server *httptest.Server
	// Repository is the repository served. It defaults to FakeRepository
	// and must be set before the first request.
	Repository string

	mu sync.Mutex
	// Rules are served by the rules-for-a-branch endpoint, PageSize per page.
	rules []github.Rule
	// protected is the branch's "protected" flag.
	protected bool
	// status, when not 200, is returned for every request.
	status int
	header map[string]string
	// pageSize of the rules listing; 0 means everything on one page.
	pageSize int
	// malformed makes the listing endpoints return a body that is not JSON.
	malformed bool
	// alerts are the open Dependabot alerts; alertsDisabled turns them off.
	alerts         []Alert
	alertsDisabled bool
	// files are the paths that exist on the default branch.
	files map[string]bool
	// requests counts the requests served; writes counts those that were
	// not GET or HEAD.
	requests int
	writes   int
}

// Alert is a synthetic Dependabot alert.
type Alert struct {
	Number   int
	Severity string
	Created  string // RFC 3339
}

// FakeToken is the only bearer token a Fake accepts.
const FakeToken = "fake-valid-token"

// FakeRepository is the repository a Fake serves.
const FakeRepository = "lab-org/lab-repo"

// NewFake starts a fake GitHub API. Close its Server when done.
func NewFake() *Fake {
	f := &Fake{status: http.StatusOK, Repository: FakeRepository}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

// Client returns a client pointed at the fake with a valid token.
func (f *Fake) Client() *github.Client {
	return &github.Client{Token: FakeToken, BaseURL: f.Server.URL, HTTP: f.Server.Client()}
}

// SetRules replaces the active rules and sets the branch's protected flag.
func (f *Fake) SetRules(protected bool, rules ...github.Rule) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules, f.protected = rules, protected
}

// SetFailure makes every request return status with the given headers.
// Passing http.StatusOK restores normal behaviour.
func (f *Fake) SetFailure(status int, header map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.header = status, header
}

// SetPageSize paginates the rules listing.
func (f *Fake) SetPageSize(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pageSize = n
}

// SetMalformed makes the rules endpoint return a body that is not JSON.
func (f *Fake) SetMalformed(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.malformed = on
}

// SetAlerts replaces the open Dependabot alerts and turns alerts on.
func (f *Fake) SetAlerts(alerts ...Alert) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alerts, f.alertsDisabled = alerts, false
}

// DisableAlerts makes the alerts endpoint answer as GitHub does when
// Dependabot alerts are turned off for the repository.
func (f *Fake) DisableAlerts() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alertsDisabled = true
}

// SetFiles replaces the paths that exist on the default branch.
func (f *Fake) SetFiles(paths ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files = map[string]bool{}
	for _, p := range paths {
		f.files[p] = true
	}
}

// Requests returns how many requests the fake has served.
func (f *Fake) Requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

// Writes returns how many requests were not reads.
func (f *Fake) Writes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

// PullRequestRule returns a rule requiring the given number of approvals.
func PullRequestRule(approvals int) github.Rule {
	return github.Rule{
		Type:              "pull_request",
		RulesetID:         1,
		RulesetSource:     FakeRepository,
		RulesetSourceType: "Repository",
		Parameters:        json.RawMessage(fmt.Sprintf(`{"required_approving_review_count":%d}`, approvals)),
	}
}

// StatusChecksRule returns a rule requiring the named status checks.
func StatusChecksRule(contexts ...string) github.Rule {
	checks := make([]map[string]string, 0, len(contexts))
	for _, c := range contexts {
		checks = append(checks, map[string]string{"context": c})
	}
	params, _ := json.Marshal(map[string]any{"required_status_checks": checks})
	return github.Rule{
		Type:              "required_status_checks",
		RulesetID:         1,
		RulesetSource:     FakeRepository,
		RulesetSourceType: "Repository",
		Parameters:        params,
	}
}

// FillerRule returns a rule no check cares about, for pagination tests.
func FillerRule(n int) github.Rule {
	return github.Rule{Type: "filler_" + strconv.Itoa(n), RulesetID: int64(100 + n), RulesetSource: FakeRepository, RulesetSourceType: "Repository"}
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		f.writes++
	}

	w.Header().Set("Content-Type", "application/json")
	if f.status != http.StatusOK {
		for k, v := range f.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(`{"message":"synthetic failure"}`))
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+FakeToken {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
		return
	}

	repoPath := "/repos/" + f.Repository
	switch r.URL.Path {
	case repoPath:
		_, _ = w.Write([]byte(`{"default_branch":"main"}`))
	case repoPath + "/branches/main":
		_, _ = fmt.Fprintf(w, `{"protected":%t}`, f.protected)
	case repoPath + "/rules/branches/main":
		if f.malformed {
			_, _ = w.Write([]byte(`<html>not json</html>`))
			return
		}
		f.serveRules(w, r)
	case repoPath + "/dependabot/alerts":
		f.serveAlerts(w, r)
	default:
		if path, ok := strings.CutPrefix(r.URL.Path, repoPath+"/contents/"); ok && f.files[path] {
			body, _ := json.Marshal(map[string]any{"type": "file", "path": path, "sha": strings.Repeat("0", 40), "size": 120})
			_, _ = w.Write(body) //nolint:gosec // a JSON test fixture, never rendered as HTML
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}
}

func (f *Fake) serveAlerts(w http.ResponseWriter, r *http.Request) {
	if f.alertsDisabled {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Dependabot alerts are disabled for this repository.","status":"403"}`))
		return
	}
	if f.malformed {
		_, _ = w.Write([]byte(`<html>not json</html>`))
		return
	}
	alerts := f.alerts
	if f.pageSize > 0 {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		start := min((page-1)*f.pageSize, len(alerts))
		end := min(start+f.pageSize, len(alerts))
		if end < len(alerts) {
			next := fmt.Sprintf("%s%s?page=%d", f.Server.URL, r.URL.Path, page+1)
			w.Header().Set("Link", "<"+next+`>; rel="next"`)
		}
		alerts = alerts[start:end]
	}
	out := make([]map[string]any, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, map[string]any{
			"number": a.Number, "state": "open", "created_at": a.Created,
			"dependency":        map[string]any{"package": map[string]string{"ecosystem": "npm", "name": "synthetic-package"}},
			"security_advisory": map[string]string{"ghsa_id": fmt.Sprintf("GHSA-fake-%04d", a.Number), "severity": a.Severity},
		})
	}
	body, _ := json.Marshal(out)
	_, _ = w.Write(body)
}

func (f *Fake) serveRules(w http.ResponseWriter, r *http.Request) {
	rules := f.rules
	if f.pageSize > 0 {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		start := min((page-1)*f.pageSize, len(rules))
		end := min(start+f.pageSize, len(rules))
		if end < len(rules) {
			next := fmt.Sprintf("%s%s?page=%d", f.Server.URL, r.URL.Path, page+1)
			w.Header().Set("Link", "<"+next+`>; rel="next"`)
		}
		rules = rules[start:end]
	}
	if rules == nil {
		rules = []github.Rule{}
	}
	body, _ := json.Marshal(rules)
	_, _ = w.Write(body)
}
