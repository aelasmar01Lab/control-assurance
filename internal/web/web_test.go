package web_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/evidence"
	"github.com/aelasmar01Lab/control-assurance/internal/github"
	"github.com/aelasmar01Lab/control-assurance/internal/github/githubtest"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
	"github.com/aelasmar01Lab/control-assurance/internal/testdb"
	"github.com/aelasmar01Lab/control-assurance/internal/web"
)

// site is the web interface running against a private database schema, a
// temporary evidence store and a synthetic GitHub.
type site struct {
	t         *testing.T
	svc       *assurance.Service
	fake      *githubtest.Fake
	url       string
	passwords map[string]string
}

func newSite(t *testing.T) *site {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.New(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	ev, err := evidence.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fake := githubtest.NewFake()
	t.Cleanup(fake.Server.Close)
	svc := &assurance.Service{Store: st, Evidence: ev, Collectors: fake.Client().Collectors()}

	users, err := svc.SeedLabUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s := &site{t: t, svc: svc, fake: fake, passwords: map[string]string{}}
	for _, u := range users {
		s.passwords[u.Username] = u.Password
	}
	srv := httptest.NewServer(web.Handler(svc, web.Options{}))
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

// failing collects and evaluates a branch with no rules, as the operator.
func (s *site) failing() {
	s.t.Helper()
	ctx := context.Background()
	op, err := s.svc.ActorByUsername(ctx, "operator")
	if err != nil {
		s.t.Fatal(err)
	}
	s.fake.SetRules(false)
	if _, err := s.svc.RequestCollection(ctx, op, "github", []string{githubtest.FakeRepository}, []string{github.BranchRulesKind}); err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.svc.Work(ctx, op, 1); err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.svc.Evaluate(ctx, op); err != nil {
		s.t.Fatal(err)
	}
}

// browser is one user's browser: a cookie jar, and requests that carry the
// headers a real browser sends for a same-origin form post.
type browser struct {
	t      *testing.T
	site   *site
	client *http.Client
}

func (s *site) browser() *browser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		s.t.Fatal(err)
	}
	return &browser{t: s.t, site: s, client: &http.Client{Jar: jar}}
}

// signedIn returns a browser signed in as username.
func (s *site) signedIn(username string) *browser {
	s.t.Helper()
	b := s.browser()
	status, body := b.post("/login", url.Values{"username": {username}, "password": {s.passwords[username]}})
	if status != http.StatusOK || !strings.Contains(body, "Sign out") {
		s.t.Fatalf("sign in as %s: status %d", username, status)
	}
	return b
}

func (b *browser) do(req *http.Request) (int, string) {
	b.t.Helper()
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		b.t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func (b *browser) get(path string) (int, string) {
	b.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, b.site.url+path, nil)
	return b.do(req)
}

func (b *browser) post(path string, form url.Values) (int, string) {
	b.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, b.site.url+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	return b.do(req)
}

var formAction = regexp.MustCompile(`action="(/[a-z]+/\d+/[a-z]+)"`)

// actions returns the form actions on a page that end with suffix.
func actions(body, suffix string) []string {
	var out []string
	for _, m := range formAction.FindAllStringSubmatch(body, -1) {
		if strings.HasSuffix(m[1], suffix) {
			out = append(out, m[1])
		}
	}
	return out
}

func TestSignInIsRequired(t *testing.T) {
	s := newSite(t)
	b := s.browser()
	for _, path := range []string{"/", "/findings", "/evidence", "/log", "/export.json", "/evidence/1/file"} {
		status, body := b.get(path)
		if status != http.StatusOK || !strings.Contains(body, `action="/login"`) {
			t.Errorf("GET %s signed out: status %d, want the sign-in page", path, status)
		}
	}
	// A signed-out post changes nothing and lands on the sign-in page.
	if _, body := b.post("/findings/1/notes", url.Values{"body": {"x"}}); !strings.Contains(body, `action="/login"`) {
		t.Error("a signed-out post did not lead to the sign-in page")
	}
}

func TestSignInAndOut(t *testing.T) {
	s := newSite(t)
	b := s.browser()

	status, body := b.post("/login", url.Values{"username": {"auditor"}, "password": {"wrong-password-here"}})
	if status != http.StatusUnauthorized || !strings.Contains(body, "incorrect") {
		t.Errorf("wrong password: status %d", status)
	}
	// The same message for an account that does not exist.
	status, body2 := b.post("/login", url.Values{"username": {"nobody"}, "password": {"wrong-password-here"}})
	if status != http.StatusUnauthorized || !strings.Contains(body2, "incorrect") {
		t.Errorf("unknown user: status %d", status)
	}
	if strings.Contains(body, "Sign out") {
		t.Error("a failed sign-in produced a session")
	}

	b = s.signedIn("auditor")
	if status, body := b.get("/"); status != http.StatusOK || !strings.Contains(body, "auditor") {
		t.Errorf("overview after sign-in: status %d", status)
	}
	b.post("/logout", nil)
	if _, body := b.get("/"); !strings.Contains(body, `action="/login"`) {
		t.Error("the session survived sign-out")
	}
}

// The decisions part of the loop, in the browser: the control owner notes
// and requests, the reviewer approves, and the control becomes accepted risk.
func TestDecisionLoopInTheBrowser(t *testing.T) {
	s := newSite(t)
	s.failing()

	owner := s.signedIn("control-owner")
	_, body := owner.get("/")
	if !strings.Contains(body, "needs attention") {
		t.Fatal("overview does not show the control needing attention")
	}

	_, body = owner.get("/findings")
	noteForms, requestForms := actions(body, "/notes"), actions(body, "/exceptions")
	if len(noteForms) != 2 || len(requestForms) != 2 {
		t.Fatalf("owner sees %d note forms and %d request forms, want 2 and 2", len(noteForms), len(requestForms))
	}
	if len(actions(body, "/decision")) != 0 {
		t.Error("the control owner is offered a decision form")
	}

	_, body = owner.post(noteForms[0], url.Values{"body": {"Restoring the ruleset on Friday."}})
	if !strings.Contains(body, "Remediation note added.") || !strings.Contains(body, "Restoring the ruleset on Friday.") {
		t.Error("the remediation note was not saved and shown")
	}
	expires := time.Now().UTC().AddDate(0, 0, 7).Format("2006-01-02")
	for _, form := range requestForms {
		_, body = owner.post(form, url.Values{"justification": {"Ruleset migration."}, "expires": {expires}})
		if !strings.Contains(body, "Exception requested.") {
			t.Fatalf("exception request via %s was not saved", form)
		}
	}
	// A request alone changes nothing.
	if _, body = owner.get("/"); !strings.Contains(body, "needs attention") {
		t.Error("an unapproved request changed the control state")
	}

	// A validation problem is reported and nothing is saved.
	_, body = owner.post(noteForms[0], url.Values{"body": {"   "}})
	if !strings.Contains(body, "Not saved") {
		t.Error("an empty note was not refused with a message")
	}

	reviewer := s.signedIn("reviewer")
	_, body = reviewer.get("/findings")
	decisions := actions(body, "/decision")
	if len(decisions) != 2 {
		t.Fatalf("reviewer sees %d decision forms, want 2", len(decisions))
	}
	if len(actions(body, "/notes")) != 0 {
		t.Error("the reviewer is offered a remediation note form")
	}
	for _, form := range decisions {
		_, body = reviewer.post(form, url.Values{"decision": {"approve"}, "reason": {"Accepted for one week."}})
		if !strings.Contains(body, "Decision recorded.") {
			t.Fatalf("approval via %s was not saved", form)
		}
	}

	_, body = reviewer.get("/")
	if !strings.Contains(body, "accepted risk") {
		t.Error("overview does not show accepted risk after approval")
	}
	// The failing results are still shown as failing.
	if !strings.Contains(body, `<span class="result fail">fail</span>`) {
		t.Error("the failing result is no longer shown")
	}

	_, body = reviewer.get("/log")
	for _, want := range []string{"remediation.noted", "exception.requested", "exception.approved", "control-owner", "reviewer"} {
		if !strings.Contains(body, want) {
			t.Errorf("decision log does not show %s", want)
		}
	}
}

func TestManualEvidenceInTheBrowser(t *testing.T) {
	s := newSite(t)
	owner := s.signedIn("control-owner")

	var buf bytes.Buffer
	form := multipart.NewWriter(&buf)
	_ = form.WriteField("control", "backup-recovery")
	_ = form.WriteField("period_start", time.Now().UTC().AddDate(0, 0, -8).Format("2006-01-02"))
	_ = form.WriteField("period_end", time.Now().UTC().AddDate(0, 0, -7).Format("2006-01-02"))
	_ = form.WriteField("note", "Synthetic record.")
	part, _ := form.CreateFormFile("file", "exercise.html")
	_, _ = part.Write([]byte("<script>alert(1)</script> synthetic recovery record"))
	_ = form.Close()

	req, _ := http.NewRequest(http.MethodPost, s.url+"/evidence", &buf)
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if _, body := owner.do(req); !strings.Contains(body, "Evidence submitted.") {
		t.Fatal("the upload was not saved")
	}
	// The submitter is not offered a review form.
	if _, body := owner.get("/evidence"); len(actions(body, "/review")) != 0 {
		t.Error("the submitter is offered a review form")
	}

	// Uploaded content is only ever served as a download.
	resp, err := owner.client.Get(s.url + "/evidence/1/file")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("evidence Content-Type = %q", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Errorf("evidence Content-Disposition = %q", cd)
	}

	reviewer := s.signedIn("reviewer")
	_, body := reviewer.get("/evidence")
	reviews := actions(body, "/review")
	if len(reviews) != 1 {
		t.Fatalf("reviewer sees %d review forms, want 1", len(reviews))
	}
	if _, body = reviewer.post(reviews[0], url.Values{"decision": {"accept"}, "reason": {"Dated and complete."}}); !strings.Contains(body, "Review recorded.") {
		t.Fatal("the review was not saved")
	}
	if _, body = reviewer.get("/"); !strings.Contains(body, "REC-01: accepted evidence is valid until") {
		t.Error("overview does not show the accepted evidence")
	}
}

// The auditor can read every page and export; every write is refused.
func TestAuditorInTheBrowser(t *testing.T) {
	s := newSite(t)
	s.failing()
	auditor := s.signedIn("auditor")

	for _, path := range []string{"/", "/findings", "/evidence", "/integrations", "/log"} {
		status, body := auditor.get(path)
		if status != http.StatusOK {
			t.Errorf("GET %s = %d", path, status)
		}
		if n := strings.Count(body, "<form"); n != 1 { // sign out only
			t.Errorf("GET %s shows the auditor %d forms, want only sign out", path, n)
		}
		// The product never calls anything compliant.
		if strings.Contains(strings.ToLower(body), "compliant") {
			t.Errorf(`GET %s uses the word "compliant"`, path)
		}
	}

	status, body := auditor.get("/export.json")
	var export struct {
		GeneratedBy string
		Findings    []json.RawMessage
		Controls    []json.RawMessage
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &export) != nil {
		t.Fatalf("export: status %d", status)
	}
	if export.GeneratedBy != "auditor" || len(export.Findings) != 2 || len(export.Controls) == 0 {
		t.Errorf("export = %+v", export)
	}

	// Writes are refused even when the request is built by hand.
	writes := map[string]url.Values{
		"/findings/1/notes":      {"body": {"note"}},
		"/findings/1/exceptions": {"justification": {"x"}, "expires": {time.Now().UTC().AddDate(0, 0, 3).Format("2006-01-02")}},
		"/exceptions/1/decision": {"decision": {"approve"}, "reason": {"x"}},
		"/evidence/1/review":     {"decision": {"accept"}, "reason": {"x"}},
		"/integrations/collect":  {},
	}
	for path, form := range writes {
		if status, body := auditor.post(path, form); status != http.StatusForbidden || !strings.Contains(body, "Nothing was changed") {
			t.Errorf("auditor POST %s = %d, want 403", path, status)
		}
	}
	actor, err := s.svc.ActorByUsername(context.Background(), "auditor")
	if err != nil {
		t.Fatal(err)
	}
	views, err := s.svc.Findings(context.Background(), actor)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range views {
		if len(v.Notes) != 0 || len(v.Exceptions) != 0 {
			t.Errorf("finding %d was changed by a refused write", v.ID)
		}
	}
}

// Integration health shows collection problems beside the results, and
// lets only the operator queue collection.
func TestIntegrationHealthInTheBrowser(t *testing.T) {
	s := newSite(t)
	s.failing()
	ctx := context.Background()
	op, err := s.svc.ActorByUsername(ctx, "operator")
	if err != nil {
		t.Fatal(err)
	}
	runsBefore, err := s.svc.Store.Runs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}

	// The source starts failing. The failure shows on the health page and
	// as a flag on the overview; the result on the overview stays.
	s.fake.SetFailure(http.StatusBadGateway, nil)
	if _, err := s.svc.RequestCollection(ctx, op, "github", []string{githubtest.FakeRepository}, []string{github.BranchRulesKind}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.svc.Work(ctx, op, 1); err != nil {
		t.Fatal(err)
	}
	operator := s.signedIn("operator")
	status, body := operator.get("/integrations")
	if status != http.StatusOK {
		t.Fatalf("GET /integrations = %d", status)
	}
	for _, want := range []string{"github.branch_rules", "retrying", "<code>server</code>", "retry of #", "Queue collection now"} {
		if !strings.Contains(body, want) {
			t.Errorf("the health page does not show %q", want)
		}
	}
	_, overview := operator.get("/")
	if !strings.Contains(overview, "Integration health:") || !strings.Contains(overview, "GH-01") {
		t.Error("the overview does not flag the collection problem beside the results")
	}

	// The operator queues collection; a second click queues nothing more.
	s.fake.SetFailure(http.StatusOK, nil)
	if status, body := operator.post("/integrations/collect", url.Values{}); status != http.StatusOK || !strings.Contains(body, "Queued 2 collection run(s); 1 were already waiting") {
		t.Errorf("queue collection = %d, flash missing: %v", status, strings.Contains(body, "Queued"))
	}
	if _, body := operator.post("/integrations/collect", url.Values{}); !strings.Contains(body, "Queued 0 collection run(s); 3 were already waiting") {
		t.Error("a second request queued more runs")
	}
	runsAfter, err := s.svc.Store.Runs(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	// One failed attempt, its retry, and the two newly queued kinds.
	if got := len(runsAfter) - len(runsBefore); got != 4 {
		t.Errorf("%d new runs, want 4", got)
	}

	// Everyone else may look but not queue.
	for _, name := range []string{"control-owner", "reviewer", "auditor"} {
		b := s.signedIn(name)
		if _, body := b.get("/integrations"); strings.Contains(body, "Queue collection now") {
			t.Errorf("%s is offered collection", name)
		}
		if status, _ := b.post("/integrations/collect", url.Values{}); status != http.StatusForbidden {
			t.Errorf("%s POST /integrations/collect = %d, want 403", name, status)
		}
	}
}

// The auditor can download the review package for a past period, and it
// verifies without the database.
func TestReviewPackageInTheBrowser(t *testing.T) {
	s := newSite(t)
	s.failing()
	auditor := s.signedIn("auditor")
	if status, body := auditor.get("/package"); status != http.StatusOK || !strings.Contains(body, "Download package") {
		t.Fatalf("GET /package = %d", status)
	}

	// The evidence was collected today, so a period ending tomorrow holds
	// it but is not over; one ending today is over but holds nothing yet.
	today := time.Now().UTC().Truncate(24 * time.Hour)
	period := func(from, to time.Time) string {
		return "/package.zip?from=" + from.Format("2006-01-02") + "&to=" + to.Format("2006-01-02")
	}
	if status, body := auditor.get(period(today, today.AddDate(0, 0, 1))); status != http.StatusOK || !strings.Contains(body, "has not passed yet") {
		t.Errorf("a period that is not over: status %d, want the form with an explanation", status)
	}
	if status, body := auditor.get("/package.zip?from=yesterday&to="); status != http.StatusOK || !strings.Contains(body, "both dates are needed") {
		t.Errorf("bad dates: status %d", status)
	}

	status, body := auditor.get(period(today.AddDate(0, 0, -7), today))
	if status != http.StatusOK || !strings.HasPrefix(body, "PK") {
		t.Fatalf("download: status %d, not a zip", status)
	}
	archive, err := zip.NewReader(strings.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	v, err := assurance.VerifyPackage(archive)
	if err != nil || !v.OK() {
		t.Errorf("the downloaded package does not verify: %+v, %v", v, err)
	}
	// The download is in the decision log, with the manifest hash.
	if _, log := auditor.get("/log"); !strings.Contains(log, "package.generated") || !strings.Contains(log, v.ManifestSHA256) {
		t.Error("the download is not in the decision log")
	}
}

func TestCrossOriginPostsAreRefused(t *testing.T) {
	s := newSite(t)
	s.failing()
	owner := s.signedIn("control-owner")

	req, _ := http.NewRequest(http.MethodPost, s.url+"/findings/1/notes", strings.NewReader("body=planted"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Origin", "https://attacker.example")
	if status, _ := owner.do(req); status != http.StatusForbidden {
		t.Errorf("cross-site POST = %d, want 403", status)
	}
	if _, body := owner.get("/findings"); strings.Contains(body, "planted") {
		t.Error("a cross-site post was saved")
	}
}

func TestSecurityHeadersAndEscaping(t *testing.T) {
	s := newSite(t)
	s.failing()
	owner := s.signedIn("control-owner")
	owner.post("/findings/1/notes", url.Values{"body": {`<script>alert("x")</script>`}})

	resp, err := owner.client.Get(s.url + "/findings")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(body), "<script>") {
		t.Error("user text was not escaped")
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "form-action 'self'") {
		t.Errorf("Content-Security-Policy = %q", csp)
	}

	// The session cookie is HttpOnly and SameSite.
	b := s.browser()
	b.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, _ := http.NewRequest(http.MethodPost, s.url+"/login", strings.NewReader(url.Values{"username": {"auditor"}, "password": {s.passwords["auditor"]}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	login, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = login.Body.Close()
	found := false
	for _, c := range login.Cookies() {
		if c.Name == "cca_session" {
			found = true
			if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
				t.Errorf("session cookie: HttpOnly=%v SameSite=%v", c.HttpOnly, c.SameSite)
			}
		}
	}
	if !found {
		t.Error("sign-in set no session cookie")
	}
}
