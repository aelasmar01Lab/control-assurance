// Package web serves the browser interface. Handlers hold no rules of their
// own: each one identifies the signed-in actor and calls the service layer,
// which decides what that actor may do.
package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/alexedwards/scs/pgxstore"
	"github.com/alexedwards/scs/v2"

	"github.com/aelasmar01Lab/control-assurance/internal/assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/authz"
	"github.com/aelasmar01Lab/control-assurance/internal/content"
	"github.com/aelasmar01Lab/control-assurance/internal/control"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
)

//go:embed templates/*.html style.css static/*
var files embed.FS

const (
	sessionUserKey  = "user_id"
	sessionFlashKey = "flash"
	sessionLifetime = 8 * time.Hour
	sessionIdle     = time.Hour
)

var funcs = template.FuncMap{
	"when": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"whenPtr": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04 UTC")
	},
	"date": func(t time.Time) string { return t.Format("2006-01-02") },
	"datePtr": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.Format("2006-01-02")
	},
	"short": func(sha string) string {
		if len(sha) > 12 {
			return sha[:12]
		}
		return sha
	},
	"label": label,
	"tone":  tone,
	"bar":   bar,
	"initials": func(name string) string {
		if len(name) > 2 {
			return name[:2]
		}
		return name
	},
	"coverage": runCoverage,
	"window":   evidenceWindow,
	"upper":    strings.ToUpper,
	"rights":   textRights,
	// sentence ends a text with a full stop when it has none.
	"sentence": func(s string) string {
		if strings.HasSuffix(s, ".") {
			return s
		}
		return s + "."
	},
	"counts": func(head string, rows []content.Counts) map[string]any {
		return map[string]any{"Head": head, "Rows": rows}
	},
	// navKey is the sidebar entry a page belongs under.
	"navKey": func(page string) string {
		if page == "requirements" {
			return "frameworks"
		}
		return page
	},
	"hours": func(d time.Duration) int { return int(d.Hours()) },
	// deref shows what a pointer points at, or nothing for nil.
	"deref": func(v any) any {
		rv := reflect.ValueOf(v)
		if rv.Kind() != reflect.Pointer {
			return v
		}
		if rv.IsNil() {
			return ""
		}
		return rv.Elem().Interface()
	},
}

func mustPage(name string) *template.Template {
	return template.Must(template.New("layout.html").Funcs(funcs).ParseFS(files, "templates/layout.html", "templates/"+name))
}

var pages = map[string]*template.Template{
	"overview":     mustPage("overview.html"),
	"findings":     mustPage("findings.html"),
	"evidence":     mustPage("evidence.html"),
	"log":          mustPage("log.html"),
	"integrations": mustPage("integrations.html"),
	"package":      mustPage("package.html"),
	"requirements": mustPage("requirements.html"),
	"frameworks":   mustPage("frameworks.html"),
	"queue":        mustPage("queue.html"),
	"login":        mustPage("login.html"),
	"error":        mustPage("error.html"),
}

// Options configures the site.
type Options struct {
	// SecureCookies marks the session cookie Secure. Turn it on whenever
	// the site is served over HTTPS.
	SecureCookies bool
	// Demo marks every page as showing synthetic data.
	Demo bool
}

type server struct {
	svc      *assurance.Service
	sessions *scs.SessionManager
	demo     bool
}

// Handler returns the site.
func Handler(svc *assurance.Service, opts Options) http.Handler {
	sessions := scs.New()
	sessions.Store = pgxstore.NewWithCleanupInterval(svc.Store.Pool(), 0)
	sessions.Lifetime = sessionLifetime
	sessions.IdleTimeout = sessionIdle
	sessions.Cookie.Name = "cca_session"
	sessions.Cookie.HttpOnly = true
	sessions.Cookie.SameSite = http.SameSiteLaxMode
	sessions.Cookie.Secure = opts.SecureCookies
	sessions.ErrorFunc = func(w http.ResponseWriter, _ *http.Request, err error) {
		log.Printf("web: session: %v", err)
		http.Error(w, "The session could not be loaded.", http.StatusInternalServerError)
	}
	s := &server{svc: svc, sessions: sessions, demo: opts.Demo}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /style.css", s.stylesheet)
	mux.HandleFunc("GET /static/{file}", s.static)
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /{$}", s.as(s.overview))
	mux.HandleFunc("GET /requirements", s.as(s.frameworks))
	mux.HandleFunc("GET /frameworks/{key}", s.as(s.requirements))
	mux.HandleFunc("GET /review-queue", s.as(s.reviewQueue))
	mux.HandleFunc("GET /findings", s.as(s.findings))
	mux.HandleFunc("POST /findings/{id}/notes", s.as(s.addNote))
	mux.HandleFunc("POST /findings/{id}/exceptions", s.as(s.requestException))
	mux.HandleFunc("POST /exceptions/{id}/decision", s.as(s.decideException))
	mux.HandleFunc("GET /evidence", s.as(s.evidence))
	mux.HandleFunc("POST /evidence", s.as(s.submitEvidence))
	mux.HandleFunc("POST /evidence/{id}/review", s.as(s.reviewEvidence))
	mux.HandleFunc("GET /evidence/{id}/file", s.as(s.evidenceFile))
	mux.HandleFunc("GET /integrations", s.as(s.integrations))
	mux.HandleFunc("POST /integrations/collect", s.as(s.queueCollection))
	mux.HandleFunc("GET /log", s.as(s.decisionLog))
	mux.HandleFunc("GET /export.json", s.as(s.export))
	mux.HandleFunc("GET /package", s.as(s.packageForm))
	mux.HandleFunc("GET /package.zip", s.as(s.packageZip))

	// Reject state-changing requests that come from another origin.
	csrf := http.NewCrossOriginProtection()
	return securityHeaders(csrf.Handler(sessions.LoadAndSave(mux)))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// view is what every page template receives.
type view struct {
	Title string
	Actor *authz.Actor
	Flash string
	Now   time.Time
	// Demo is true when everything shown is synthetic.
	Demo bool
	// DemoName is the name of the fictional organization shown, if it has one.
	DemoName string
	// Page is the page's key, Meta its heading, Nav the sidebar, and Host
	// the address the site was reached at.
	Page string
	Meta pageMeta
	Nav  []navGroup
	Host string
	Data any
}

func (s *server) render(w http.ResponseWriter, r *http.Request, status int, page, title string, actor *authz.Actor, data any) {
	v := view{Title: title, Actor: actor, Now: time.Now(), Demo: s.demo, Page: page, Meta: pageMetas[page], Host: r.Host, Data: data}
	if v.Meta.Title == "" {
		v.Meta.Title = title
	}
	if s.demo {
		if sc, ok := control.ScopeFor(s.svc.Organization); ok && sc.Synthetic {
			v.DemoName = sc.Name
		}
	}
	if actor != nil {
		v.Flash = s.sessions.PopString(r.Context(), sessionFlashKey)
		// The sidebar counts open findings. If that cannot be read the
		// page still renders, without the count.
		open, err := s.svc.OpenFindings(r.Context(), *actor)
		if err != nil {
			open = 0
		}
		v.Nav = navigation(open)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages[page].Execute(w, v); err != nil {
		log.Printf("web: render %s: %v", page, err)
	}
}

// fail turns a service error into a response. Permission and validation
// messages are written for the user; anything else is logged and hidden.
func (s *server) fail(w http.ResponseWriter, r *http.Request, actor *authz.Actor, err error) {
	switch {
	case errors.Is(err, authz.ErrDenied):
		s.render(w, r, http.StatusForbidden, "error", "Not permitted", actor,
			"Your role does not permit that action. Nothing was changed.")
	case errors.Is(err, store.ErrNotFound):
		s.render(w, r, http.StatusNotFound, "error", "Not found", actor, "That item does not exist.")
	default:
		// Log the matched route, not the raw path, and quote the error text.
		log.Printf("web: %s: %q", r.Pattern, err.Error()) //nolint:gosec // %q escapes newlines, so the entry cannot be forged
		s.render(w, r, http.StatusInternalServerError, "error", "Something went wrong", actor,
			"The request could not be completed. Nothing was changed.")
	}
}

// done finishes a form post: a validation problem or a success both return
// to the page with a message; anything else is an error page.
func (s *server) done(w http.ResponseWriter, r *http.Request, actor authz.Actor, back, success string, err error) {
	switch {
	case err == nil:
		s.sessions.Put(r.Context(), sessionFlashKey, success)
	case errors.Is(err, assurance.ErrInvalid):
		s.sessions.Put(r.Context(), sessionFlashKey, "Not saved: "+strings.TrimPrefix(err.Error(), assurance.ErrInvalid.Error()+": "))
	default:
		s.fail(w, r, &actor, err)
		return
	}
	// back is a fixed path, at most with a finding number parsed as an integer.
	http.Redirect(w, r, back, http.StatusSeeOther) //nolint:gosec // never built from request text
}

// as wraps a handler that needs a signed-in actor. The actor is loaded from
// the database on every request, so a changed role applies at once.
func (s *server) as(next func(http.ResponseWriter, *http.Request, authz.Actor)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := s.sessions.GetInt64(r.Context(), sessionUserKey)
		if id == 0 {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		actor, err := s.svc.ActorByID(r.Context(), id)
		if err != nil {
			_ = s.sessions.Destroy(r.Context())
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r, actor)
	}
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func (s *server) stylesheet(w http.ResponseWriter, _ *http.Request) {
	css, _ := files.ReadFile("style.css")
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(css)
}

// staticTypes are the only files served from static/: the fonts.
var staticTypes = map[string]string{
	"inter-latin.woff2": "font/woff2", "inter-latin-ext.woff2": "font/woff2", "phosphor.woff2": "font/woff2",
}

func (s *server) static(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	contentType, ok := staticTypes[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, err := files.ReadFile("static/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	// Fonts hold nothing private and never change within a build.
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(data) //nolint:gosec // a font embedded in the binary, chosen from a fixed list
}

func (s *server) loginForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "login", "Sign in", nil, "")
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	actor, err := s.svc.Authenticate(r.Context(), r.PostFormValue("username"), r.PostFormValue("password"))
	if errors.Is(err, assurance.ErrBadCredentials) {
		s.render(w, r, http.StatusUnauthorized, "login", "Sign in", nil, "The username or password is incorrect.")
		return
	}
	if err != nil {
		s.fail(w, r, nil, err)
		return
	}
	// A new session token on sign-in, so a token seen before sign-in is useless after it.
	if err := s.sessions.RenewToken(r.Context()); err != nil {
		s.fail(w, r, nil, err)
		return
	}
	s.sessions.Put(r.Context(), sessionUserKey, actor.UserID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	_ = s.sessions.Destroy(r.Context())
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *server) overview(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	ctx := r.Context()
	ov, err := s.svc.Overview(ctx, actor)
	if err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	reqs, err := s.svc.Requirements(ctx, actor)
	if err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	findings, err := s.svc.Findings(ctx, actor)
	if err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	health, err := s.svc.Health(ctx, actor)
	if err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	s.render(w, r, http.StatusOK, "overview", "Overview", &actor,
		buildOverview(ov, reqs, findings, health, r.URL.Query().Get("control")))
}

func (s *server) findings(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	data, err := s.svc.Findings(r.Context(), actor)
	if err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	selected, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	s.render(w, r, http.StatusOK, "findings", "Findings", &actor, buildFindings(data, selected))
}

func (s *server) addNote(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	id, ok := pathID(r)
	if !ok {
		s.fail(w, r, &actor, store.ErrNotFound)
		return
	}
	_, err := s.svc.AddRemediationNote(r.Context(), actor, id, r.PostFormValue("body"))
	s.done(w, r, actor, fmt.Sprintf("/findings?id=%d", id), "Remediation note added.", err)
}

func (s *server) requestException(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	id, ok := pathID(r)
	if !ok {
		s.fail(w, r, &actor, store.ErrNotFound)
		return
	}
	// The exception runs to the end of the chosen day, UTC.
	var expires time.Time
	if d, err := time.Parse("2006-01-02", r.PostFormValue("expires")); err == nil {
		expires = d.Add(24*time.Hour - time.Second)
	}
	_, err := s.svc.RequestException(r.Context(), actor, id, r.PostFormValue("justification"), expires)
	s.done(w, r, actor, fmt.Sprintf("/findings?id=%d", id), "Exception requested. It has no effect until someone else approves it.", err)
}

func (s *server) decideException(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	id, ok := pathID(r)
	if !ok {
		s.fail(w, r, &actor, store.ErrNotFound)
		return
	}
	// Return to the finding the exception belongs to.
	back := "/findings"
	if finding, err := strconv.ParseInt(r.PostFormValue("finding"), 10, 64); err == nil && finding > 0 {
		back = fmt.Sprintf("/findings?id=%d", finding)
	}
	var approve bool
	switch r.PostFormValue("decision") {
	case "approve":
		approve = true
	case "reject":
	default:
		s.done(w, r, actor, back, "", fmt.Errorf("%w: choose approve or reject", assurance.ErrInvalid))
		return
	}
	err := s.svc.DecideException(r.Context(), actor, id, approve, r.PostFormValue("reason"))
	s.done(w, r, actor, back, "Decision recorded.", err)
}

func (s *server) evidence(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	data, err := s.svc.ManualEvidence(r.Context(), actor)
	if err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	s.render(w, r, http.StatusOK, "evidence", "Manual evidence", &actor, data)
}

func (s *server) submitEvidence(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	r.Body = http.MaxBytesReader(w, r.Body, assurance.MaxEvidenceBytes+1<<20)
	if err := r.ParseMultipartForm(1 << 20); err != nil { //nolint:gosec // body is bounded by MaxBytesReader on the line above
		s.done(w, r, actor, "/evidence", "", fmt.Errorf("%w: the upload could not be read, or is larger than %d MB",
			assurance.ErrInvalid, assurance.MaxEvidenceBytes>>20))
		return
	}
	up := assurance.EvidenceUpload{ControlKey: r.PostFormValue("control"), Note: r.PostFormValue("note")}
	up.PeriodStart, _ = time.Parse("2006-01-02", r.PostFormValue("period_start"))
	up.PeriodEnd, _ = time.Parse("2006-01-02", r.PostFormValue("period_end"))
	if file, header, err := r.FormFile("file"); err == nil {
		defer func() { _ = file.Close() }()
		up.Filename = header.Filename
		if up.Data, err = io.ReadAll(io.LimitReader(file, assurance.MaxEvidenceBytes+1)); err != nil {
			s.fail(w, r, &actor, err)
			return
		}
	}
	_, err := s.svc.SubmitEvidence(r.Context(), actor, up)
	s.done(w, r, actor, "/evidence", "Evidence submitted. It does not count until a reviewer accepts it.", err)
}

func (s *server) reviewEvidence(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	id, ok := pathID(r)
	if !ok {
		s.fail(w, r, &actor, store.ErrNotFound)
		return
	}
	var accept bool
	switch r.PostFormValue("decision") {
	case "accept":
		accept = true
	case "reject":
	default:
		s.done(w, r, actor, "/evidence", "", fmt.Errorf("%w: choose accept or reject", assurance.ErrInvalid))
		return
	}
	err := s.svc.ReviewEvidence(r.Context(), actor, id, accept, r.PostFormValue("reason"))
	s.done(w, r, actor, "/evidence", "Review recorded.", err)
}

func (s *server) evidenceFile(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	id, ok := pathID(r)
	if !ok {
		s.fail(w, r, &actor, store.ErrNotFound)
		return
	}
	data, name, err := s.svc.EvidenceFile(r.Context(), actor, id)
	if err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	// Always a download, never rendered: uploaded content is untrusted.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	_, _ = w.Write(data) //nolint:gosec // sent as an octet-stream attachment with nosniff, so never rendered
}

func (s *server) frameworks(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	fws, reqs, err := s.svc.Frameworks(r.Context(), actor)
	if err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	s.render(w, r, http.StatusOK, "frameworks", "Frameworks", &actor, buildFrameworks(fws, reqs))
}

func (s *server) requirements(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	fws, reqs, err := s.svc.Frameworks(r.Context(), actor)
	if err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	for _, fw := range fws {
		if fw.Key == r.PathValue("key") {
			s.render(w, r, http.StatusOK, "requirements", fw.Title, &actor, buildRequirements(fw, reqs))
			return
		}
	}
	s.fail(w, r, &actor, store.ErrNotFound)
}

func (s *server) reviewQueue(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	q, err := s.svc.ReviewQueue(r.Context(), actor)
	if err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	s.render(w, r, http.StatusOK, "queue", "Review queue", &actor, q)
}

func (s *server) packageForm(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	// Offer the last complete week, ending today (UTC).
	today := time.Now().UTC().Truncate(24 * time.Hour)
	s.render(w, r, http.StatusOK, "package", "Review package", &actor, map[string]any{
		"From": today.AddDate(0, 0, -7).Format("2006-01-02"), "To": today.Format("2006-01-02"), "Items": packageItems,
	})
}

func (s *server) packageZip(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	from, errFrom := time.Parse("2006-01-02", r.URL.Query().Get("from"))
	to, errTo := time.Parse("2006-01-02", r.URL.Query().Get("to"))
	var (
		p   *assurance.Package
		err error
	)
	if errFrom != nil || errTo != nil {
		err = fmt.Errorf("%w: both dates are needed, as YYYY-MM-DD", assurance.ErrInvalid)
	} else {
		p, err = s.svc.BuildPackage(r.Context(), actor, from, to)
	}
	if errors.Is(err, assurance.ErrInvalid) {
		// A problem with the period goes back to the form.
		s.sessions.Put(r.Context(), sessionFlashKey, "No package was made: "+strings.TrimPrefix(err.Error(), assurance.ErrInvalid.Error()+": "))
		http.Redirect(w, r, "/package", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	var buf bytes.Buffer
	if err := p.WriteZip(&buf); err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	name := fmt.Sprintf("review-package-%s-to-%s.zip", from.Format("2006-01-02"), to.Format("2006-01-02"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Manifest-SHA256", p.ManifestSHA256)
	_, _ = w.Write(buf.Bytes())
}

func (s *server) integrations(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	health, err := s.svc.Health(r.Context(), actor)
	if err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	s.render(w, r, http.StatusOK, "integrations", "Integration health", &actor, buildHealth(health))
}

func (s *server) queueCollection(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	queued, err := s.svc.RequestAll(r.Context(), actor)
	added := 0
	for _, q := range queued {
		if q.Queued {
			added++
		}
	}
	msg := fmt.Sprintf("Queued %d collection run(s); %d were already waiting. A running worker collects them.", added, len(queued)-added)
	if err == nil && len(queued) == 0 {
		msg = "Nothing to queue: no resource is in scope yet. Run \"cca collect\" once to register one."
	}
	s.done(w, r, actor, "/integrations", msg, err)
}

func (s *server) decisionLog(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	data, err := s.svc.DecisionLog(r.Context(), actor)
	if err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	s.render(w, r, http.StatusOK, "log", "Decision log", &actor, data)
}

func (s *server) export(w http.ResponseWriter, r *http.Request, actor authz.Actor) {
	data, err := s.svc.Export(r.Context(), actor)
	if err != nil {
		s.fail(w, r, &actor, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="control-assurance-export.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		log.Printf("web: write export: %v", err)
	}
}

// Serve runs the site on addr until ctx is cancelled.
func Serve(ctx context.Context, addr string, svc *assurance.Service, opts Options) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           Handler(svc, opts),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
