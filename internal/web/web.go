// Package web serves the read-only pages.
package web

import (
	"context"
	"embed"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/store"
)

//go:embed page.html style.css
var files embed.FS

// Reader is the data the pages show.
type Reader interface {
	LatestResults(ctx context.Context) ([]store.EvaluationRow, error)
	Evaluations(ctx context.Context, limit int) ([]store.EvaluationRow, error)
	Findings(ctx context.Context) ([]store.FindingRow, error)
	Runs(ctx context.Context, limit int) ([]store.RunRow, error)
}

var page = template.Must(template.New("page.html").Funcs(template.FuncMap{
	"when": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
	"whenPtr": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04:05 UTC")
	},
	"short": func(sha string) string {
		if len(sha) > 12 {
			return sha[:12]
		}
		return sha
	},
	"label": func(result string) string { return strings.ReplaceAll(result, "_", " ") },
}).ParseFS(files, "page.html"))

type pageData struct {
	Results     []store.EvaluationRow
	Findings    []store.FindingRow
	Runs        []store.RunRow
	Evaluations []store.EvaluationRow
}

// Handler returns the read-only site. It serves GET requests only.
func Handler(r Reader) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		var d pageData
		var err error
		if d.Results, err = r.LatestResults(ctx); err == nil {
			if d.Findings, err = r.Findings(ctx); err == nil {
				if d.Runs, err = r.Runs(ctx, 25); err == nil {
					d.Evaluations, err = r.Evaluations(ctx, 50)
				}
			}
		}
		if err != nil {
			log.Printf("web: load page data: %v", err)
			http.Error(w, "The page could not be loaded.", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := page.Execute(w, d); err != nil {
			log.Printf("web: render page: %v", err)
		}
	})
	mux.HandleFunc("GET /style.css", func(w http.ResponseWriter, _ *http.Request) {
		css, _ := files.ReadFile("style.css")
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(css)
	})
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// Serve runs the site on addr until ctx is cancelled.
func Serve(ctx context.Context, addr string, r Reader) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           Handler(r),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
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
