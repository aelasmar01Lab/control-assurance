package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/store"
)

type fakeReader struct {
	err error
}

func (f fakeReader) LatestResults(context.Context) ([]store.EvaluationRow, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []store.EvaluationRow{{
		EvaluationID: 4, ObservationID: 2, Resource: "lab-org/lab-repo",
		CheckKey: "GH-01", CheckVersion: "1", Result: "not_evaluated",
		Explanation:   `Incomplete coverage <script>alert("x")</script>`,
		PayloadSHA256: strings.Repeat("ab", 32), CollectedAt: time.Unix(0, 0),
	}}, nil
}

func (f fakeReader) Evaluations(context.Context, int) ([]store.EvaluationRow, error) {
	return nil, nil
}

func (f fakeReader) Findings(context.Context) ([]store.FindingRow, error) {
	closing, closedAt, why := int64(9), time.Unix(60, 0), "Ruleset 1 is active"
	return []store.FindingRow{
		{ID: 2, Resource: "lab-org/lab-repo", CheckKey: "GH-01", OpeningEvaluationID: 11, OpeningExplanation: "No active rule"},
		{ID: 1, Resource: "lab-org/lab-repo", CheckKey: "GH-01", OpeningEvaluationID: 3, OpeningExplanation: "No active rule",
			ClosingEvaluationID: &closing, ClosedAt: &closedAt, ClosingExplanation: &why},
	}, nil
}

func (f fakeReader) Runs(context.Context, int) ([]store.RunRow, error) {
	return []store.RunRow{{ID: 5, Integration: "github", Resource: "lab-org/lab-repo", Outcome: "failed", ErrorClass: "auth", ErrorDetail: "GET /repos/x returned 401"}}, nil
}

func get(t *testing.T, r Reader, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler(r).ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestPage(t *testing.T) {
	rec := get(t, fakeReader{}, http.MethodGet, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"lab-org/lab-repo", "GH-01", "not evaluated", "abababababab",
		"Evaluation 3", "Evaluation 9", "Evaluation 11", "Not closed",
		"auth", "GET /repos/x returned 401",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
	if strings.Contains(body, "<script>") {
		t.Error("explanation text was not escaped")
	}
	// The product never calls anything compliant.
	if strings.Contains(strings.ToLower(body), "compliant") {
		t.Error(`page uses the word "compliant"`)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("Content-Security-Policy = %q", csp)
	}
}

func TestPageIsReadOnly(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		if rec := get(t, fakeReader{}, method, "/"); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s / = %d, want 405", method, rec.Code)
		}
	}
	if rec := get(t, fakeReader{}, http.MethodGet, "/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("GET /nope = %d, want 404", rec.Code)
	}
}

func TestPageHidesInternalErrors(t *testing.T) {
	rec := get(t, fakeReader{err: errors.New("password=hunter2 connection refused")}, http.MethodGet, "/")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Error("internal error detail leaked to the page")
	}
}

func TestStylesheet(t *testing.T) {
	rec := get(t, fakeReader{}, http.MethodGet, "/style.css")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/css") {
		t.Errorf("GET /style.css = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}
