package github_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/aelasmar01Lab/control-assurance/internal/github"
	"github.com/aelasmar01Lab/control-assurance/internal/github/githubtest"
)

func TestCollectAlerts(t *testing.T) {
	ctx := context.Background()
	f := githubtest.NewFake()
	defer f.Server.Close()
	// Served out of order, to prove the payload is sorted.
	f.SetAlerts(
		githubtest.Alert{Number: 9, Severity: "HIGH", Created: "2026-10-01T00:00:00Z"},
		githubtest.Alert{Number: 2, Severity: "medium", Created: "2026-09-01T00:00:00Z"})

	got, err := f.Client().CollectAlerts(ctx, githubtest.FakeRepository)
	if err != nil {
		t.Fatalf("CollectAlerts: %v", err)
	}
	if !got.AlertsEnabled || !got.AlertsComplete || len(got.Alerts) != 2 {
		t.Fatalf("unexpected snapshot: %+v", got)
	}
	if got.Alerts[0].Number != 2 || got.Alerts[1].Severity != "high" || got.Alerts[1].Package != "synthetic-package" {
		t.Errorf("alerts = %+v, want sorted by number with lower-case severity", got.Alerts)
	}

	// The same state collected through the registered collector yields
	// identical bytes each time.
	collectAlerts := f.Client().Collectors()[github.AlertsKind]
	a, err := collectAlerts(ctx, githubtest.FakeRepository)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := collectAlerts(ctx, githubtest.FakeRepository)
	if string(a.Payload) != string(b.Payload) || a.Kind != github.AlertsKind || a.Normalizer != github.AlertsNormalizer || !a.Complete {
		t.Errorf("snapshots differ or are mislabelled: %+v", a)
	}
}

// Alerts turned off is evidence, not an error and not an empty list.
func TestCollectAlertsDisabled(t *testing.T) {
	f := githubtest.NewFake()
	defer f.Server.Close()
	f.DisableAlerts()
	got, err := f.Client().CollectAlerts(context.Background(), githubtest.FakeRepository)
	if err != nil {
		t.Fatalf("CollectAlerts: %v", err)
	}
	if got.AlertsEnabled {
		t.Errorf("snapshot = %+v, want alerts_enabled false", got)
	}

	// Any other 403 is still a permission failure.
	f.SetFailure(http.StatusForbidden, nil)
	_, err = f.Client().CollectAlerts(context.Background(), githubtest.FakeRepository)
	var ce *github.Error
	if !errors.As(err, &ce) || ce.Class != github.ClassPermission {
		t.Errorf("err = %v, want a permission error", err)
	}
}

func TestCollectAlertsTruncated(t *testing.T) {
	f := githubtest.NewFake()
	defer f.Server.Close()
	f.SetAlerts(
		githubtest.Alert{Number: 1, Severity: "low", Created: "2026-10-01T00:00:00Z"},
		githubtest.Alert{Number: 2, Severity: "low", Created: "2026-10-01T00:00:00Z"},
		githubtest.Alert{Number: 3, Severity: "low", Created: "2026-10-01T00:00:00Z"})
	f.SetPageSize(1)
	c := f.Client()

	c.MaxPages = 2
	got, err := c.CollectAlerts(context.Background(), githubtest.FakeRepository)
	if err != nil {
		t.Fatal(err)
	}
	if got.AlertsComplete || len(got.Alerts) != 2 {
		t.Errorf("snapshot = %+v, want 2 alerts and incomplete", got)
	}

	c.MaxPages = 3
	got, err = c.CollectAlerts(context.Background(), githubtest.FakeRepository)
	if err != nil {
		t.Fatal(err)
	}
	if !got.AlertsComplete || len(got.Alerts) != 3 {
		t.Errorf("snapshot = %+v, want 3 alerts and complete", got)
	}
}

func TestCollectSecurityPolicy(t *testing.T) {
	ctx := context.Background()
	f := githubtest.NewFake()
	defer f.Server.Close()

	got, err := f.Client().CollectSecurityPolicy(ctx, githubtest.FakeRepository)
	if err != nil {
		t.Fatalf("CollectSecurityPolicy: %v", err)
	}
	if len(got.Found) != 0 || len(got.PathsChecked) != 3 || got.DefaultBranch != "main" {
		t.Errorf("snapshot = %+v, want nothing found at three paths", got)
	}

	f.SetFiles(".github/SECURITY.md", "README.md")
	got, err = f.Client().CollectSecurityPolicy(ctx, githubtest.FakeRepository)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Found) != 1 || got.Found[0].Path != ".github/SECURITY.md" || got.Found[0].Size == 0 {
		t.Errorf("found = %+v, want .github/SECURITY.md", got.Found)
	}

	// A missing repository is an error, not "no policy".
	_, err = f.Client().CollectSecurityPolicy(ctx, "lab-org/missing")
	var ce *github.Error
	if !errors.As(err, &ce) || ce.Class != github.ClassNotFound {
		t.Errorf("err = %v, want not_found", err)
	}
}

// The collectors only ever read.
func TestCollectorsOnlyRead(t *testing.T) {
	f := githubtest.NewFake()
	defer f.Server.Close()
	f.SetFiles("SECURITY.md")
	for kind, collector := range f.Client().Collectors() {
		if _, err := collector(context.Background(), githubtest.FakeRepository); err != nil {
			t.Errorf("%s: %v", kind, err)
		}
	}
	if f.Requests() == 0 || f.Writes() != 0 {
		t.Errorf("requests = %d, writes = %d; want only reads", f.Requests(), f.Writes())
	}
}
