package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	// AlertsKind names the observation CollectAlerts produces.
	AlertsKind = "github.dependabot_alerts"
	// AlertsNormalizer versions the shape of the Alerts payload.
	AlertsNormalizer = "github.dependabot_alerts/1"

	// alertsDisabledMessage is the body GitHub returns with a 403 when
	// Dependabot alerts are turned off for the repository. Observed on a
	// lab repository on 2026-11-12.
	alertsDisabledMessage = "Dependabot alerts are disabled for this repository."
)

// Alert is one open Dependabot alert, reduced to what the check reads.
type Alert struct {
	Number    int       `json:"number"`
	Severity  string    `json:"severity"`
	Package   string    `json:"package"`
	Ecosystem string    `json:"ecosystem"`
	Advisory  string    `json:"advisory"`
	CreatedAt time.Time `json:"created_at"`
}

// Alerts is the normalized evidence for a repository's open Dependabot alerts.
type Alerts struct {
	Repository string `json:"repository"`
	// AlertsEnabled is false when GitHub says Dependabot alerts are turned
	// off. An empty list then means nothing, and must not read as zero alerts.
	AlertsEnabled bool `json:"alerts_enabled"`
	// AlertsComplete is false when the listing had more pages than were read.
	AlertsComplete bool    `json:"alerts_complete"`
	Alerts         []Alert `json:"alerts"`
}

// CollectAlerts reads the open Dependabot alerts on repo.
func (c *Client) CollectAlerts(ctx context.Context, repo string) (*Alerts, error) {
	if _, err := c.defaultBranch(ctx, repo); err != nil {
		return nil, err
	}
	out := &Alerts{Repository: repo, AlertsEnabled: true, AlertsComplete: true, Alerts: []Alert{}}

	next := fmt.Sprintf("/repos/%s/dependabot/alerts?state=open&per_page=%d", repo, pageSize)
	for page := 1; next != ""; page++ {
		if page > c.maxPages() {
			out.AlertsComplete = false
			break
		}
		resp, err := c.fetch(ctx, next)
		if err != nil {
			return nil, err
		}
		if resp.status == http.StatusForbidden && strings.HasPrefix(resp.message(), alertsDisabledMessage) {
			// Alerts are off. That is a fact about the repository, not a
			// failure to read it, so it is recorded as evidence.
			out.AlertsEnabled = false
			return out, nil
		}
		if resp.status != http.StatusOK {
			return nil, resp.failure()
		}
		var raw []struct {
			Number     int    `json:"number"`
			State      string `json:"state"`
			CreatedAt  string `json:"created_at"`
			Dependency struct {
				Package struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
			} `json:"dependency"`
			Advisory struct {
				GHSA     string `json:"ghsa_id"`
				Severity string `json:"severity"`
			} `json:"security_advisory"`
		}
		if err := json.Unmarshal(resp.body, &raw); err != nil {
			return nil, &Error{Class: ClassMalformed, Detail: fmt.Sprintf("GET %s: response is not the expected JSON", resp.path)}
		}
		for _, a := range raw {
			created, err := time.Parse(time.RFC3339, a.CreatedAt)
			if err != nil || a.Number == 0 || a.Advisory.Severity == "" {
				// An alert without an age or a severity cannot be judged;
				// refuse the page rather than guess.
				return nil, &Error{Class: ClassMalformed, Detail: fmt.Sprintf("GET %s: an alert has no number, severity or creation time", resp.path)}
			}
			if a.State != "" && a.State != "open" {
				continue
			}
			out.Alerts = append(out.Alerts, Alert{
				Number: a.Number, Severity: strings.ToLower(a.Advisory.Severity),
				Package: a.Dependency.Package.Name, Ecosystem: a.Dependency.Package.Ecosystem,
				Advisory: a.Advisory.GHSA, CreatedAt: created.UTC(),
			})
		}
		next = nextLink(resp.header.Get("Link"))
	}
	sort.Slice(out.Alerts, func(i, j int) bool { return out.Alerts[i].Number < out.Alerts[j].Number })
	return out, nil
}
