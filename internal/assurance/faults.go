package assurance

import (
	"fmt"
	"strings"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/collect"
)

// Fault is one failure the test suite injects into a collector.
type Fault struct {
	// Name identifies the fault; the tests inject each one by this name.
	Name string
	// Source is the integration the fault is injected into.
	Source string
	// Injected says what the synthetic source is made to do.
	Injected string
	// Class is the error class the attempt must end in. It is empty for a
	// fault that is evidence rather than a failure to collect.
	Class collect.Class
	// Result is the check result the fault must lead to, for a fault that
	// is evidence. It is never pass.
	Result string
}

// Faults is every fault the suite injects. The fault table is generated
// from this list, and TestEveryFault fails if an entry has no injection or
// ends in a different class.
var Faults = []Fault{
	{Name: "github-invalid-token", Source: "GitHub", Injected: "The token is rejected (401).", Class: collect.Auth},
	{Name: "github-forbidden", Source: "GitHub", Injected: "The API refuses the read (403, no rate-limit headers).", Class: collect.Permission},
	{Name: "github-rate-limited", Source: "GitHub", Injected: "The API reports the rate limit is spent (403, X-RateLimit-Remaining: 0, Retry-After: 120).", Class: collect.RateLimited},
	{Name: "github-not-found", Source: "GitHub", Injected: "The repository does not exist (404).", Class: collect.NotFound},
	{Name: "github-server-error", Source: "GitHub", Injected: "The API answers 503.", Class: collect.Server},
	{Name: "github-malformed", Source: "GitHub", Injected: "A listing returns a body that is not JSON.", Class: collect.Malformed},
	{Name: "github-unreachable", Source: "GitHub", Injected: "The API host refuses the connection.", Class: collect.Network},
	{Name: "github-teapot", Source: "GitHub", Injected: "The API answers with a status the collector does not expect (418).", Class: collect.Unexpected},
	{Name: "aws-expired-credentials", Source: "AWS", Injected: "Every call fails with ExpiredToken.", Class: collect.Auth},
	{Name: "aws-access-denied", Source: "AWS", Injected: "Every call fails with AccessDenied.", Class: collect.Permission},
	{Name: "aws-throttled", Source: "AWS", Injected: "Every call fails with ThrottlingException.", Class: collect.RateLimited},
	{Name: "aws-server-fault", Source: "AWS", Injected: "Every call fails with a server-side fault.", Class: collect.Server},
	{Name: "aws-unreachable", Source: "AWS", Injected: "No call reaches the service.", Class: collect.Network},
	{Name: "aws-wrong-account", Source: "AWS", Injected: "The credentials belong to a different account.", Class: collect.Permission},
	{Name: "aws-report-malformed", Source: "AWS", Injected: "The credential report lacks a column the collector reads.", Class: collect.Malformed},
	{Name: "aws-report-never-ready", Source: "AWS", Injected: "The credential report is never reported ready.", Class: collect.Network},
	{Name: "evidence-store-down", Source: "Evidence store", Injected: "The evidence store refuses the write after a successful read.", Class: collect.Storage},
	{Name: "worker-killed", Source: "Worker", Injected: "The worker stops after claiming a run and never finishes it.", Class: collect.Interrupted},
	{Name: "collector-hangs", Source: "Worker", Injected: "The collector does not return within the run timeout.", Class: collect.Network},

	{Name: "github-truncated-rules", Source: "GitHub", Injected: "The rule listing has more pages than the collector reads, and the rule is not among those read.", Result: "not_evaluated"},
	{Name: "github-truncated-alerts", Source: "GitHub", Injected: "The alert listing has more pages than the collector reads, and no alert read is overdue.", Result: "not_evaluated"},
	{Name: "github-alerts-disabled", Source: "GitHub", Injected: "Dependabot alerts are turned off for the repository (403 with GitHub's own message).", Result: "not_evaluated"},
	{Name: "github-protected-no-rules", Source: "GitHub", Injected: "The branch reports as protected but no rule is visible.", Result: "not_evaluated"},
	{Name: "aws-trail-status-denied", Source: "AWS", Injected: "The trail is described but its status is refused.", Result: "not_evaluated"},
}

func describeDelay(d time.Duration) string {
	switch {
	case d == 0:
		return "at once"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	default:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
}

// describeRetry renders a class's retry policy in a few words.
func describeRetry(class collect.Class) string {
	p := RetryPolicies[class]
	if p.MaxAttempts <= 1 {
		return "Not retried. The next scheduled collection tries again."
	}
	var waits []string
	for attempt := 1; attempt < p.MaxAttempts; attempt++ {
		d, _ := NextAttempt(class, attempt, 0)
		waits = append(waits, describeDelay(d))
	}
	out := fmt.Sprintf("Up to %d attempts; waits: %s.", p.MaxAttempts, strings.Join(waits, ", "))
	if class == collect.RateLimited {
		out += " The source's own Retry-After is used instead when it gives one, capped at 1 h."
	}
	return out
}

// FaultTableMarkdown renders the fault table from the fault list and the
// retry policies in force.
func FaultTableMarkdown() string {
	var b strings.Builder
	b.WriteString("# Fault table\n\n")
	b.WriteString("Generated by `cca faults` from the fault list and retry policies in `internal/assurance`. Do not edit by hand.\n\n")
	b.WriteString("Every fault below is injected into a synthetic source by `TestEveryFault`, which asserts the error class or result shown here ")
	b.WriteString("and that the fault never produces a `pass`. All data in those tests is synthetic.\n\n")

	b.WriteString("## Faults that stop collection\n\n")
	b.WriteString("The attempt is recorded as failed with an error class. It produces no observation, so no check is evaluated, ")
	b.WriteString("no result changes and no finding opens or closes. The previous result stands and its evidence ages toward stale.\n\n")
	b.WriteString("| Fault | Source | What is injected | Error class | Retry |\n| --- | --- | --- | --- | --- |\n")
	for _, f := range Faults {
		if f.Class != "" {
			fmt.Fprintf(&b, "| `%s` | %s | %s | `%s` | %s |\n", f.Name, f.Source, f.Injected, f.Class, describeRetry(f.Class))
		}
	}

	b.WriteString("\n## Faults that are evidence\n\n")
	b.WriteString("Collection succeeds and stores what it saw, including that the view was partial. The check then declines to judge.\n\n")
	b.WriteString("| Fault | Source | What is injected | Check result |\n| --- | --- | --- | --- |\n")
	for _, f := range Faults {
		if f.Class == "" {
			fmt.Fprintf(&b, "| `%s` | %s | %s | `%s` |\n", f.Name, f.Source, f.Injected, f.Result)
		}
	}

	b.WriteString("\n## Retry policy by error class\n\n")
	b.WriteString("Each attempt, including each retry, is its own collection run row.\n\n")
	b.WriteString("| Error class | Retry | Why |\n| --- | --- | --- |\n")
	for _, class := range collect.Classes {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", class, describeRetry(class), RetryPolicies[class].Why)
	}
	return b.String()
}
