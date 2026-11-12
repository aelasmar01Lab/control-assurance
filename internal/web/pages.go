package web

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/aelasmar01Lab/control-assurance/internal/assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/control"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
)

// pageMeta is the heading of a page: the navigation group it belongs to,
// its title, and one paragraph saying what it shows.
type pageMeta struct{ Group, Title, Note string }

var pageMetas = map[string]pageMeta{
	"overview":     {"Monitor", "Overview", "Each control has a state and, beside it, the reasons. Supported always lists the checks it rests on, and says nothing about any framework."},
	"requirements": {"Monitor", "Framework requirements", "Every requirement of the catalog. A requirement is partly evidenced only when every control mapped to it is supported by current evidence; no mapping in this release is strong enough to say more. A requirement that no control covers shows how it is tracked instead, with the reason."},
	"findings":     {"Monitor", "Findings", "A finding is opened by a failing evaluation and closed only by a later passing one. An exception accepts the risk for a limited time; it never changes an evaluation, and it stops counting when it expires."},
	"evidence":     {"Evidence", "Manual evidence", "Submitting and accepting are separate actions by separate people. Submitted evidence does not count until a reviewer accepts it, and accepted evidence stops counting after its validity date."},
	"integrations": {"Evidence", "Integration health", "Whether evidence is arriving. A problem here is a problem with collection: it is never a check result, and it changes none. A failed attempt leaves the previous result in place and lets its evidence age."},
	"log":          {"Audit", "Decision log", "Who did what, to what, and why. Entries are written in the same transaction as the change they describe, and are never edited or removed. The 200 most recent are shown."},
	"package":      {"Audit", "Review package", "Everything recorded for one past period, in one archive. The period must be over. Asking for the same period again gives a package with the same manifest hash."},
}

// navItem is one link in the sidebar.
type navItem struct {
	Key, Icon, Label, Href string
	Badge                  int
}

// navGroup is a labelled group of sidebar links.
type navGroup struct {
	Label string
	Items []navItem
}

func navigation(openFindings int) []navGroup {
	return []navGroup{
		{"Monitor", []navItem{
			{Key: "overview", Icon: "ph-squares-four", Label: "Overview", Href: "/"},
			{Key: "requirements", Icon: "ph-list-checks", Label: "Requirements", Href: "/requirements"},
			{Key: "findings", Icon: "ph-warning-diamond", Label: "Findings", Href: "/findings", Badge: openFindings},
		}},
		{"Evidence", []navItem{
			{Key: "evidence", Icon: "ph-file-arrow-up", Label: "Manual evidence", Href: "/evidence"},
			{Key: "integrations", Icon: "ph-plugs-connected", Label: "Integration health", Href: "/integrations"},
		}},
		{"Audit", []navItem{
			{Key: "log", Icon: "ph-scroll", Label: "Decision log", Href: "/log"},
			{Key: "package", Icon: "ph-package", Label: "Review package", Href: "/package"},
			{Key: "export", Icon: "ph-download-simple", Label: "Export JSON", Href: "/export.json"},
		}},
	}
}

// tones maps every state, result and status the pages show to one of four
// tones. Anything not listed is neutral.
var tones = map[string]string{
	"supported": "pass", "partly_evidenced": "pass", "pass": "pass", "succeeded": "pass", "healthy": "pass",
	"approved": "pass", "accepted": "pass", "closed": "pass", "complete": "pass",
	"needs_attention": "fail", "fail": "fail", "failed": "fail", "failing": "fail", "rejected": "fail",
	"expired": "fail", "open": "fail",
	"stale": "warn", "not_evaluated": "warn", "accepted_risk": "warn", "queued": "warn", "running": "warn",
	"retrying": "warn", "requested": "warn", "pending": "warn", "incomplete": "warn",
}

func tone(v any) string {
	if t, ok := tones[fmt.Sprint(v)]; ok {
		return t
	}
	return "neutral"
}

// seg is one segment of a proportion bar and its legend row.
type seg struct {
	Label string
	N     int
	// Fill is the colour class: s-pass, s-fail, s-warn, s-neutral or s-dim.
	Fill string
}

// bar draws segments as an inline SVG, because the content security policy
// allows no inline style to size them with.
func bar(segs []seg) template.HTML {
	total := 0
	for _, s := range segs {
		total += s.N
	}
	var b strings.Builder
	b.WriteString(`<svg viewBox="0 0 100 6" preserveAspectRatio="none" aria-hidden="true">`)
	x := 0.0
	for _, s := range segs {
		if s.N == 0 || total == 0 {
			continue
		}
		w := 100 * float64(s.N) / float64(total)
		// A hairline gap between segments.
		fmt.Fprintf(&b, `<rect class="%s" x="%.2f" y="0" width="%.2f" height="6"/>`, template.HTMLEscapeString(s.Fill), x, max(w-0.5, 0.5))
		x += w
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec // built from numbers and an escaped class name
}

func label(v any) string { return strings.ReplaceAll(fmt.Sprint(v), "_", " ") }

// countSegs turns counts by state into segments, in the given order.
func countSegs(counts map[string]int, order ...string) []seg {
	var out []seg
	for _, state := range order {
		if counts[state] > 0 {
			out = append(out, seg{Label: label(state), N: counts[state], Fill: "s-" + tone(state)})
		}
	}
	return out
}

// summaryCard is one of the figures at the top of the overview.
type summaryCard struct {
	Label, Big, Unit, Link, Href string
	Segs                         []seg
}

// overviewPage is the overview with its summary and, when a control was
// asked for, that control's detail.
type overviewPage struct {
	*assurance.Overview
	Summary []summaryCard
	Detail  *assurance.ControlView
}

func requirementSegs(reqs []assurance.RequirementView) []seg {
	counts := map[string]int{}
	for _, r := range reqs {
		counts[string(r.State)]++
	}
	segs := countSegs(counts, "partly_evidenced", "accepted_risk", "not_evaluated", "stale", "needs_attention", "tracked_manually")
	if n := counts["not_implemented"]; n > 0 {
		segs = append(segs, seg{"not implemented", n, "s-neutral"})
	}
	if n := counts["out_of_scope"]; n > 0 {
		segs = append(segs, seg{"out of scope", n, "s-dim"})
	}
	for i := range segs {
		if segs[i].Label == "tracked manually" {
			segs[i].Fill = "s-soft"
		}
	}
	return segs
}

func buildOverview(ov *assurance.Overview, reqs []assurance.RequirementView, findings []assurance.FindingView, health *assurance.Health, detailKey string) overviewPage {
	p := overviewPage{Overview: ov}
	controls := map[string]int{}
	for i, c := range ov.Controls {
		controls[string(c.State)]++
		if c.Control.Key == detailKey {
			p.Detail = &ov.Controls[i]
		}
	}
	covered, tracked := 0, 0
	evidenced := map[string]int{}
	for _, r := range reqs {
		if len(r.Controls) > 0 {
			covered++
			evidenced[string(r.State)]++
		} else {
			tracked++
		}
	}
	reqSegs := countSegs(evidenced, "partly_evidenced", "accepted_risk", "not_evaluated", "stale", "needs_attention")
	if tracked > 0 {
		reqSegs = append(reqSegs, seg{"tracked, with a reason", tracked, "s-neutral"})
	}
	open, closed := 0, 0
	for _, f := range findings {
		if f.Open() {
			open++
		} else {
			closed++
		}
	}
	jobs := map[string]int{}
	for _, j := range health.Jobs {
		switch {
		case j.Status == assurance.JobFailing || j.Status == assurance.JobRetrying:
			jobs[string(j.Status)]++
		case j.Stale && j.Status != assurance.JobPending:
			jobs["stale"]++
		default:
			jobs[string(j.Status)]++
		}
	}
	p.Summary = []summaryCard{
		{"Controls", fmt.Sprint(len(ov.Controls)), "internal controls", "Details", "#controls",
			countSegs(controls, "supported", "accepted_risk", "stale", "not_evaluated", "needs_attention")},
		{"MVSP requirements", fmt.Sprint(covered), fmt.Sprintf("of %d covered in part", len(reqs)), "View", "/requirements", reqSegs},
		{"Findings", fmt.Sprint(open), "open", "View", "/findings",
			[]seg{{"open", open, "s-fail"}, {"closed", closed, "s-pass"}}},
		{"Integration health", fmt.Sprint(len(health.Jobs)), "collection jobs", "View", "/integrations",
			countSegs(jobs, "healthy", "pending", "retrying", "stale", "failing")},
	}
	// Always show both sides of the findings and health cards, zero or not.
	if len(health.Jobs) > 0 && health.Problems == 0 {
		p.Summary[3].Segs = append(p.Summary[3].Segs, seg{"failing, retrying or stale", 0, "s-neutral"})
	}
	return p
}

// findingsPage is the list of findings and the one selected.
type findingsPage struct {
	List     []assurance.FindingView
	Selected *assurance.FindingView
}

func buildFindings(all []assurance.FindingView, id int64) findingsPage {
	p := findingsPage{List: all}
	for i := range all {
		if all[i].ID == id {
			p.Selected = &all[i]
		}
	}
	if p.Selected == nil && len(all) > 0 {
		p.Selected = &all[0]
	}
	return p
}

// requirementGroup is the requirements of one group of the catalog.
type requirementGroup struct {
	N    string
	Name string
	Rows []assurance.RequirementView
}

// requirementsPage is the requirements grouped as the catalog groups them.
type requirementsPage struct {
	Framework, Version string
	Total              int
	Segs               []seg
	Groups             []requirementGroup
}

func buildRequirements(reqs []assurance.RequirementView) requirementsPage {
	p := requirementsPage{Total: len(reqs), Segs: requirementSegs(reqs)}
	for _, r := range reqs {
		p.Framework, p.Version = strings.ToUpper(r.Framework), r.FrameworkVersion
		if n := len(p.Groups); n == 0 || p.Groups[n-1].Name != r.Group {
			number, _, _ := strings.Cut(r.ID, ".")
			p.Groups = append(p.Groups, requirementGroup{N: number, Name: r.Group})
		}
		g := &p.Groups[len(p.Groups)-1]
		g.Rows = append(g.Rows, r)
	}
	return p
}

// providerCard is the jobs of one resource of one source.
type providerCard struct {
	Name, Icon, Resource string
	// Summary and SummaryState head the card: "3 healthy", or the worst state.
	Summary, SummaryState string
	Jobs                  []assurance.JobView
}

// healthPage is integration health with its jobs grouped by resource.
type healthPage struct {
	*assurance.Health
	Providers []providerCard
}

var providerNames = map[string][2]string{"github": {"GitHub", "ph-github-logo"}, "aws": {"AWS", "ph-cloud"}}

func buildHealth(h *assurance.Health) healthPage {
	p := healthPage{Health: h}
	for _, j := range h.Jobs {
		if n := len(p.Providers); n == 0 || p.Providers[n-1].Resource != j.Resource {
			name := providerNames[j.Provider]
			if name[0] == "" {
				name = [2]string{j.Provider, "ph-plugs-connected"}
			}
			p.Providers = append(p.Providers, providerCard{Name: name[0], Icon: name[1], Resource: j.Resource})
		}
		card := &p.Providers[len(p.Providers)-1]
		card.Jobs = append(card.Jobs, j)
	}
	for i := range p.Providers {
		card := &p.Providers[i]
		healthy, worst := 0, ""
		rank := map[string]int{"pending": 1, "stale": 2, "retrying": 3, "failing": 4}
		for _, j := range card.Jobs {
			state := string(j.Status)
			if state == "healthy" && j.Stale {
				state = "stale"
			}
			if state == "healthy" {
				healthy++
			} else if rank[state] > rank[worst] {
				worst = state
			}
		}
		if worst == "" {
			card.Summary, card.SummaryState = fmt.Sprintf("%d healthy", healthy), "healthy"
		} else {
			card.Summary, card.SummaryState = fmt.Sprintf("%d of %d healthy", healthy, len(card.Jobs)), worst
		}
	}
	return p
}

// packageItems says what a review package holds.
var packageItems = []string{
	"Control and requirement states as they stood at the end of the period",
	"Every collection run, observation and evaluation in it",
	"Findings that were open, with their exceptions and notes",
	"The decision log",
	"The evidence files",
	"index.html, a reading copy, and manifest.json with the SHA-256 of every file",
}

// runCoverage says what a run read, in a word.
func runCoverage(r store.RunRow) string {
	switch {
	case r.Outcome != "succeeded":
		return "none"
	case r.InventoryComplete:
		return "complete"
	default:
		return "incomplete"
	}
}

// evidenceWindow describes how long a control's evidence counts.
func evidenceWindow(c control.Control) string {
	switch {
	case c.ManualCheck != "" && c.Freshness == 0:
		return fmt.Sprintf("Manual evidence, valid %d months", c.ManualValidityMonths)
	case c.Freshness > 0:
		return fmt.Sprintf("%d hours", int(c.Freshness.Hours()))
	default:
		return "None"
	}
}
