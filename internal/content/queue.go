package content

import (
	"fmt"
	"sort"
	"strings"
)

// waves is the order frameworks are reviewed in. A framework not listed
// comes last. The first release's framework is wave 0.
var waves = map[string]int{
	"mvsp": 0,
	"soc2": 1, "iso-27001": 1, "iso-42001": 1, "nist-csf": 1, "nist-800-53": 1, "nist-ai-rmf": 1,
	"fedramp": 2, "nist-800-171": 2, "cmmc": 2, "hipaa": 2, "gdpr": 2, "eu-ai-act": 2, "pci-dss": 2, "cis": 2,
}

// Wave is the review wave a framework belongs to.
func Wave(framework string) int {
	if w, ok := waves[framework]; ok {
		return w
	}
	return 9
}

// Counts is how much of one group of entries has been reviewed.
type Counts struct {
	Name     string
	Draft    int
	Reviewed int
	// Noted is how many drafts carry a reviewer note: a doubt the agent
	// recorded, which blocks signing until it is cleared.
	Noted int
	// NotAssessed is how many tracking entries say only that nobody has
	// looked at the requirement. They are neither drafts nor reviewed, and
	// are not in the queue.
	NotAssessed int
}

// Total is every entry in the group.
func (c Counts) Total() int { return c.Draft + c.Reviewed }

// QueueItem is one draft waiting for the maintainer.
type QueueItem struct {
	// Kind is control, mapping, tracking or exclusion.
	Kind string
	// Group is the domain for a control, the organization for an exclusion
	// and the framework otherwise.
	Group string
	Path  string
	Entry string
	// Summary is what the entry says, in a line.
	Summary string
	Note    string
	// Sign is the command that signs this entry.
	Sign string
}

// Queue is what is waiting for review, in the order to review it.
type Queue struct {
	Controls []Counts // by domain
	Mappings []Counts // by framework
	Tracking []Counts // by organization and framework
	Scope    []Counts // exclusions, by organization
	// Items are the drafts: controls first, then mappings and tracking
	// entries wave by wave and framework by framework. Within each group,
	// entries with a reviewer note come first.
	Items []QueueItem
}

// Drafts is how many entries are waiting.
func (q Queue) Drafts() int { return len(q.Items) }

// Reviewed is how many entries have been signed.
func (q Queue) Reviewed() int {
	n := 0
	for _, list := range [][]Counts{q.Controls, q.Mappings, q.Tracking, q.Scope} {
		for _, c := range list {
			n += c.Reviewed
		}
	}
	return n
}

// NotAssessed is how many tracking entries say only that nobody has looked
// at the requirement for that organization.
func (q Queue) NotAssessed() int {
	n := 0
	for _, c := range q.Tracking {
		n += c.NotAssessed
	}
	return n
}

// BuildQueue works out the review queue for a set.
func BuildQueue(s *Set) Queue {
	var q Queue
	tally := func(list *[]Counts, index map[string]int, name string, r Review, note string) {
		i, ok := index[name]
		if !ok {
			i = len(*list)
			index[name] = i
			*list = append(*list, Counts{Name: name})
		}
		c := &(*list)[i]
		if r.IsReviewed() {
			c.Reviewed++
			return
		}
		c.Draft++
		if note != "" {
			c.Noted++
		}
	}

	domainOrder := map[string]int{}
	for i, d := range Domains {
		domainOrder[d] = i
	}
	controls := append([]Control(nil), s.Controls...)
	sort.SliceStable(controls, func(i, j int) bool {
		a, b := controls[i], controls[j]
		if a.Domain != b.Domain {
			return domainOrder[a.Domain] < domainOrder[b.Domain]
		}
		if (a.ReviewerNote != "") != (b.ReviewerNote != "") {
			return a.ReviewerNote != ""
		}
		return a.Key < b.Key
	})
	idx := map[string]int{}
	for _, c := range controls {
		tally(&q.Controls, idx, c.Domain, c.Review, c.ReviewerNote)
		if !c.Review.IsReviewed() {
			q.Items = append(q.Items, QueueItem{
				Kind: "control", Group: c.Domain, Path: c.Path, Entry: c.Key,
				Summary: c.Statement, Note: c.ReviewerNote,
				Sign: "cca review sign " + c.Path,
			})
		}
	}

	byFramework := func(fi, fj string) (less, same bool) {
		if fi == fj {
			return false, true
		}
		if Wave(fi) != Wave(fj) {
			return Wave(fi) < Wave(fj), false
		}
		return fi < fj, false
	}
	mappings := append([]Mapping(nil), s.Mappings...)
	sort.SliceStable(mappings, func(i, j int) bool {
		if less, same := byFramework(mappings[i].Framework, mappings[j].Framework); !same {
			return less
		}
		return mappings[i].ReviewerNote != "" && mappings[j].ReviewerNote == ""
	})
	idx = map[string]int{}
	for _, m := range mappings {
		tally(&q.Mappings, idx, m.Framework, m.Review, m.ReviewerNote)
		if !m.Review.IsReviewed() {
			q.Items = append(q.Items, QueueItem{
				Kind: "mapping", Group: m.Framework, Path: m.Path, Entry: m.Control + " -> " + m.Requirement,
				Summary: m.Strength + ". " + m.Rationale, Note: m.ReviewerNote,
				Sign: fmt.Sprintf("cca review sign %s --control %s --requirement %s", m.Path, m.Control, shellArg(m.Requirement)),
			})
		}
	}
	tracking := append([]Tracking(nil), s.Tracking...)
	sort.SliceStable(tracking, func(i, j int) bool {
		if tracking[i].Organization != tracking[j].Organization {
			return tracking[i].Organization < tracking[j].Organization
		}
		if less, same := byFramework(tracking[i].Framework, tracking[j].Framework); !same {
			return less
		}
		return tracking[i].ReviewerNote != "" && tracking[j].ReviewerNote == ""
	})
	idx = map[string]int{}
	for _, t := range tracking {
		group := t.Organization + ": " + t.Framework
		if !t.Assessed() {
			i, ok := idx[group]
			if !ok {
				i = len(q.Tracking)
				idx[group] = i
				q.Tracking = append(q.Tracking, Counts{Name: group})
			}
			q.Tracking[i].NotAssessed++
			continue
		}
		tally(&q.Tracking, idx, group, t.Review, t.ReviewerNote)
		if !t.Review.IsReviewed() {
			q.Items = append(q.Items, QueueItem{
				Kind: "tracking", Group: group, Path: t.Path, Entry: t.Requirement,
				Summary: strings.ReplaceAll(t.Status, "_", " ") + ". " + t.Rationale, Note: t.ReviewerNote,
				Sign: fmt.Sprintf("cca review sign %s --requirement %s", t.Path, shellArg(t.Requirement)),
			})
		}
	}
	idx = map[string]int{}
	for _, sc := range s.Scopes {
		// An organization with no exclusion is still listed, with zeroes.
		idx[sc.Organization] = len(q.Scope)
		q.Scope = append(q.Scope, Counts{Name: sc.Organization})
		xs := append([]Exclusion(nil), sc.Exclusions...)
		sort.SliceStable(xs, func(i, j int) bool { return xs[i].ReviewerNote != "" && xs[j].ReviewerNote == "" })
		for _, x := range xs {
			tally(&q.Scope, idx, x.Organization, x.Review, x.ReviewerNote)
			if !x.Review.IsReviewed() {
				q.Items = append(q.Items, QueueItem{
					Kind: "exclusion", Group: x.Organization, Path: x.Path, Entry: x.Control,
					Summary: "Does not apply to " + x.Organization + ". " + x.Reason, Note: x.ReviewerNote,
					Sign: fmt.Sprintf("cca review sign %s --control %s", x.Path, x.Control),
				})
			}
		}
	}
	return q
}

// shellArg quotes an identifier for a shell when it needs it.
func shellArg(s string) string {
	for _, r := range s {
		plain := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' || r == ':'
		if !plain {
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}

// StatusText is the review status as a table for a terminal.
func (q Queue) StatusText() string {
	var b strings.Builder
	section := func(title string, list []Counts) {
		fmt.Fprintf(&b, "%s\n", title)
		if len(list) == 0 {
			b.WriteString("  none\n")
		}
		for _, c := range list {
			fmt.Fprintf(&b, "  %-22s %4d reviewed  %4d draft", c.Name, c.Reviewed, c.Draft)
			if c.Noted > 0 {
				fmt.Fprintf(&b, "  (%d blocked by a reviewer note)", c.Noted)
			}
			if c.NotAssessed > 0 {
				fmt.Fprintf(&b, "  %4d not assessed", c.NotAssessed)
			}
			b.WriteString("\n")
		}
	}
	section("Controls, by domain", q.Controls)
	section("Mappings, by framework", q.Mappings)
	section("Tracking entries, by organization and framework", q.Tracking)
	section("Exclusions, by organization", q.Scope)
	fmt.Fprintf(&b, "\n%d reviewed, %d waiting\n", q.Reviewed(), q.Drafts())
	if n := q.NotAssessed(); n > 0 {
		fmt.Fprintf(&b, "%d tracking entries not assessed yet; nothing to review for them\n", n)
	}
	return b.String()
}

// Markdown is the review queue as a document.
func (q Queue) Markdown() string {
	var b strings.Builder
	b.WriteString("# Review queue\n\n")
	b.WriteString("Generated by `cca review queue` from the files under `controls/`, `mappings/`, `tracking/` and `scope/`. Do not edit by hand; run `make content`.\n\n")
	b.WriteString("Everything listed here was drafted by an AI agent and has not been reviewed. ")
	b.WriteString("To review an entry: read it, edit the YAML until it is right, run `make content`, then run the command shown to sign it. ")
	b.WriteString("An entry with a **note** carries a doubt the agent recorded; clear the `reviewer_note` once it is settled, or the entry cannot be signed.\n\n")
	fmt.Fprintf(&b, "**%d reviewed, %d waiting.**\n\n", q.Reviewed(), q.Drafts())
	if n := q.NotAssessed(); n > 0 {
		fmt.Fprintf(&b, "%d tracking entries are marked `not_assessed`: nobody has looked at that requirement for that organization yet, so there is nothing to review and they are not listed below.\n\n", n)
	}

	table := func(title, head string, list []Counts) {
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(&b, "## %s\n\n| %s | Reviewed | Draft | Blocked by a note |\n| --- | --- | --- | --- |\n", title, head)
		for _, c := range list {
			fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", c.Name, c.Reviewed, c.Draft, c.Noted)
		}
		b.WriteString("\n")
	}
	table("Controls", "Domain", q.Controls)
	table("Mappings", "Framework", q.Mappings)
	if len(q.Tracking) > 0 {
		b.WriteString("## Tracking entries\n\n| Organization: framework | Reviewed | Draft | Blocked by a note | Not assessed |\n| --- | --- | --- | --- | --- |\n")
		for _, c := range q.Tracking {
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %d |\n", c.Name, c.Reviewed, c.Draft, c.Noted, c.NotAssessed)
		}
		b.WriteString("\n")
	}

	table("Exclusions", "Organization", q.Scope)

	heads := map[string]string{"control": "Controls: %s", "mapping": "Mappings: %s", "tracking": "Tracking entries: %s", "exclusion": "Exclusions: %s"}
	last := ""
	for _, it := range q.Items {
		if h := it.Kind + "/" + it.Group; h != last {
			last = h
			fmt.Fprintf(&b, "## "+heads[it.Kind]+"\n\n", it.Group)
			if it.Kind != "control" {
				fmt.Fprintf(&b, "File: `%s`. To sign every entry in it at once: `cca review sign %s --all`.\n\n", it.Path, it.Path)
			}
		}
		fmt.Fprintf(&b, "- **%s**: %s\n", it.Entry, it.Summary)
		if it.Note != "" {
			fmt.Fprintf(&b, "  - **Note:** %s\n", it.Note)
		}
		fmt.Fprintf(&b, "  - `%s`\n", it.Sign)
	}
	if len(q.Items) == 0 {
		b.WriteString("Nothing is waiting.\n")
	}
	return b.String()
}
