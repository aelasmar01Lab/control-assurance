// Package content reads the files the maintainer edits: controls, mappings
// and tracking entries. It validates them against their schemas and against
// each other, and it knows which entries have been reviewed.
//
// Everything here is drafted by an AI agent and reviewed by the maintainer.
// An entry is a draft until it is signed, and a signature covers a hash of
// the entry's content, so an entry edited after signing no longer verifies.
package content

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/aelasmar01Lab/control-assurance/internal/check"
	"github.com/aelasmar01Lab/control-assurance/internal/pack"
)

// Domains are the control domains, which are also the folder names under
// controls/. A control's key starts with its domain.
var Domains = []string{
	"governance", "risk", "people", "access", "assets", "change", "secure-development",
	"vulnerability", "logging", "incident", "continuity", "data-protection", "cryptography",
	"network", "endpoint", "vendor", "physical", "privacy", "ai-governance",
}

// firstReleaseKeys are the eight controls of the first release. Their keys
// predate the rule that a key starts with its domain, and a key is never
// renamed, so they are the only exceptions to it.
var firstReleaseKeys = map[string]bool{
	"change-management": true, "dependency-remediation": true, "vulnerability-disclosure": true,
	"human-access": true, "credential-lifecycle": true, "audit-logging": true,
	"ai-usage-logging": true, "backup-recovery": true,
}

// BannedWords may not appear in a draft control. They are the words that
// let a statement sound finished without saying what is true.
var BannedWords = []string{"compliant", "ensures", "guarantees", "robust", "appropriate", "as needed"}

// MaxTitleWords is the most words a control title may have.
const MaxTitleWords = 8

// The review statuses.
const (
	Draft    = "draft"
	Reviewed = "reviewed"
)

// Review says whether a person has reviewed an entry, and what content
// they reviewed.
type Review struct {
	Status        string `yaml:"status" json:"status"`
	DraftedBy     string `yaml:"drafted_by" json:"drafted_by"`
	ReviewedBy    string `yaml:"reviewed_by" json:"reviewed_by"`
	ReviewedOn    string `yaml:"reviewed_on" json:"reviewed_on"`
	ContentSHA256 string `yaml:"content_sha256" json:"content_sha256"`
}

// IsReviewed reports whether the entry has been signed.
func (r Review) IsReviewed() bool { return r.Status == Reviewed }

// Label is how the review is shown beside the entry, everywhere.
func (r Review) Label() string {
	if r.IsReviewed() {
		return "reviewed by " + r.ReviewedBy + " on " + r.ReviewedOn
	}
	return "draft, not reviewed"
}

// ManualEvidence says what a person submits for a control, and how long an
// accepted submission counts.
type ManualEvidence struct {
	Expectation    string `yaml:"expectation" json:"expectation"`
	ValidityMonths int    `yaml:"validity_months" json:"validity_months"`
}

// Control is one control file.
type Control struct {
	Key                 string          `yaml:"key" json:"key"`
	Title               string          `yaml:"title" json:"title"`
	Statement           string          `yaml:"statement" json:"statement"`
	Risk                string          `yaml:"risk" json:"risk"`
	OwnerRole           string          `yaml:"owner_role" json:"owner_role"`
	Type                string          `yaml:"type" json:"type"`
	Checks              []string        `yaml:"checks" json:"checks"`
	ManualEvidence      *ManualEvidence `yaml:"manual_evidence" json:"manual_evidence,omitempty"`
	EvidenceExpectation string          `yaml:"evidence_expectation" json:"evidence_expectation"`
	FreshnessHours      int             `yaml:"freshness_hours" json:"freshness_hours,omitempty"`
	ReviewerNote        string          `yaml:"reviewer_note" json:"reviewer_note,omitempty"`
	Review              Review          `yaml:"review" json:"-"`

	// Domain is the folder the file is in.
	Domain string `yaml:"-" json:"domain"`
	// Path is the file, relative to the content root.
	Path string `yaml:"-" json:"-"`
}

// Mapping ties a control to a requirement of one framework version.
type Mapping struct {
	Control      string `yaml:"control" json:"control"`
	Requirement  string `yaml:"requirement" json:"requirement"`
	Strength     string `yaml:"strength" json:"strength"`
	Rationale    string `yaml:"rationale" json:"rationale"`
	Limitation   string `yaml:"limitation" json:"limitation,omitempty"`
	Basis        string `yaml:"basis" json:"basis"`
	BasisSource  string `yaml:"basis_source" json:"basis_source,omitempty"`
	ReviewerNote string `yaml:"reviewer_note" json:"reviewer_note,omitempty"`
	Review       Review `yaml:"review" json:"-"`

	Framework string `yaml:"-" json:"framework"`
	Version   string `yaml:"-" json:"version"`
	Path      string `yaml:"-" json:"-"`
}

// EffectiveStrength is the strength the mapping counts as. A direct mapping
// that nobody has reviewed counts as partial.
func (m Mapping) EffectiveStrength() string {
	if m.Strength == "direct" && !m.Review.IsReviewed() {
		return "partial"
	}
	return m.Strength
}

// NotAssessed is the tracking status of a requirement nobody has looked at
// yet. Such an entry carries only the requirement and the status: there is
// nothing in it to review, so it has no review block, is never signed and
// is left out of the review queue.
const NotAssessed = "not_assessed"

// Assessed reports whether the entry says anything about the requirement.
func (t Tracking) Assessed() bool { return t.Status != NotAssessed }

// Tracking says how a requirement that no control covers is tracked.
type Tracking struct {
	Requirement         string `yaml:"requirement" json:"requirement"`
	Status              string `yaml:"status" json:"status"`
	OwnerRole           string `yaml:"owner_role" json:"owner_role"`
	Applicability       string `yaml:"applicability" json:"applicability"`
	EvidenceExpectation string `yaml:"evidence_expectation" json:"evidence_expectation"`
	Rationale           string `yaml:"rationale" json:"rationale"`
	Note                string `yaml:"note" json:"note,omitempty"`
	ReviewerNote        string `yaml:"reviewer_note" json:"reviewer_note,omitempty"`
	Review              Review `yaml:"review" json:"-"`

	Framework string `yaml:"-" json:"framework"`
	Version   string `yaml:"-" json:"version"`
	Path      string `yaml:"-" json:"-"`
}

type mappingFile struct {
	Framework string    `yaml:"framework"`
	Version   string    `yaml:"version"`
	Mappings  []Mapping `yaml:"mappings"`
}

type trackingFile struct {
	Framework string     `yaml:"framework"`
	Version   string     `yaml:"version"`
	Entries   []Tracking `yaml:"entries"`
}

// Set is everything read from one content root.
type Set struct {
	Controls []Control
	Mappings []Mapping
	Tracking []Tracking
	// Scopes are the organizations the controls are applied to.
	Scopes []Scope
}

// Scope is one organization the controls are applied to. Controls describe
// a generic small company; a scope lists the ones that do not apply to this
// organization. A control not listed applies.
type Scope struct {
	Organization string `yaml:"organization"`
	// Name is what the organization is called, when it has a name.
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// Synthetic marks an organization that does not exist: every record of
	// it is made up, and every page about it says so.
	Synthetic  bool        `yaml:"synthetic"`
	Exclusions []Exclusion `yaml:"exclusions"`
	Path       string      `yaml:"-"`
}

// Exclusion says a control does not apply to one organization, and why. It
// takes effect only once reviewed: a draft exclusion changes no state.
type Exclusion struct {
	Control      string `yaml:"control" json:"control"`
	Reason       string `yaml:"reason" json:"reason"`
	ReviewerNote string `yaml:"reviewer_note" json:"reviewer_note,omitempty"`
	Review       Review `yaml:"review" json:"-"`

	Organization string `yaml:"-" json:"organization"`
	Path         string `yaml:"-" json:"-"`
}

// Scope returns the organization with the given key.
func (s *Set) Scope(organization string) (Scope, bool) {
	for _, sc := range s.Scopes {
		if sc.Organization == organization {
			return sc, true
		}
	}
	return Scope{}, false
}

// Problem is one thing wrong with the content.
type Problem struct {
	Path string
	// Entry names the entry within the file, when the file has several.
	Entry string
	Msg   string
	// Review marks a problem with a signature rather than with the content.
	Review bool
}

func (p Problem) String() string {
	if p.Entry != "" {
		return p.Path + " (" + p.Entry + "): " + p.Msg
	}
	return p.Path + ": " + p.Msg
}

// Problems is a list of problems that is also an error.
type Problems []Problem

func (ps Problems) Error() string {
	lines := make([]string, len(ps))
	for i, p := range ps {
		lines[i] = p.String()
	}
	return strings.Join(lines, "\n")
}

// Refs is what content is validated against.
type Refs struct {
	// Packs are the framework packs a mapping or tracking entry may name.
	Packs []*pack.Pack
	// Checks are the keys of the checks a control may rest on.
	Checks map[string]bool
}

// BuiltInRefs returns the given packs with the checks registered in code.
func BuiltInRefs(packs []*pack.Pack) Refs {
	keys := map[string]bool{}
	for _, c := range check.All() {
		keys[c.Key] = true
	}
	return Refs{Packs: packs, Checks: keys}
}

const (
	controlSchemaPath  = "controls/control.schema.json"
	mappingSchemaPath  = "mappings/mapping.schema.json"
	trackingSchemaPath = "tracking/tracking.schema.json"
	scopeSchemaPath    = "scope/scope.schema.json"
)

// Load reads every content file under fsys and validates it. It returns
// what it could read together with every problem found; the set is usable
// only when there are no problems.
func Load(fsys fs.FS, refs Refs) (*Set, Problems) {
	set := &Set{}
	var problems Problems
	add := func(p, entry, format string, args ...any) {
		problems = append(problems, Problem{Path: p, Entry: entry, Msg: fmt.Sprintf(format, args...)})
	}

	controlSchema, err1 := compile(fsys, controlSchemaPath)
	mappingSchema, err2 := compile(fsys, mappingSchemaPath)
	trackingSchema, err3 := compile(fsys, trackingSchemaPath)
	for p, err := range map[string]error{controlSchemaPath: err1, mappingSchemaPath: err2, trackingSchemaPath: err3} {
		if err != nil {
			add(p, "", "%v", err)
		}
	}
	if len(problems) > 0 {
		return set, problems
	}

	// Controls: controls/<domain>/<key>.yaml.
	files, _ := fs.Glob(fsys, "controls/*/*.yaml")
	sort.Strings(files)
	stray, _ := fs.Glob(fsys, "controls/*.yaml")
	for _, p := range stray {
		add(p, "", "a control file belongs in a domain folder, controls/<domain>/")
	}
	for _, p := range files {
		var c Control
		if err := readFile(fsys, p, controlSchema, &c); err != nil {
			add(p, "", "%v", err)
			continue
		}
		c.Path, c.Domain = p, path.Base(path.Dir(p))
		trimControl(&c)
		set.Controls = append(set.Controls, c)
	}

	// Mappings and tracking: one file per framework.
	files, _ = fs.Glob(fsys, "mappings/*.yaml")
	sort.Strings(files)
	for _, p := range files {
		var f mappingFile
		if err := readFile(fsys, p, mappingSchema, &f); err != nil {
			add(p, "", "%v", err)
			continue
		}
		if want := "mappings/" + f.Framework + ".yaml"; p != want {
			add(p, "", "the file for framework %q is %s", f.Framework, want)
		}
		for _, m := range f.Mappings {
			m.Framework, m.Version, m.Path = f.Framework, f.Version, p
			trimMapping(&m)
			set.Mappings = append(set.Mappings, m)
		}
	}
	files, _ = fs.Glob(fsys, "tracking/*.yaml")
	sort.Strings(files)
	for _, p := range files {
		var f trackingFile
		if err := readFile(fsys, p, trackingSchema, &f); err != nil {
			add(p, "", "%v", err)
			continue
		}
		if want := "tracking/" + f.Framework + ".yaml"; p != want {
			add(p, "", "the file for framework %q is %s", f.Framework, want)
		}
		for _, t := range f.Entries {
			t.Framework, t.Version, t.Path = f.Framework, f.Version, p
			trimTracking(&t)
			set.Tracking = append(set.Tracking, t)
		}
	}

	// Scope: one file per organization. A content root may have none.
	files, _ = fs.Glob(fsys, "scope/*.yaml")
	sort.Strings(files)
	if len(files) > 0 {
		scopeSchema, err := compile(fsys, scopeSchemaPath)
		if err != nil {
			add(scopeSchemaPath, "", "%v", err)
			files = nil
		}
		for _, p := range files {
			var sc Scope
			if err := readFile(fsys, p, scopeSchema, &sc); err != nil {
				add(p, "", "%v", err)
				continue
			}
			if want := "scope/" + sc.Organization + ".yaml"; p != want {
				add(p, "", "the file for organization %q is %s", sc.Organization, want)
			}
			sc.Path = p
			sc.Name, sc.Description = strings.TrimSpace(sc.Name), strings.TrimSpace(sc.Description)
			for i := range sc.Exclusions {
				x := &sc.Exclusions[i]
				x.Organization, x.Path = sc.Organization, p
				x.Reason, x.ReviewerNote = strings.TrimSpace(x.Reason), strings.TrimSpace(x.ReviewerNote)
			}
			set.Scopes = append(set.Scopes, sc)
		}
	}

	problems = append(problems, set.check(refs)...)
	return set, problems
}

// check applies the rules a schema cannot express.
func (s *Set) check(refs Refs) Problems {
	var problems Problems
	add := func(p, entry, format string, args ...any) {
		problems = append(problems, Problem{Path: p, Entry: entry, Msg: fmt.Sprintf(format, args...)})
	}
	review := func(p, entry string, r Review, note, hash string) {
		for _, msg := range checkReview(r, note, hash) {
			problems = append(problems, Problem{Path: p, Entry: entry, Msg: msg, Review: true})
		}
	}
	domains := map[string]bool{}
	for _, d := range Domains {
		domains[d] = true
	}

	manualCheck := map[string]bool{}
	for _, c := range check.All() {
		manualCheck[c.Key] = c.Manual
	}

	controls := map[string]Control{}
	for _, c := range s.Controls {
		if prev, ok := controls[c.Key]; ok {
			add(c.Path, "", "control %q is already defined in %s", c.Key, prev.Path)
			continue
		}
		controls[c.Key] = c
		if !domains[c.Domain] {
			add(c.Path, "", "%q is not a control domain", c.Domain)
		}
		if want := c.Key + ".yaml"; path.Base(c.Path) != want {
			add(c.Path, "", "the file for control %q is named %s", c.Key, want)
		}
		if !firstReleaseKeys[c.Key] && !strings.HasPrefix(c.Key, c.Domain+"-") {
			add(c.Path, "", "the key starts with the domain: %s-...", c.Domain)
		}
		if n := len(strings.Fields(c.Title)); n > MaxTitleWords {
			add(c.Path, "", "the title has %d words; the most is %d", n, MaxTitleWords)
		}
		if !c.Review.IsReviewed() {
			// A person who signs a word has chosen it; a draft has not.
			text := strings.ToLower(strings.Join([]string{c.Title, c.Statement, c.Risk, c.EvidenceExpectation}, " \n "))
			for _, w := range BannedWords {
				if containsWord(text, w) {
					add(c.Path, "", "a draft control may not use %q", w)
				}
			}
		}
		manualChecks := 0
		for _, k := range c.Checks {
			if !refs.Checks[k] {
				add(c.Path, "", "check %q does not exist", k)
			}
			if manualCheck[k] {
				manualChecks++
			}
		}
		automated := len(c.Checks) - manualChecks
		switch {
		case manualChecks > 1:
			add(c.Path, "", "a control rests on at most one manual-evidence check")
		case manualChecks == 1 && c.ManualEvidence == nil:
			add(c.Path, "", "a control that rests on a manual-evidence check needs manual_evidence")
		case automated > 0 && c.FreshnessHours <= 0:
			add(c.Path, "", "a control with automated checks needs freshness_hours")
		case c.Type == "automated" && c.ManualEvidence != nil:
			add(c.Path, "", "an automated control takes no manual evidence; its type is hybrid")
		case c.Type == "manual" && automated > 0:
			add(c.Path, "", "a manual control has no automated checks; its type is hybrid")
		case (c.Type == "manual" || c.Type == "hybrid") && c.ManualEvidence == nil:
			add(c.Path, "", "a %s control needs manual_evidence", c.Type)
		}
		review(c.Path, "", c.Review, c.ReviewerNote, c.Hash())
	}

	packs := map[string]*pack.Pack{}
	versions := map[string][]string{}
	for _, p := range refs.Packs {
		packs[p.ID()] = p
		versions[p.Framework.Key] = append(versions[p.Framework.Key], p.Framework.Version)
	}
	// requirement reports whether a pack version has the requirement.
	requirement := func(p, entry, framework, version, id string) bool {
		pk, ok := packs[framework+"@"+version]
		if !ok {
			if have := versions[framework]; len(have) > 0 {
				add(p, "", "framework %s has no version %q; it has %s", framework, version, strings.Join(have, ", "))
			} else {
				add(p, "", "framework %q is not a built-in pack", framework)
			}
			return false
		}
		r, ok := pk.Lookup(id)
		if !ok {
			add(p, entry, "%s %s has no requirement %q", framework, version, id)
			return false
		}
		if r.Heading {
			add(p, entry, "%s %s is a heading of %s, not a requirement; map or track what is under it", framework, id, framework)
			return false
		}
		return true
	}

	type pair struct{ framework, a, b string }
	seenMapping := map[pair]bool{}
	mapped := map[pair]bool{}
	badFile := map[string]bool{}
	for _, m := range s.Mappings {
		entry := m.Control + " -> " + m.Requirement
		if badFile[m.Path] {
			continue
		}
		if _, ok := packs[m.Framework+"@"+m.Version]; !ok {
			requirement(m.Path, entry, m.Framework, m.Version, m.Requirement)
			badFile[m.Path] = true
			continue
		}
		requirement(m.Path, entry, m.Framework, m.Version, m.Requirement)
		if _, ok := controls[m.Control]; !ok {
			add(m.Path, entry, "control %q does not exist", m.Control)
		}
		k := pair{m.Framework, m.Control, m.Requirement}
		if seenMapping[k] {
			add(m.Path, entry, "this pair is mapped twice")
		}
		seenMapping[k] = true
		mapped[pair{m.Framework, m.Version, m.Requirement}] = true
		if m.Strength != "direct" && m.Limitation == "" {
			add(m.Path, entry, "a %s mapping states its limitation: what the requirement asks for that the control does not show", m.Strength)
		}
		switch m.Basis {
		case "published_crosswalk":
			if !strings.HasPrefix(m.BasisSource, "https://") {
				add(m.Path, entry, "a mapping from a published crosswalk names it by URL in basis_source")
			}
		case "derived":
			if !strings.HasPrefix(m.BasisSource, "via ") {
				add(m.Path, entry, "a derived mapping names its path in basis_source, such as \"via nist-800-53:IA-2(1)\"")
			}
			if m.Strength != "supporting" {
				add(m.Path, entry, "a derived mapping is at most supporting")
			}
		}
		review(m.Path, entry, m.Review, m.ReviewerNote, m.Hash())
	}

	seenTracking := map[pair]bool{}
	for _, t := range s.Tracking {
		if badFile[t.Path] {
			continue
		}
		if _, ok := packs[t.Framework+"@"+t.Version]; !ok {
			requirement(t.Path, t.Requirement, t.Framework, t.Version, t.Requirement)
			badFile[t.Path] = true
			continue
		}
		requirement(t.Path, t.Requirement, t.Framework, t.Version, t.Requirement)
		k := pair{t.Framework, t.Version, t.Requirement}
		if seenTracking[k] {
			add(t.Path, t.Requirement, "this requirement is tracked twice")
		}
		seenTracking[k] = true
		if mapped[k] {
			add(t.Path, t.Requirement, "a control maps to this requirement, so it needs no tracking entry")
		}
		if t.Assessed() {
			review(t.Path, t.Requirement, t.Review, t.ReviewerNote, t.Hash())
		}
	}

	for _, sc := range s.Scopes {
		seen := map[string]bool{}
		for _, x := range sc.Exclusions {
			if _, ok := controls[x.Control]; !ok {
				add(sc.Path, x.Control, "control %q does not exist", x.Control)
			}
			if seen[x.Control] {
				add(sc.Path, x.Control, "this control is excluded twice")
			}
			seen[x.Control] = true
			review(sc.Path, x.Control, x.Review, x.ReviewerNote, x.Hash())
		}
	}

	// Every requirement is mapped by a control or tracked with a reason.
	// A profile's requirements are its parent's, and are covered there.
	for _, p := range refs.Packs {
		if p.Framework.ProfileOf != "" {
			continue
		}
		var missing []string
		for _, r := range p.Assessed() {
			k := pair{p.Framework.Key, p.Framework.Version, r.ID}
			if !mapped[k] && !seenTracking[k] {
				missing = append(missing, r.ID)
			}
		}
		if len(missing) > 0 {
			const show = 12
			list := strings.Join(missing[:min(show, len(missing))], ", ")
			if len(missing) > show {
				list += fmt.Sprintf(" and %d more", len(missing)-show)
			}
			add("tracking/"+p.Framework.Key+".yaml", "",
				"%s %s: %d requirements have neither a mapping nor a tracking entry: %s",
				p.Framework.Key, p.Framework.Version, len(missing), list)
		}
	}
	return problems
}

// containsWord reports whether text contains word as whole words.
func containsWord(text, word string) bool {
	for i := 0; ; {
		j := strings.Index(text[i:], word)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(word)
		before := start == 0 || !isLetter(text[start-1])
		after := end == len(text) || !isLetter(text[end])
		if before && after {
			return true
		}
		i = end
	}
}

func isLetter(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }

func trimControl(c *Control) {
	for _, s := range []*string{&c.Title, &c.Statement, &c.Risk, &c.EvidenceExpectation, &c.ReviewerNote} {
		*s = strings.TrimSpace(*s)
	}
	if c.ManualEvidence != nil {
		c.ManualEvidence.Expectation = strings.TrimSpace(c.ManualEvidence.Expectation)
	}
	if c.Checks == nil {
		c.Checks = []string{}
	}
}

func trimMapping(m *Mapping) {
	for _, s := range []*string{&m.Rationale, &m.Limitation, &m.BasisSource, &m.ReviewerNote} {
		*s = strings.TrimSpace(*s)
	}
}

func trimTracking(t *Tracking) {
	for _, s := range []*string{&t.Applicability, &t.EvidenceExpectation, &t.Rationale, &t.Note, &t.ReviewerNote} {
		*s = strings.TrimSpace(*s)
	}
}

func compile(fsys fs.FS, name string) (*jsonschema.Schema, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, fmt.Errorf("the schema is missing: %w", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	// A fixed address, so messages do not depend on the working directory.
	url := "https://github.com/aelasmar01Lab/control-assurance/" + name
	c := jsonschema.NewCompiler()
	if err := c.AddResource(url, doc); err != nil {
		return nil, fmt.Errorf("add schema: %w", err)
	}
	return c.Compile(url)
}

// readFile validates a YAML file against its schema and decodes it.
func readFile(fsys fs.FS, name string, schema *jsonschema.Schema, into any) error {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return err
	}
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	asJSON, err := json.Marshal(plain(raw))
	if err != nil {
		return fmt.Errorf("convert to json: %w", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(asJSON))
	if err != nil {
		return fmt.Errorf("convert to json: %w", err)
	}
	if err := schema.Validate(doc); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			return fmt.Errorf("schema: %s", schemaMessage(ve))
		}
		return fmt.Errorf("schema: %w", err)
	}
	return yaml.Unmarshal(data, into)
}

// schemaMessage flattens a validation error to its leaves, one per line.
func schemaMessage(ve *jsonschema.ValidationError) string {
	var leaves []string
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			at := "/" + strings.Join(e.InstanceLocation, "/")
			leaves = append(leaves, at+": "+e.ErrorKind.LocalizedString(message.NewPrinter(language.English)))
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	return strings.Join(leaves, "; ")
}

// plain turns what YAML decoded into what JSON can hold. A date written
// without quotes is read by YAML as a time; it goes back to a date.
func plain(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = plain(e)
		}
	case []any:
		for i, e := range x {
			x[i] = plain(e)
		}
	case time.Time:
		return x.Format("2006-01-02")
	}
	return v
}
