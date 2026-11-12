package content_test

import (
	"os"
	"strings"
	"testing"
	"testing/fstest"

	contentfs "github.com/aelasmar01Lab/control-assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/content"
	"github.com/aelasmar01Lab/control-assurance/internal/pack"
	"github.com/aelasmar01Lab/control-assurance/packs"
)

const fixturePack = `
framework:
  key: fixture
  title: Fixture Framework
  version: v1
  text_rights: own_composition
  license: Synthetic test data
  source:
    kind: document
    retrieved: "2026-01-01"
requirements:
  - {id: "R1", group: "One", title: "First"}
  - {id: "R2", group: "One", title: "Second"}
  - {id: "R3", group: "One", title: "Third"}
`

const fixtureControl = `key: access-console-mfa
title: MFA on console access
statement: >-
  Every person who can sign in to the console has a second factor.
risk: A stolen password is enough to sign in.
owner_role: control-owner
type: automated
checks: [AWS-01]
evidence_expectation: The credential report, collected every 48 hours.
freshness_hours: 48
reviewer_note: ""
review:
  status: draft
  drafted_by: agent
  reviewed_by: ""
  reviewed_on: ""
  content_sha256: ""
`

const fixtureMappings = `# A comment the signer must keep.
framework: fixture
version: v1
mappings:
  - control: access-console-mfa
    requirement: "R1"
    strength: partial
    rationale: A second factor is one of the things R1 asks for.
    limitation: R1 also asks for account review, which this does not show.
    basis: own_analysis
    review: {status: draft, drafted_by: agent, reviewed_by: "", reviewed_on: "", content_sha256: ""}
  - control: access-console-mfa
    requirement: "R2"
    strength: supporting
    rationale: Sign-in strength is related to what R2 covers.
    limitation: R2 is about session length, which this does not show.
    basis: own_analysis
    review:
      status: draft
      drafted_by: agent
      reviewed_by: ""
      reviewed_on: ""
      content_sha256: ""
`

const fixtureTracking = `framework: fixture
version: v1
entries:
  - requirement: "R3"
    status: not_implemented
    owner_role: control-owner
    applicability: Applicable.
    evidence_expectation: A record of the thing.
    rationale: Nothing addresses it.
    review:
      status: draft
      drafted_by: agent
      reviewed_by: ""
      reviewed_on: ""
      content_sha256: ""
`

const fixtureScope = `organization: fixture-org
description: An organization for tests.
synthetic: true
exclusions:
  - control: access-console-mfa
    reason: The organization has no console.
    review:
      status: draft
      drafted_by: agent
      reviewed_by: ""
      reviewed_on: ""
      content_sha256: ""
`

func fixture(t *testing.T) (fstest.MapFS, content.Refs) {
	t.Helper()
	fsys := fstest.MapFS{
		"controls/access/access-console-mfa.yaml": {Data: []byte(fixtureControl)},
		"mappings/fixture.yaml":                   {Data: []byte(fixtureMappings)},
		"tracking/fixture.yaml":                   {Data: []byte(fixtureTracking)},
	}
	for _, schema := range []string{"controls/control.schema.json", "mappings/mapping.schema.json", "tracking/tracking.schema.json", "scope/scope.schema.json"} {
		data, err := os.ReadFile("../../" + schema) //nolint:gosec // a fixed list of schema files
		if err != nil {
			t.Fatal(err)
		}
		fsys[schema] = &fstest.MapFile{Data: data}
	}
	p, err := pack.Parse([]byte(fixturePack))
	if err != nil {
		t.Fatal(err)
	}
	return fsys, content.BuiltInRefs([]*pack.Pack{p})
}

// The content built into the binary is valid, and every reviewed entry in
// it reads as it did when it was signed. This is what "cca review verify"
// checks in CI.
func TestBuiltInContentIsValid(t *testing.T) {
	all, err := pack.LoadFS(packs.FS)
	if err != nil {
		t.Fatal(err)
	}
	set, problems := content.Load(contentfs.FS, content.BuiltInRefs(all))
	for _, p := range problems {
		t.Error(p)
	}
	if len(set.Controls) < 8 {
		t.Errorf("%d controls, want at least the first release's 8", len(set.Controls))
	}
}

func TestFixtureLoads(t *testing.T) {
	fsys, refs := fixture(t)
	set, problems := content.Load(fsys, refs)
	if len(problems) > 0 {
		t.Fatalf("problems:\n%v", problems)
	}
	if len(set.Controls) != 1 || len(set.Mappings) != 2 || len(set.Tracking) != 1 {
		t.Fatalf("set = %d controls, %d mappings, %d tracking", len(set.Controls), len(set.Mappings), len(set.Tracking))
	}
	if c := set.Controls[0]; c.Domain != "access" || !strings.HasPrefix(c.Statement, "Every person") || strings.HasSuffix(c.Statement, "\n") {
		t.Errorf("control = %+v", c)
	}
	q := content.BuildQueue(set)
	if q.Drafts() != 4 || q.Reviewed() != 0 || q.Items[0].Kind != "control" {
		t.Errorf("queue = %d drafts, %d reviewed, first %+v", q.Drafts(), q.Reviewed(), q.Items[0])
	}
}

// Each case changes one thing in a valid fixture and names the problem it
// must cause. Content that loads despite the change would reach the pages.
func TestInvalidContentIsRejected(t *testing.T) {
	const control, mappings, tracking, scope = "controls/access/access-console-mfa.yaml", "mappings/fixture.yaml", "tracking/fixture.yaml", "scope/fixture-org.yaml"
	cases := []struct {
		name, file, old, new, want string
	}{
		{"banned word", control, "has a second factor", "has an appropriate second factor", `may not use "appropriate"`},
		{"banned phrase", control, "is enough to sign in", "is enough, as needed", `may not use "as needed"`},
		{"long title", control, "title: MFA on console access", "title: Multi factor authentication on every console access path there is", "the most is 8"},
		{"key without domain", control, "key: access-console-mfa", "key: console-mfa", "named console-mfa.yaml"},
		{"unknown check", control, "[AWS-01]", "[AWS-99]", `check "AWS-99" does not exist`},
		{"no freshness", control, "freshness_hours: 48\n", "", "needs freshness_hours"},
		{"manual without evidence", control, "type: automated\nchecks: [AWS-01]", "type: manual\nchecks: []", "needs manual_evidence"},
		{"unknown field", control, "risk:", "risks:", "schema"},
		{"draft with a reviewer", control, `reviewed_by: ""`, `reviewed_by: "someone"`, "a draft names no reviewer"},
		{"reviewed without a hash", control, "status: draft", "status: reviewed", "names its reviewer"},
		{"unknown control", mappings, "control: access-console-mfa\n    requirement: \"R1\"", "control: access-nothing\n    requirement: \"R1\"", `control "access-nothing" does not exist`},
		{"unknown requirement", mappings, `requirement: "R2"`, `requirement: "R9"`, `has no requirement "R9"`},
		{"unknown version", mappings, "version: v1", "version: v2", `has no version "v2"`},
		{"partial without limitation", mappings, "    limitation: R1 also asks for account review, which this does not show.\n", "", "states its limitation"},
		{"crosswalk without source", mappings, "basis: own_analysis\n    review: {", "basis: published_crosswalk\n    review: {", "names it by URL"},
		{"derived and partial", mappings, "basis: own_analysis\n    review: {", "basis: derived\n    basis_source: via other:X\n    review: {", "at most supporting"},
		{"mapped twice", mappings, `requirement: "R2"`, `requirement: "R1"`, "mapped twice"},
		{"bad strength", mappings, "strength: supporting", "strength: strong", "schema"},
		{"tracked and mapped", tracking, `requirement: "R3"`, `requirement: "R1"`, "needs no tracking entry"},
		{"out of scope status typo", tracking, "status: not_implemented", "status: done", "schema"},
		{"control says where it applies", control, "reviewer_note: \"\"", "applies_to_lab: \"yes\"\nreviewer_note: \"\"", "schema"},
		{"exclusion of an unknown control", scope, "control: access-console-mfa", "control: access-nothing", `control "access-nothing" does not exist`},
		{"exclusion without a reason", scope, "    reason: The organization has no console.\n", "", "schema"},
		{"scope file misnamed", scope, "organization: fixture-org", "organization: other-org", "is scope/other-org.yaml"},
		{"not assessed with a rationale", tracking, "status: not_implemented", "status: not_assessed", "schema"},
		{"assessed without a review block", tracking, "    review:\n      status: draft\n      drafted_by: agent\n      reviewed_by: \"\"\n      reviewed_on: \"\"\n      content_sha256: \"\"\n", "", "schema"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fsys, refs := fixture(t)
			fsys[scope] = &fstest.MapFile{Data: []byte(fixtureScope)}
			before := string(fsys[c.file].Data)
			after := strings.Replace(before, c.old, c.new, 1)
			if after == before {
				t.Fatalf("the fixture does not contain %q", c.old)
			}
			fsys[c.file] = &fstest.MapFile{Data: []byte(after)}
			_, problems := content.Load(fsys, refs)
			if !strings.Contains(problems.Error(), c.want) {
				t.Errorf("problems = %q, want one containing %q", problems.Error(), c.want)
			}
		})
	}
}

// Every requirement is mapped by a control or tracked. One that is neither
// is a problem, named.
func TestEveryRequirementIsMappedOrTracked(t *testing.T) {
	fsys, refs := fixture(t)
	fsys["tracking/fixture.yaml"] = &fstest.MapFile{Data: []byte("framework: fixture\nversion: v1\nentries: []\n")}
	_, problems := content.Load(fsys, refs)
	if !strings.Contains(problems.Error(), "1 requirements have neither a mapping nor a tracking entry: R3") {
		t.Errorf("problems = %q", problems.Error())
	}
}

func sign(t *testing.T, fsys fstest.MapFS, refs content.Refs, file string, sel content.Selector, unsign bool) []content.Signed {
	t.Helper()
	set, problems := content.Load(fsys, refs)
	for _, p := range problems {
		if !p.Review {
			t.Fatalf("content problem before signing: %v", p)
		}
	}
	out, signed, err := content.Sign(fsys[file].Data, file, set, sel, "ali", "2026-11-12", unsign)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	fsys[file] = &fstest.MapFile{Data: out}
	return signed
}

// A requirement nobody has looked at is marked not_assessed. The entry
// satisfies "mapped or tracked", but it is not a draft: it is not in the
// review queue, not counted as waiting, and cannot be signed.
func TestNotAssessedIsNotInTheQueueAndCannotBeSigned(t *testing.T) {
	const file = "tracking/fixture.yaml"
	fsys, refs := fixture(t)
	fsys[file] = &fstest.MapFile{Data: []byte("framework: fixture\nversion: v1\nentries:\n  - requirement: \"R3\"\n    status: not_assessed\n")}
	set, problems := content.Load(fsys, refs)
	if len(problems) > 0 {
		t.Fatalf("problems:\n%v", problems)
	}
	if len(set.Tracking) != 1 || set.Tracking[0].Assessed() {
		t.Fatalf("tracking = %+v", set.Tracking)
	}
	q := content.BuildQueue(set)
	if q.NotAssessed() != 1 || q.Tracking[0].Draft != 0 || q.Tracking[0].Reviewed != 0 {
		t.Errorf("queue tracking = %+v", q.Tracking)
	}
	for _, it := range q.Items {
		if it.Kind == "tracking" {
			t.Errorf("a not assessed entry is in the queue: %+v", it)
		}
	}
	if q.Drafts() != 3 {
		t.Errorf("%d drafts waiting, want the control and its two mappings", q.Drafts())
	}
	if md := q.Markdown(); strings.Contains(md, "**R3**") || !strings.Contains(md, "1 requirements are marked `not_assessed`") {
		t.Errorf("the queue document:\n%s", md)
	}
	_, _, err := content.Sign(fsys[file].Data, file, set, content.Selector{Requirement: "R3"}, "ali", "2026-11-12", false)
	if err == nil || !strings.Contains(err.Error(), "is not assessed") {
		t.Errorf("signing a not assessed entry by name: err = %v", err)
	}
	if _, _, err := content.Sign(fsys[file].Data, file, set, content.Selector{All: true}, "ali", "2026-11-12", false); err == nil {
		t.Error("--all signed a file that holds only not assessed entries")
	}
}

// An exclusion is reviewed like any other entry: it sits in the queue as a
// draft, is signed by control, and an edit to its reason after signing is
// caught.
func TestExclusionsAreQueuedAndSigned(t *testing.T) {
	const file = "scope/fixture-org.yaml"
	fsys, refs := fixture(t)
	fsys[file] = &fstest.MapFile{Data: []byte(fixtureScope)}
	set, problems := content.Load(fsys, refs)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	sc, ok := set.Scope("fixture-org")
	if !ok || !sc.Synthetic || len(sc.Exclusions) != 1 || sc.Exclusions[0].Review.IsReviewed() {
		t.Fatalf("scope = %+v", sc)
	}
	q := content.BuildQueue(set)
	last := q.Items[len(q.Items)-1]
	if len(q.Scope) != 1 || q.Scope[0].Draft != 1 || last.Kind != "exclusion" || last.Sign != "cca review sign scope/fixture-org.yaml --control access-console-mfa" {
		t.Errorf("queue scope = %+v, last item = %+v", q.Scope, last)
	}
	if _, _, err := content.Sign(fsys[file].Data, file, set, content.Selector{Requirement: "R1"}, "ali", "2026-11-12", false); err == nil {
		t.Error("an exclusion was signed by requirement")
	}
	signed := sign(t, fsys, refs, file, content.Selector{Control: "access-console-mfa"}, false)
	if len(signed) != 1 {
		t.Fatalf("signed = %+v", signed)
	}
	set, problems = content.Load(fsys, refs)
	if len(problems) > 0 || !set.Scopes[0].Exclusions[0].Review.IsReviewed() {
		t.Fatalf("after signing: %v", problems)
	}
	fsys[file] = &fstest.MapFile{Data: []byte(strings.Replace(string(fsys[file].Data), "has no console", "has no console at all", 1))}
	if _, problems = content.Load(fsys, refs); len(problems) != 1 || !problems[0].Review {
		t.Errorf("an edit to a signed exclusion: problems = %v", problems)
	}
}

// Signing changes four values and nothing else, the signed entry then
// verifies, and an edit after signing is caught.
func TestSignAControlThenEditIt(t *testing.T) {
	const file = "controls/access/access-console-mfa.yaml"
	fsys, refs := fixture(t)
	signed := sign(t, fsys, refs, file, content.Selector{}, false)
	if len(signed) != 1 || signed[0].Entry != "access-console-mfa" {
		t.Fatalf("signed = %+v", signed)
	}
	got := string(fsys[file].Data)
	head, _, _ := strings.Cut(fixtureControl, "review:")
	if !strings.HasPrefix(got, head) {
		t.Errorf("signing changed the file above its review block:\n%s", got)
	}
	for _, want := range []string{"  status: reviewed\n", `  reviewed_by: "ali"`, `  reviewed_on: "2026-11-12"`, `  content_sha256: "` + signed[0].Hash + `"`, "  drafted_by: agent\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("signed file lacks %q:\n%s", want, got)
		}
	}
	set, problems := content.Load(fsys, refs)
	if len(problems) > 0 {
		t.Fatalf("a signed control does not verify:\n%v", problems)
	}
	if r := set.Controls[0].Review; !r.IsReviewed() || r.Label() != "reviewed by ali on 2026-11-12" {
		t.Errorf("review = %+v", r)
	}

	// Laying the text out differently is not an edit.
	relaid := strings.Replace(got, "statement: >-\n  Every person who can sign in to the console has a second factor.",
		"statement: Every person who can sign in to the console has a second factor.", 1)
	if relaid == got {
		t.Fatal("the fixture's statement is not laid out as expected")
	}
	fsys[file] = &fstest.MapFile{Data: []byte(relaid)}
	if _, problems := content.Load(fsys, refs); len(problems) > 0 {
		t.Errorf("a change of layout broke the signature:\n%v", problems)
	}

	// Changing what it says is.
	fsys[file] = &fstest.MapFile{Data: []byte(strings.Replace(got, "a second factor", "two factors", 1))}
	_, problems = content.Load(fsys, refs)
	if len(problems) != 1 || !problems[0].Review || !strings.Contains(problems[0].Msg, "edited after ali reviewed it on 2026-11-12") {
		t.Fatalf("an edit after signing: problems = %v", problems)
	}

	// Signing again, or going back to draft, both settle it.
	sign(t, fsys, refs, file, content.Selector{}, false)
	if _, problems := content.Load(fsys, refs); len(problems) > 0 {
		t.Errorf("after signing again:\n%v", problems)
	}
	sign(t, fsys, refs, file, content.Selector{}, true)
	set, problems = content.Load(fsys, refs)
	if len(problems) > 0 || set.Controls[0].Review.IsReviewed() {
		t.Errorf("after unsigning: review = %+v, problems = %v", set.Controls[0].Review, problems)
	}
	if want := strings.Replace(fixtureControl, "a second factor", "two factors", 1); string(fsys[file].Data) != want {
		t.Errorf("signing and unsigning did not give the file back:\n%s", fsys[file].Data)
	}
}

func TestSignMappingsBySelector(t *testing.T) {
	const file = "mappings/fixture.yaml"
	fsys, refs := fixture(t)

	// One entry, whose review block is written on one line.
	signed := sign(t, fsys, refs, file, content.Selector{Requirement: "R1"}, false)
	if len(signed) != 1 || signed[0].Entry != "access-console-mfa -> R1" {
		t.Fatalf("signed = %+v", signed)
	}
	got := string(fsys[file].Data)
	if !strings.Contains(got, `review: {status: reviewed, drafted_by: agent, reviewed_by: "ali", reviewed_on: "2026-11-12", content_sha256: "`+signed[0].Hash+`"}`) {
		t.Errorf("the one-line review block was not signed in place:\n%s", got)
	}
	if !strings.HasPrefix(got, "# A comment the signer must keep.\n") {
		t.Errorf("the comment was lost:\n%s", got)
	}
	set, problems := content.Load(fsys, refs)
	if len(problems) > 0 {
		t.Fatalf("problems:\n%v", problems)
	}
	if !set.Mappings[0].Review.IsReviewed() || set.Mappings[1].Review.IsReviewed() {
		t.Errorf("reviewed = %v, %v; want only the first", set.Mappings[0].Review.IsReviewed(), set.Mappings[1].Review.IsReviewed())
	}

	// The rest.
	if signed := sign(t, fsys, refs, file, content.Selector{All: true}, false); len(signed) != 2 {
		t.Errorf("--all signed %d entries, want 2", len(signed))
	}
	set, problems = content.Load(fsys, refs)
	if len(problems) > 0 || !set.Mappings[1].Review.IsReviewed() {
		t.Errorf("after --all: problems = %v", problems)
	}
	if q := content.BuildQueue(set); q.Reviewed() != 2 || q.Drafts() != 2 {
		t.Errorf("queue = %d reviewed, %d drafts", q.Reviewed(), q.Drafts())
	}

	// Nothing selected, and nothing matching, are both refused.
	for _, sel := range []content.Selector{{}, {Requirement: "R9"}} {
		if _, _, err := content.Sign(fsys[file].Data, file, set, sel, "ali", "2026-11-12", false); err == nil {
			t.Errorf("Sign with %+v succeeded", sel)
		}
	}
}

// An entry with an open reviewer note cannot be signed: the note is a doubt
// the agent recorded, and signing over it would bury it.
func TestSignRefusesAnOpenNote(t *testing.T) {
	const file = "tracking/fixture.yaml"
	fsys, refs := fixture(t)
	fsys[file] = &fstest.MapFile{Data: []byte(strings.Replace(fixtureTracking,
		"    review:", "    reviewer_note: Is R3 really in scope for the lab?\n    review:", 1))}
	set, problems := content.Load(fsys, refs)
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	_, _, err := content.Sign(fsys[file].Data, file, set, content.Selector{Requirement: "R3"}, "ali", "2026-11-12", false)
	if err == nil || !strings.Contains(err.Error(), "open reviewer_note") {
		t.Fatalf("err = %v", err)
	}
	if q := content.BuildQueue(set); q.Tracking[0].Noted != 1 || q.Items[len(q.Items)-1].Note == "" {
		t.Errorf("queue = %+v", q.Tracking)
	}
}

// A direct mapping counts as partial until a person has reviewed it.
func TestDraftDirectMappingCountsAsPartial(t *testing.T) {
	m := content.Mapping{Strength: "direct", Review: content.Review{Status: content.Draft}}
	if got := m.EffectiveStrength(); got != "partial" {
		t.Errorf("draft direct = %q", got)
	}
	m.Review.Status = content.Reviewed
	if got := m.EffectiveStrength(); got != "direct" {
		t.Errorf("reviewed direct = %q", got)
	}
}

// The committed review queue must match the content files.
func TestReviewQueueIsInSync(t *testing.T) {
	all, err := pack.LoadFS(packs.FS)
	if err != nil {
		t.Fatal(err)
	}
	set, problems := content.Load(contentfs.FS, content.BuiltInRefs(all))
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	const path = "../../docs/review-queue.md"
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with `make content`)", path, err)
	}
	if string(onDisk) != content.BuildQueue(set).Markdown() {
		t.Errorf("%s is out of date; regenerate with `make content`", path)
	}
}
