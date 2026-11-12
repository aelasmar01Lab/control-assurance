// Package pack parses and validates framework pack files.
package pack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"

	"github.com/aelasmar01Lab/control-assurance/packs"
)

// Pack is one version of one framework.
type Pack struct {
	Framework    Framework     `yaml:"framework"`
	Requirements []Requirement `yaml:"requirements"`

	// ContentSHA256 is the hash of the pack file itself, as opposed to
	// Framework.Source.SHA256, which is the hash of the upstream file the
	// pack was derived from.
	ContentSHA256 string `yaml:"-"`
}

// The rights a pack has over the framework's text.
const (
	// TextFull means upstream's titles and text are included, under the
	// licence the pack records.
	TextFull = "full"
	// TextIdentifiersOnly means the pack carries identifiers, hierarchy and
	// labels in the project's own words, and none of upstream's wording.
	TextIdentifiersOnly = "identifiers_only"
	// TextOwnComposition means the project wrote the requirements itself.
	TextOwnComposition = "own_composition"
)

// MaxLabelWords is the most words a requirement label may have. A label
// names a topic; it is not a paraphrase of the requirement.
const MaxLabelWords = 12

// Framework identifies a framework version, where it came from and what of
// it may be redistributed.
type Framework struct {
	Key         string `yaml:"key"`
	Title       string `yaml:"title"`
	Version     string `yaml:"version"`
	TextRights  string `yaml:"text_rights"`
	License     string `yaml:"license"`
	Attribution string `yaml:"attribution"`
	Source      Source `yaml:"source"`
	// ProfileOf names the pack this one selects from, as key@version.
	ProfileOf string `yaml:"profile_of"`
}

// Source pins the upstream file or document a pack was derived from.
type Source struct {
	// Kind is git (a file at a commit), url (a file fetched from a URL) or
	// document (a published document read by a person or the agent).
	Kind      string `yaml:"kind"`
	URL       string `yaml:"url"`
	Commit    string `yaml:"commit"`
	Path      string `yaml:"path"`
	Retrieved string `yaml:"retrieved"`
	SHA256    string `yaml:"sha256"`
}

// Ref is the source as one string: the URL, with the commit when there is one.
func (s Source) Ref() string {
	switch {
	case s.URL == "":
		return "a " + s.Kind + " with no public address"
	case s.Commit != "":
		return s.URL + "@" + s.Commit
	}
	return s.URL
}

// Requirement is one requirement of a framework version.
type Requirement struct {
	ID string `yaml:"id"`
	// Parent is the identifier of the requirement this one sits under.
	Parent string `yaml:"parent"`
	Group  string `yaml:"group"`
	// Title and Text are upstream's, present only when the pack has the
	// right to carry them, or the project's own in an own composition.
	Title string `yaml:"title"`
	Text  string `yaml:"text"`
	// Label is a short description in the project's own words.
	Label string `yaml:"label"`
}

// Name is what to call the requirement beside its identifier: upstream's
// title when the pack carries it, otherwise the project's label.
func (r Requirement) Name() string {
	if r.Title != "" {
		return r.Title
	}
	return r.Label
}

var compileSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(packs.Schema))
	if err != nil {
		return nil, fmt.Errorf("read pack schema: %w", err)
	}
	// The schema's own $id, so error messages do not depend on the working directory.
	const url = "https://github.com/aelasmar01Lab/control-assurance/packs/pack.schema.json"
	c := jsonschema.NewCompiler()
	if err := c.AddResource(url, doc); err != nil {
		return nil, fmt.Errorf("add pack schema: %w", err)
	}
	s, err := c.Compile(url)
	if err != nil {
		return nil, fmt.Errorf("compile pack schema: %w", err)
	}
	return s, nil
})

// Parse validates data against the pack schema and the rules a schema cannot
// express, and returns the pack.
func Parse(data []byte) (*Pack, error) {
	schema, err := compileSchema()
	if err != nil {
		return nil, err
	}

	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	// Round-trip through JSON so the validator sees plain JSON types.
	asJSON, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("convert to json: %w", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(asJSON))
	if err != nil {
		return nil, fmt.Errorf("convert to json: %w", err)
	}
	if err := schema.Validate(doc); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}

	var p Pack
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if err := p.check(); err != nil {
		return nil, err
	}

	sum := sha256.Sum256(data)
	p.ContentSHA256 = hex.EncodeToString(sum[:])
	return &p, nil
}

// check applies the rules the schema cannot express.
func (p *Pack) check() error {
	f := p.Framework
	src := f.Source
	switch src.Kind {
	case "git":
		if src.URL == "" || src.Commit == "" || src.Path == "" || src.SHA256 == "" {
			return errors.New("a git source needs url, commit, path and sha256")
		}
	case "url":
		if src.URL == "" || src.SHA256 == "" {
			return errors.New("a url source needs url and sha256")
		}
		if src.Commit != "" {
			return errors.New("only a git source has a commit")
		}
	case "document":
		if src.Commit != "" {
			return errors.New("only a git source has a commit")
		}
	}
	profile := f.ProfileOf != ""
	if profile && strings.HasPrefix(f.ProfileOf, f.Key+"@") && f.ProfileOf == f.Key+"@"+f.Version {
		return errors.New("a pack cannot be a profile of itself")
	}

	seen := make(map[string]bool, len(p.Requirements))
	for _, r := range p.Requirements {
		if seen[r.ID] {
			return fmt.Errorf("duplicate requirement id %q", r.ID)
		}
		seen[r.ID] = true
	}
	for _, r := range p.Requirements {
		if n := len(strings.Fields(r.Label)); n > MaxLabelWords {
			return fmt.Errorf("requirement %s: the label has %d words; the most is %d", r.ID, n, MaxLabelWords)
		}
		if profile {
			// A profile selects; everything else comes from the pack it selects from.
			if r.Parent != "" || r.Group != "" || r.Title != "" || r.Text != "" || r.Label != "" {
				return fmt.Errorf("requirement %s: a profile lists identifiers only", r.ID)
			}
			continue
		}
		if r.Group == "" {
			return fmt.Errorf("requirement %s has no group", r.ID)
		}
		if r.Parent != "" && !seen[r.Parent] {
			return fmt.Errorf("requirement %s: parent %q is not in this pack", r.ID, r.Parent)
		}
		if r.Parent == r.ID {
			return fmt.Errorf("requirement %s is its own parent", r.ID)
		}
		switch f.TextRights {
		case TextIdentifiersOnly:
			if r.Title != "" || r.Text != "" {
				return fmt.Errorf("requirement %s: an identifiers_only pack carries no title or text", r.ID)
			}
			if r.Label == "" {
				return fmt.Errorf("requirement %s: an identifiers_only pack needs a label", r.ID)
			}
		default:
			if r.Title == "" && r.Text == "" {
				return fmt.Errorf("requirement %s has neither a title nor text", r.ID)
			}
		}
	}
	return nil
}

// Lookup returns the requirement with the given identifier.
func (p *Pack) Lookup(id string) (Requirement, bool) {
	for _, r := range p.Requirements {
		if r.ID == id {
			return r, true
		}
	}
	return Requirement{}, false
}

// ID is the pack's key and version, as key@version.
func (p *Pack) ID() string { return p.Framework.Key + "@" + p.Framework.Version }

// LoadFS parses every *.yaml file one directory deep in fsys, in path order.
// It fails on the first invalid pack, on two packs that claim the same
// framework key and version, and on a profile whose parent pack is missing
// or lacks a requirement the profile selects. A profile's requirements come
// back filled in from its parent.
func LoadFS(fsys fs.FS) ([]*Pack, error) {
	paths, err := fs.Glob(fsys, "*/*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)

	var out []*Pack
	seen := make(map[string]string)
	byID := make(map[string]*Pack)
	for _, path := range paths {
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, err
		}
		p, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if prev, ok := seen[p.ID()]; ok {
			return nil, fmt.Errorf("%s: framework %s already defined in %s", path, p.ID(), prev)
		}
		seen[p.ID()] = path
		byID[p.ID()] = p
		out = append(out, p)
	}
	for _, p := range out {
		if p.Framework.ProfileOf == "" {
			continue
		}
		parent, ok := byID[p.Framework.ProfileOf]
		if !ok {
			return nil, fmt.Errorf("%s: it is a profile of %s, which is not a built-in pack", seen[p.ID()], p.Framework.ProfileOf)
		}
		if parent.Framework.ProfileOf != "" {
			return nil, fmt.Errorf("%s: %s is itself a profile", seen[p.ID()], p.Framework.ProfileOf)
		}
		for i, r := range p.Requirements {
			full, ok := parent.Lookup(r.ID)
			if !ok {
				return nil, fmt.Errorf("%s: requirement %s is not in %s", seen[p.ID()], r.ID, p.Framework.ProfileOf)
			}
			p.Requirements[i] = full
		}
	}
	return out, nil
}
