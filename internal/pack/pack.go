// Package pack parses and validates framework pack files.
package pack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
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

// Framework identifies a framework version and where its text came from.
type Framework struct {
	Key     string `yaml:"key"`
	Title   string `yaml:"title"`
	Version string `yaml:"version"`
	License string `yaml:"license"`
	Source  Source `yaml:"source"`
}

// Source pins the upstream file a pack was derived from.
type Source struct {
	Repository string `yaml:"repository"`
	Commit     string `yaml:"commit"`
	Path       string `yaml:"path"`
	Retrieved  string `yaml:"retrieved"`
	SHA256     string `yaml:"sha256"`
}

// Requirement is one requirement of a framework version.
type Requirement struct {
	ID    string `yaml:"id"`
	Group string `yaml:"group"`
	Title string `yaml:"title"`
	Text  string `yaml:"text"`
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
	seen := make(map[string]bool, len(p.Requirements))
	for _, r := range p.Requirements {
		if seen[r.ID] {
			return nil, fmt.Errorf("duplicate requirement id %q", r.ID)
		}
		seen[r.ID] = true
	}

	sum := sha256.Sum256(data)
	p.ContentSHA256 = hex.EncodeToString(sum[:])
	return &p, nil
}

// LoadFS parses every *.yaml file one directory deep in fsys, in path order.
// It fails on the first invalid pack and on two packs that claim the same
// framework key and version.
func LoadFS(fsys fs.FS) ([]*Pack, error) {
	paths, err := fs.Glob(fsys, "*/*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)

	var out []*Pack
	seen := make(map[string]string)
	for _, path := range paths {
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, err
		}
		p, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		id := p.Framework.Key + "@" + p.Framework.Version
		if prev, ok := seen[id]; ok {
			return nil, fmt.Errorf("%s: framework %s already defined in %s", path, id, prev)
		}
		seen[id] = path
		out = append(out, p)
	}
	return out, nil
}
