package pack

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/aelasmar01Lab/control-assurance/packs"
)

func TestEmbeddedPacksAreValid(t *testing.T) {
	got, err := LoadFS(packs.FS)
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no embedded packs found")
	}
}

func TestMVSPPack(t *testing.T) {
	all, err := LoadFS(packs.FS)
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	var mvsp *Pack
	for _, p := range all {
		if p.Framework.Key == "mvsp" {
			mvsp = p
		}
	}
	if mvsp == nil {
		t.Fatal("mvsp pack not found")
	}
	if got := len(mvsp.Requirements); got != 25 {
		t.Errorf("requirements = %d, want 25", got)
	}
	if got, want := mvsp.Framework.Version, "v3.0-20231109"; got != want {
		t.Errorf("version = %q, want %q", got, want)
	}
	if len(mvsp.ContentSHA256) != 64 {
		t.Errorf("ContentSHA256 = %q, want 64 hex characters", mvsp.ContentSHA256)
	}
}

// Each fixture in testdata/broken is a valid pack with one defect. A pack
// that loads despite its defect would let bad catalog data into the product.
func TestBrokenPacksAreRejected(t *testing.T) {
	wantErr := map[string]string{
		"bad-commit.yaml":         "schema",
		"bad-sha256.yaml":         "schema",
		"duplicate-id.yaml":       "duplicate requirement id",
		"empty-requirements.yaml": "schema",
		"missing-source.yaml":     "schema",
		"missing-text.yaml":       "schema",
		"not-yaml.yaml":           "parse yaml",
		"unknown-field.yaml":      "schema",
	}
	files, err := filepath.Glob("testdata/broken/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(wantErr) {
		t.Fatalf("found %d fixtures, expected %d; update wantErr", len(files), len(wantErr))
	}
	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(f) //nolint:gosec // fixture path from Glob above
			if err != nil {
				t.Fatal(err)
			}
			_, err = Parse(data)
			if err == nil {
				t.Fatal("Parse succeeded, want an error")
			}
			if !strings.Contains(err.Error(), wantErr[name]) {
				t.Errorf("error = %q, want it to contain %q", err, wantErr[name])
			}
		})
	}
}

func TestValidFixtureParses(t *testing.T) {
	data, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Requirements) != 2 {
		t.Errorf("requirements = %d, want 2", len(p.Requirements))
	}
}

func TestLoadFSRejectsDuplicateFrameworkVersion(t *testing.T) {
	data, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{
		"a/one.yaml": {Data: data},
		"b/two.yaml": {Data: data},
	}
	_, err = LoadFS(fsys)
	if err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Errorf("error = %v, want a duplicate framework error", err)
	}
}
