// Command nist-csf turns NIST's reference-data export of the Cybersecurity
// Framework into a pack file. It is run by hand when the pack is made, so
// that the import can be repeated and checked:
//
//	curl -sSL -o csf.json 'https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/csf_2_0_0/export/json?element=all'
//	go run ./tools/import/nist-csf csf.json > packs/nist-csf/2.0.yaml
//
// The export holds the current core and the identifiers version 1.1 used
// that version 2.0 withdrew. Withdrawn elements are left out. Functions and
// categories become headings; the subcategories are the requirements.
// NIST's wording is kept exactly. Implementation examples are not imported.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	sourceURL = "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/csf_2_0_0/export/json?element=all"
	document  = "CSF_2_0_0"
	// The counts NIST states for the version 2.0 core. An import that does
	// not match them stops.
	wantFunctions, wantCategories, wantSubcategories = 6, 22, 106
)

type element struct {
	Type  string `json:"element_type"`
	ID    string `json:"element_identifier"`
	Title string `json:"title"`
	Text  string `json:"text"`
	Doc   string `json:"doc_identifier"`
}

type export struct {
	Response struct {
		Elements struct {
			Elements      []element `json:"elements"`
			Relationships []struct {
				Source string `json:"source_element_identifier"`
				Dest   string `json:"dest_element_identifier"`
				Kind   string `json:"relationship_identifier"`
			} `json:"relationships"`
		} `json:"elements"`
	} `json:"response"`
}

type requirement struct {
	ID      string `yaml:"id"`
	Parent  string `yaml:"parent,omitempty"`
	Group   string `yaml:"group"`
	Title   string `yaml:"title,omitempty"`
	Text    string `yaml:"text,omitempty"`
	Heading bool   `yaml:"heading,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nist-csf:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: nist-csf <export.json>")
	}
	data, err := os.ReadFile(os.Args[1]) //nolint:gosec // the operator names the export to import
	if err != nil {
		return err
	}
	var ex export
	if err := json.Unmarshal(data, &ex); err != nil {
		return fmt.Errorf("parse export: %w", err)
	}

	byID := map[string]element{}
	withdrawn := map[string]bool{}
	order := map[string]string{}
	for _, e := range ex.Response.Elements.Elements {
		if e.Doc != document {
			return fmt.Errorf("element %s belongs to %s, not %s", e.ID, e.Doc, document)
		}
		switch e.Type {
		case "withdraw_reason":
			withdrawn[strings.TrimPrefix(e.ID, "WR-")] = true
		case "sort":
			order[strings.TrimPrefix(e.ID, "S-")] = e.Title
		case "function", "category", "subcategory":
			byID[e.ID] = e
		}
	}
	parent := map[string]string{}
	for _, r := range ex.Response.Elements.Relationships {
		if _, ok := byID[r.Dest]; ok && r.Kind == "projection" {
			if _, ok := byID[r.Source]; ok {
				parent[r.Dest] = r.Source
			}
		}
	}

	var ids []string
	counts := map[string]int{}
	for id, e := range byID {
		if withdrawn[id] {
			continue
		}
		if order[id] == "" {
			return fmt.Errorf("%s has no place in the export's order", id)
		}
		ids = append(ids, id)
		counts[e.Type]++
	}
	sort.Slice(ids, func(i, j int) bool { return order[ids[i]] < order[ids[j]] })
	fmt.Fprintf(os.Stderr, "imported %d functions, %d categories, %d subcategories; NIST states %d, %d, %d\n",
		counts["function"], counts["category"], counts["subcategory"], wantFunctions, wantCategories, wantSubcategories)
	if counts["function"] != wantFunctions || counts["category"] != wantCategories || counts["subcategory"] != wantSubcategories {
		return fmt.Errorf("the counts do not match what NIST states")
	}

	var reqs []requirement
	for _, id := range ids {
		e := byID[id]
		r := requirement{ID: id, Title: e.Title, Text: e.Text}
		switch e.Type {
		case "function":
			r.Heading, r.Group = true, e.Title+" ("+id+")"
		case "category":
			f, ok := byID[parent[id]]
			if !ok || f.Type != "function" {
				return fmt.Errorf("category %s has no function above it", id)
			}
			r.Heading, r.Parent, r.Group = true, f.ID, f.Title+" ("+f.ID+")"
		case "subcategory":
			c, ok := byID[parent[id]]
			if !ok || c.Type != "category" || withdrawn[c.ID] {
				return fmt.Errorf("subcategory %s has no current category above it", id)
			}
			f := byID[parent[c.ID]]
			r.Parent, r.Group = c.ID, f.Title+" ("+f.ID+"): "+c.Title+" ("+c.ID+")"
			if r.Text == "" {
				return fmt.Errorf("subcategory %s has no text", id)
			}
		}
		reqs = append(reqs, r)
	}

	sum := sha256.Sum256(data)
	pack := map[string]any{
		"framework": map[string]any{
			"key":         "nist-csf",
			"title":       "NIST Cybersecurity Framework (CSF)",
			"version":     "2.0",
			"text_rights": "full",
			"license":     "Not subject to copyright protection within the United States (a work of NIST employees). NIST grants the public a worldwide right to reprint.",
			"attribution": "National Institute of Standards and Technology (2024) The NIST Cybersecurity Framework (CSF) 2.0. NIST CSWP 29. https://doi.org/10.6028/NIST.CSWP.29. Republished courtesy of the National Institute of Standards and Technology.",
			"source": map[string]any{
				"kind":      "url",
				"url":       sourceURL,
				"retrieved": retrieved(),
				"sha256":    hex.EncodeToString(sum[:]),
			},
		},
		"requirements": reqs,
	}
	fmt.Println("# NIST CSF 2.0 core, generated by tools/import/nist-csf from NIST's")
	fmt.Println("# reference-data export. The wording is NIST's, unmodified. Functions and")
	fmt.Println("# categories are headings; the 106 subcategories are the requirements.")
	fmt.Println("# Do not edit by hand; a new release is a new pack file.")
	enc := yaml.NewEncoder(os.Stdout)
	enc.SetIndent(2)
	if err := enc.Encode(pack); err != nil {
		return err
	}
	return enc.Close()
}

// retrieved is the date the export was fetched: RETRIEVED when set, so a
// re-run reproduces the committed file, otherwise today.
func retrieved() string {
	if d := os.Getenv("RETRIEVED"); d != "" {
		return d
	}
	return time.Now().UTC().Format("2006-01-02")
}
