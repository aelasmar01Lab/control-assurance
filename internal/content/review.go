package content

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// hashOf is the hash a signature covers: the entry's content as JSON, with
// surrounding white space trimmed from each text and without the review
// block. How the YAML is laid out does not change it; any change to what
// the entry says does.
func hashOf(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err) // the entry types hold only strings, integers and lists of them
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Hash is the hash of the control's content.
func (c Control) Hash() string { return hashOf(c) }

// Hash is the hash of the mapping's content, with its framework version.
func (m Mapping) Hash() string { return hashOf(m) }

// Hash is the hash of the tracking entry's content, with its framework version.
func (t Tracking) Hash() string { return hashOf(t) }

// JSON is the control's content as hashed, for the record of revisions.
func (c Control) JSON() []byte {
	data, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	return data
}

// checkReview says what is wrong with an entry's review block, given the
// hash of the entry as it now reads.
func checkReview(r Review, note, hash string) []string {
	var out []string
	switch r.Status {
	case Draft:
		if r.ReviewedBy != "" || r.ReviewedOn != "" || r.ContentSHA256 != "" {
			out = append(out, "a draft names no reviewer, date or hash; sign it with \"cca review sign\"")
		}
	case Reviewed:
		switch {
		case r.ReviewedBy == "" || r.ReviewedOn == "" || r.ContentSHA256 == "":
			out = append(out, "a reviewed entry names its reviewer, the date and the hash of what was reviewed; sign it with \"cca review sign\"")
		case r.ContentSHA256 != hash:
			out = append(out, "it was edited after "+r.ReviewedBy+" reviewed it on "+r.ReviewedOn+
				"; sign it again, or set its status back to draft")
		}
		if note != "" {
			out = append(out, "a reviewed entry has no reviewer_note left open")
		}
	}
	return out
}

// Selector picks the entries of a mapping or tracking file to sign. A
// control file holds one entry and needs none.
type Selector struct {
	Requirement string
	Control     string
	All         bool
}

func (s Selector) empty() bool { return s.Requirement == "" && s.Control == "" && !s.All }

// Signed is one entry a call to Sign changed.
type Signed struct {
	Entry string
	Hash  string
}

// Sign marks entries of one content file as reviewed by reviewer on the
// given date, and returns the file's new bytes. Only the four values in each
// review block change; every other byte of the file is kept. set is the
// content the file was loaded into, so the hashes are of what validation saw.
//
// With unsign true it sets the entries back to draft instead.
func Sign(data []byte, filePath string, set *Set, sel Selector, reviewer, date string, unsign bool) ([]byte, []Signed, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse yaml: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, errors.New("the file is not a YAML mapping")
	}
	root := doc.Content[0]

	type target struct {
		node  *yaml.Node // the entry's mapping node
		entry string
		hash  string
		note  string
	}
	var targets []target

	switch {
	case strings.HasPrefix(filePath, "controls/"):
		if !sel.empty() {
			return nil, nil, errors.New("a control file holds one control; it takes no --requirement, --control or --all")
		}
		for _, c := range set.Controls {
			if c.Path == filePath {
				targets = append(targets, target{root, c.Key, c.Hash(), c.ReviewerNote})
			}
		}
	case strings.HasPrefix(filePath, "mappings/"):
		if sel.empty() {
			return nil, nil, errors.New("say which mappings: --requirement <id>, --control <key> or --all")
		}
		list := child(root, "mappings")
		i := 0
		for _, m := range set.Mappings {
			if m.Path != filePath {
				continue
			}
			if list == nil || i >= len(list.Content) {
				return nil, nil, errors.New("the file changed while it was being read")
			}
			node := list.Content[i]
			i++
			if sel.All || (sel.Requirement == "" || sel.Requirement == m.Requirement) && (sel.Control == "" || sel.Control == m.Control) {
				targets = append(targets, target{node, m.Control + " -> " + m.Requirement, m.Hash(), m.ReviewerNote})
			}
		}
	case strings.HasPrefix(filePath, "tracking/"):
		if sel.Control != "" {
			return nil, nil, errors.New("a tracking entry has no control; use --requirement <id> or --all")
		}
		if sel.empty() {
			return nil, nil, errors.New("say which entries: --requirement <id> or --all")
		}
		list := child(root, "entries")
		i := 0
		for _, t := range set.Tracking {
			if t.Path != filePath {
				continue
			}
			if list == nil || i >= len(list.Content) {
				return nil, nil, errors.New("the file changed while it was being read")
			}
			node := list.Content[i]
			i++
			if !t.Assessed() {
				// Nothing was assessed, so there is nothing to review.
				if !sel.All && sel.Requirement == t.Requirement {
					return nil, nil, fmt.Errorf("%s is not assessed; there is nothing to sign until the entry says how the requirement is tracked", t.Requirement)
				}
				continue
			}
			if sel.All || sel.Requirement == t.Requirement {
				targets = append(targets, target{node, t.Requirement, t.Hash(), t.ReviewerNote})
			}
		}
	default:
		return nil, nil, errors.New("only files under controls/, mappings/ and tracking/ are signed")
	}
	if len(targets) == 0 {
		return nil, nil, errors.New("nothing in the file matches")
	}

	type edit struct {
		line, col int // 1-based, as YAML reports them
		node      *yaml.Node
		value     string
	}
	var edits []edit
	var signed []Signed
	for _, t := range targets {
		if !unsign && t.note != "" {
			return nil, nil, fmt.Errorf("%s has an open reviewer_note; clear it once the doubt is settled: %q", t.entry, t.note)
		}
		rv := child(t.node, "review")
		if rv == nil || rv.Kind != yaml.MappingNode {
			return nil, nil, fmt.Errorf("%s has no review block", t.entry)
		}
		values := map[string]string{"status": Reviewed, "reviewed_by": quote(reviewer), "reviewed_on": quote(date), "content_sha256": quote(t.hash)}
		if unsign {
			values = map[string]string{"status": Draft, "reviewed_by": `""`, "reviewed_on": `""`, "content_sha256": `""`}
		}
		for _, key := range []string{"status", "reviewed_by", "reviewed_on", "content_sha256"} {
			n := child(rv, key)
			if n == nil || n.Kind != yaml.ScalarNode {
				return nil, nil, fmt.Errorf("%s: the review block has no %s", t.entry, key)
			}
			edits = append(edits, edit{n.Line, n.Column, n, values[key]})
		}
		signed = append(signed, Signed{Entry: t.entry, Hash: t.hash})
	}

	lines := bytes.SplitAfter(data, []byte("\n"))
	// Later edits first, so an edit never moves one still to be made.
	for i := len(edits) - 1; i >= 0; i-- {
		e := edits[i]
		if e.line < 1 || e.line > len(lines) {
			return nil, nil, errors.New("the review block is not where YAML reported it")
		}
		line := lines[e.line-1]
		start := byteOffset(line, e.col)
		end, err := scalarEnd(line, start, e.node)
		if err != nil {
			return nil, nil, err
		}
		lines[e.line-1] = append(append(append([]byte{}, line[:start]...), e.value...), line[end:]...)
	}
	return bytes.Join(lines, nil), signed, nil
}

// child returns the value of key in a mapping node.
func child(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// quote writes a value as a double-quoted YAML scalar.
func quote(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}

// byteOffset turns a 1-based column, counted in characters, into a byte offset.
func byteOffset(line []byte, col int) int {
	off := 0
	for i := 1; i < col && off < len(line); i++ {
		_, size := utf8.DecodeRune(line[off:])
		off += size
	}
	return off
}

// scalarEnd finds where the scalar that starts at start ends on its line.
func scalarEnd(line []byte, start int, n *yaml.Node) (int, error) {
	bad := fmt.Errorf("line %d: the value is not written on one line in a form this command can replace", n.Line)
	if start >= len(line) {
		return 0, bad
	}
	switch {
	case n.Style&yaml.DoubleQuotedStyle != 0:
		if line[start] != '"' {
			return 0, bad
		}
		for i := start + 1; i < len(line); i++ {
			switch line[i] {
			case '\\':
				i++
			case '"':
				return i + 1, nil
			}
		}
		return 0, bad
	case n.Style&yaml.SingleQuotedStyle != 0:
		if line[start] != '\'' {
			return 0, bad
		}
		for i := start + 1; i < len(line); i++ {
			if line[i] == '\'' {
				if i+1 < len(line) && line[i+1] == '\'' {
					i++
					continue
				}
				return i + 1, nil
			}
		}
		return 0, bad
	case n.Style == 0:
		// A plain scalar: the file holds exactly its value.
		if n.Value == "" || !bytes.HasPrefix(line[start:], []byte(n.Value)) {
			return 0, bad
		}
		return start + len(n.Value), nil
	}
	return 0, bad
}
