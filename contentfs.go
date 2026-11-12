// Package contentfs embeds the content the maintainer edits: controls,
// mappings and tracking entries, with the schema each must satisfy.
// Framework packs are embedded separately, by package packs.
package contentfs

import "embed"

// FS holds controls/<domain>/<key>.yaml, mappings/<framework>.yaml and
// tracking/<framework>.yaml, each directory with its schema beside them.
//
//go:embed controls mappings tracking
var FS embed.FS
