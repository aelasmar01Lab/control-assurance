// Package contentfs embeds the content the maintainer edits: controls,
// mappings, tracking entries and each organization's scope, with the schema each must satisfy.
// Framework packs are embedded separately, by package packs.
package contentfs

import "embed"

// FS holds controls/<domain>/<key>.yaml, mappings/<framework>.yaml,
// tracking/<framework>.yaml and scope/<organization>.yaml, each directory
// with its schema beside them.
//
//go:embed controls mappings tracking scope
var FS embed.FS
