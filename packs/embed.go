// Package packs embeds the framework pack files and the schema they must satisfy.
package packs

import "embed"

// Schema is the JSON Schema every pack file is validated against.
//
//go:embed pack.schema.json
var Schema []byte

// FS holds the pack files, one directory per framework.
//
//go:embed */*.yaml
var FS embed.FS
