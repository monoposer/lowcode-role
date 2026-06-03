// Package spec holds machine-readable API/DSL specifications.
package spec

import _ "embed"

// DSLV1JSON is the JSON Schema for policy body DSL version 1.
//
//go:embed dsl/v1.schema.json
var DSLV1JSON []byte
