// Package schema embeds the versioned JSON Schema documents that are this
// project's normative report and configuration contracts (see
// docs/report-contract.md and docs/configuration-contract.md). Embedding
// directly from this directory means the compiled CLI's `schema` command
// serves the exact same bytes as the checked-in, human/tool-readable files —
// there is no separate copy to drift out of sync.
package schema

import _ "embed"

//go:embed report-1.0.json
var Report10 []byte

//go:embed config-1.json
var Config1 []byte
