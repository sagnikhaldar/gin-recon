package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"
)

// Format selects which strict parser Decode uses. There is no auto-detection:
// the caller (CLI flag, MCP tool input, or file extension convention) always
// states the format explicitly, so a misidentified file fails loudly rather
// than being guessed at.
type Format string

const (
	FormatJSON Format = "json"
	FormatYAML Format = "yaml"
)

// yamlCoreSchemaTags are the only YAML tags Decode accepts. Everything else —
// language-specific object tags, custom application tags, anything not part
// of the YAML core schema — is rejected before the document is even
// structurally decoded. This is what
// docs/configuration-contract.md#format-and-validation means by "custom tags
// are rejected": the underlying YAML library does not execute a custom tag's
// semantics itself, but silently accepting one would let a byte-identical
// configuration file mean something different to a different YAML processor,
// which is its own trust hazard for a security tool's configuration.
var yamlCoreSchemaTags = map[string]bool{
	"":            true, // untyped/plain scalar, resolved by the library itself
	"!!map":       true,
	"!!seq":       true,
	"!!str":       true,
	"!!int":       true,
	"!!float":     true,
	"!!bool":      true,
	"!!null":      true,
	"!!timestamp": true,
	"!!binary":    true,
	"!!merge":     true,
	"!!value":     true,
}

// Decode strictly parses raw configuration bytes into a validated Config.
// Decode never executes anything found in data — see the package doc comment
// and ADR 0003. On success the returned Config has every documented default
// applied (see Validate/applyDefaults) and is guaranteed to satisfy every
// rule in docs/configuration-contract.md.
func Decode(format Format, data []byte) (*Config, error) {
	var cfg Config
	switch format {
	case FormatJSON:
		if err := decodeJSON(data, &cfg); err != nil {
			return nil, err
		}
	case FormatYAML:
		if err := decodeYAML(data, &cfg); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("config: unknown format %q", format)
	}

	if err := Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// DecodeReader is a convenience wrapper for callers that have an io.Reader
// (a CLI --config file, an MCP tool argument) rather than a byte slice.
func DecodeReader(format Format, r io.Reader) (*Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("config: read: %w", err)
	}
	return Decode(format, data)
}

// decodeJSON relies on encoding/json's own grammar to satisfy
// docs/configuration-contract.md#format-and-validation's "non-finite numbers
// ... fail before scanning" rule for JSON: standard JSON text has no
// representation for NaN or Infinity at all (Go's own json.Marshal must be
// asked to break spec to emit them), so a config file containing one is
// already a syntax error the decoder rejects on its own. No extra check is
// needed here the way it is for YAML's ".inf"/".nan" literals in decodeYAML.
func decodeJSON(data []byte, cfg *Config) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("config: invalid JSON: %w", err)
	}
	if dec.More() {
		return fmt.Errorf("config: invalid JSON: trailing content after the top-level object")
	}
	return nil
}

func decodeYAML(data []byte, cfg *Config) error {
	// First pass: decode into a generic Node tree purely to audit tags.
	// yaml.Node.Decode/KnownFields do not interact — KnownFields only applies
	// when the destination is a typed struct, and a Node capture has no
	// knowledge of destination fields at all. So tag auditing and strict
	// struct decoding are necessarily two separate passes over the same
	// bytes.
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("config: invalid YAML: %w", err)
	}
	if err := rejectNonCoreTags(&root); err != nil {
		return err
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("config: invalid YAML: %w", err)
	}
	// A second document in the same stream (a "---" separated multi-doc
	// file) is rejected the same way trailing JSON content is: exactly one
	// configuration object per file.
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("config: invalid YAML: only one document is allowed per configuration file")
	}
	return nil
}

func rejectNonCoreTags(n *yaml.Node) error {
	if n.Tag != "" && !yamlCoreSchemaTags[n.Tag] {
		return fmt.Errorf("config: invalid YAML: line %d: custom tag %q is not permitted in configuration", n.Line, n.Tag)
	}
	for _, c := range n.Content {
		if err := rejectNonCoreTags(c); err != nil {
			return err
		}
	}
	return nil
}
