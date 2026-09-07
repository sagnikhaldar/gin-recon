package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/schema"
)

// TestSchemaConfig1DeclaresEveryConfigField is a regression test for a real
// gap found while reviewing gin-recon against express-recon: schema/config-1.json
// was missing its "fleet" property entirely, even though Config.Fleet is a
// real, validated (validateFleet), documented (docs/reference.md's
// "fleet --allow-remote-targets" example) field — the published contract
// simply never caught up when Fleet was added to the Go struct. Since
// config-1.json declares "additionalProperties": false, any external
// schema-validating tool (an IDE, a CI linter) would have rejected a
// perfectly valid fleet-config.json's own "fleet" block as a schema
// violation, contradicting gin-recon's own binary, which accepts and uses
// it correctly.
//
// Rather than guard only that one field, this reflects over every top-level
// JSON tag on Config and asserts the schema's own "properties" object names
// it too — the same class of drift, for any future field, fails a build
// instead of silently shipping a stale published contract. This does not
// replace a full JSON Schema validator (no such dependency exists in this
// module, a deliberate choice — see the security-hardening-review memory
// for why introducing one wasn't done unilaterally here); it only catches
// "the property is missing entirely," not deeper shape mismatches.
func TestSchemaConfig1DeclaresEveryConfigField(t *testing.T) {
	var doc struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schema.Config1, &doc); err != nil {
		t.Fatalf("schema/config-1.json: %v", err)
	}

	typ := reflect.TypeOf(Config{})
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		if _, ok := doc.Properties[name]; !ok {
			t.Errorf("Config.%s (json tag %q) has no matching property in schema/config-1.json", typ.Field(i).Name, name)
		}
	}
}
