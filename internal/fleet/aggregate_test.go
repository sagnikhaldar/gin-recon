package fleet

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/sagnikhaldar/gin-recon/schema"
)

func TestParseAggregateRejectsMalformedCurrentEnvelope(t *testing.T) {
	for _, data := range []string{
		`{"schemaVersion":"1.0","kind":"fleet","tool":"gin-recon","toolVersion":"test","targets":[],"unknown":true}`,
		`{"schemaVersion":"1.0","kind":"fleet","tool":"gin-recon","toolVersion":"test","targets":[{"name":"a","name":"b","status":"ok"}]}`,
		`{"schemaVersion":"1.0","kind":"fleet","tool":"gin-recon","toolVersion":"test","targets":[{"name":"a","status":"bogus"}]}`,
		`{"schemaVersion":"1.0","kind":"fleet","tool":"gin-recon","toolVersion":"test","targets":[{"name":"a","status":"failed","repository":{"scannedCommit":"not-a-commit"}}]}`,
	} {
		if _, err := ParseAggregate([]byte(data), false); err == nil {
			t.Fatalf("ParseAggregate(%s) unexpectedly succeeded", data)
		}
	}
}

func TestParseAggregateAllowsLegacyOnlyWhenRequested(t *testing.T) {
	data := []byte(`{"targets":[{"name":"a","status":"ok"}]}`)
	if _, err := ParseAggregate(data, false); err == nil {
		t.Fatal("unversioned aggregate accepted for update reuse")
	}
	if _, err := ParseAggregate(data, true); err != nil {
		t.Fatalf("legacy aggregate rejected for offline compatibility: %v", err)
	}
}

func TestParseAggregateRejectsInvalidModuleMetadata(t *testing.T) {
	const prefix = `{"schemaVersion":"1.0","kind":"fleet","tool":"gin-recon","toolVersion":"test","targets":[{"name":"a","status":"ok","modules":[`
	const suffix = `]}]}`
	for _, module := range []string{
		`{"id":"../escape","kind":"go-module","status":"ok"}`,
		`{"id":"root","kind":"go-module","status":"ok","artifacts":[{"path":"routes.json","bytes":1,"sha256":"invalid"}]}`,
		`{"id":"root","kind":"go-module","status":"ok"},{"id":"root","kind":"go-module","status":"ok"}`,
	} {
		if _, err := ParseAggregate([]byte(prefix+module+suffix), false); err == nil {
			t.Fatalf("ParseAggregate unexpectedly accepted invalid module metadata: %s", module)
		}
	}
}

func TestParseAggregateValidatesOptionalRepositoryGroups(t *testing.T) {
	valid := []byte(`{"schemaVersion":"1.0","kind":"fleet","tool":"gin-recon","toolVersion":"test","targets":[{"name":"routes","status":"ok","routes":1},{"name":"zero","status":"ok","complete":true,"modules":[{"id":"root","path":"","modulePath":"example.test/zero","kind":"gin-module-no-routes","status":"ok","complete":true}]}],"repositoryGroups":{"withRoutes":["routes"],"reference":[{"name":"zero","category":"gin-no-routes"}]}}`)
	if _, err := ParseAggregate(valid, false); err != nil {
		t.Fatalf("matching repositoryGroups rejected: %v", err)
	}

	for name, groups := range map[string]string{
		"missing target": `{"withRoutes":[],"reference":[{"name":"zero","category":"gin-no-routes"}]}`,
		"wrong category": `{"withRoutes":["routes"],"reference":[{"name":"zero","category":"non-gin"}]}`,
		"wrong order":    `{"withRoutes":["routes"],"reference":[{"name":"zero","category":"gin-no-routes"},{"name":"aaa","category":"failed"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			data := []byte(`{"schemaVersion":"1.0","kind":"fleet","tool":"gin-recon","toolVersion":"test","targets":[{"name":"routes","status":"ok","routes":1},{"name":"zero","status":"ok","complete":true,"modules":[{"id":"root","path":"","modulePath":"example.test/zero","kind":"gin-module-no-routes","status":"ok","complete":true}]}],"repositoryGroups":` + groups + `}`)
			if _, err := ParseAggregate(data, false); err == nil || !strings.Contains(err.Error(), "repositoryGroups does not match targets") {
				t.Fatalf("ParseAggregate error = %v, want repositoryGroups mismatch", err)
			}
		})
	}
}

func TestParseAggregateAllowsOlderFleetWithoutRepositoryGroups(t *testing.T) {
	data := []byte(`{"schemaVersion":"1.0","kind":"fleet","tool":"gin-recon","toolVersion":"test","targets":[]}`)
	aggregate, err := ParseAggregate(data, false)
	if err != nil {
		t.Fatalf("aggregate without repositoryGroups rejected: %v", err)
	}
	if aggregate.RepositoryGroups != nil {
		t.Fatalf("repositoryGroups = %#v, want nil for older input", aggregate.RepositoryGroups)
	}
}

func TestFleetSchemaDeclaresEveryContractField(t *testing.T) {
	type schemaObject struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	var document struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Defs       map[string]schemaObject    `json:"$defs"`
	}
	if err := json.Unmarshal(schema.Fleet10, &document); err != nil {
		t.Fatal(err)
	}
	contracts := []struct {
		name       string
		typeOf     reflect.Type
		properties map[string]json.RawMessage
	}{
		{"aggregate", reflect.TypeOf(Aggregate{}), document.Properties},
		{"repositoryGroups", reflect.TypeOf(RepositoryGroups{}), document.Defs["repositoryGroups"].Properties},
		{"repositoryReference", reflect.TypeOf(RepositoryReference{}), document.Defs["repositoryReference"].Properties},
		{"target", reflect.TypeOf(TargetResult{}), document.Defs["target"].Properties},
		{"module", reflect.TypeOf(ModuleResult{}), document.Defs["module"].Properties},
		{"artifact", reflect.TypeOf(Artifact{}), document.Defs["artifact"].Properties},
		{"inventory", reflect.TypeOf(RepositoryInventory{}), document.Defs["inventory"].Properties},
		{"repository", reflect.TypeOf(RepositoryProvenance{}), document.Defs["repository"].Properties},
		{"scope", reflect.TypeOf(Scope{}), document.Defs["scope"].Properties},
		{"discovery", reflect.TypeOf(DiscoverySummary{}), document.Defs["discovery"].Properties},
		{"repositoryDisposition", reflect.TypeOf(RepositoryDisposition{}), document.Defs["repositoryDisposition"].Properties},
		{"dispositionCount", reflect.TypeOf(DispositionCount{}), document.Defs["dispositionCount"].Properties},
		{"rateLimit", reflect.TypeOf(RateLimitState{}), document.Defs["rateLimit"].Properties},
	}
	for _, contract := range contracts {
		for fieldIndex := 0; fieldIndex < contract.typeOf.NumField(); fieldIndex++ {
			field := contract.typeOf.Field(fieldIndex)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			if _, ok := contract.properties[name]; !ok {
				t.Errorf("%s field %s (json %q) is absent from fleet-1.0.json", contract.name, field.Name, name)
			}
		}
	}
}
