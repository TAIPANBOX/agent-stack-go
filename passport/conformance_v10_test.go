package passport

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The golden Passport, stamped v1.0, conforms to the vendored v1.0 schema, whose
// top level is closed: this is what proves the struct emits no key the schema
// never named. The v0.1 half of this pair is conformance_test.go.
func TestGoldenPassportConformsToV10(t *testing.T) {
	c := jsonschema.NewCompiler()
	sch, err := c.Compile("testdata/schema/agent-passport.v1.0.schema.json")
	if err != nil {
		t.Fatalf("compile the vendored v1.0 schema: %v", err)
	}
	p := goldenPassport()
	p.Schema = SchemaV10
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(doc); err != nil {
		t.Fatalf("the golden passport stamped v1.0 does not conform to the closed v1.0 schema: %v", err)
	}
}
