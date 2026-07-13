// Command agent-conform validates Agent Passport documents and agent-event
// NDJSON streams against the canonical agent-passport JSON Schemas
// (TAIPANBOX/agent-passport, schemas/), the standalone check agent-passport's
// README.md status section names as not existing yet ("today, conformance is
// verified per-repo against the JSON Schemas by hand").
//
// Every product's own Parse/Unmarshal (package passport's Parse, package
// event's Unmarshal) only enforces required-field presence -- see e.g.
// event.Unmarshal's own doc comment. This tool is the stricter, full-schema
// check: the same one event's own conformance_test.go already runs, just
// against golden fixtures in a test rather than an arbitrary file a caller
// names. A file passing this tool is a stronger guarantee than a file
// merely parsing through passport.Parse/event.Unmarshal without error.
//
// Usage:
//
//	agent-conform <file>...
//
// Each file is classified by content, not extension -- the same
// classify-by-schema-field convention every connector in the stack already
// uses (see e.g. Idryx's internal/ingest/passport, Qryx's
// internal/agentstack): a file that parses as one JSON object with a
// "schema" field starting "taipanbox.dev/agent-passport/" is a Passport
// document; anything else is tried as an agent-event NDJSON stream, one
// JSON object per line, each validated against the v0.1 or v0.2 event
// schema chosen by that line's own "schema" field. A file that is neither
// is reported as a failure, not silently skipped -- unlike the tolerant
// connectors it mirrors, this tool's whole job is to flag exactly this.
//
// Exit code 0 means every file -- and every line within an event stream --
// conforms to its schema. Exit code 1 means at least one did not, or a file
// could not be read or parsed as JSON at all.
package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/*.json
var embeddedSchemas embed.FS

// Schema $ids, copied verbatim from agent-passport/schemas/*.json (see
// that repo's own SPEC.md §4 and §6 for what each governs). Used both as
// the AddResource key and the Compile target, so a mismatch between a
// schema file's own declared $id and what this program expects fails
// loudly at startup (newCompiler), not silently at validation time.
const (
	schemaPassport = "https://taipanbox.dev/agent-passport/v0.1/agent-passport.schema.json" // #nosec G101 -- a public schema $id URL, not a credential
	schemaEventV01 = "https://taipanbox.dev/agent-passport/v0.1/agent-event.schema.json"    // #nosec G101 -- a public schema $id URL, not a credential
	schemaEventV02 = "https://taipanbox.dev/agent-passport/v0.2/agent-event.schema.json"    // #nosec G101 -- a public schema $id URL, not a credential
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: agent-conform <file>...")
		os.Exit(2)
	}

	schemas, err := loadSchemas()
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent-conform: load embedded schemas:", err)
		os.Exit(2)
	}

	allOK := true
	for _, path := range os.Args[1:] {
		if !checkFile(schemas, path) {
			allOK = false
		}
	}
	if !allOK {
		os.Exit(1)
	}
}

// compiledSchemas holds the three schemas this program validates against,
// compiled once at startup and reused for every file/line.
type compiledSchemas struct {
	passport *jsonschema.Schema
	eventV01 *jsonschema.Schema
	eventV02 *jsonschema.Schema
}

// loadSchemas compiles the embedded schema files. A compile failure here
// means the embedded copies are themselves broken (invalid JSON Schema),
// not that any input file failed conformance -- distinct from every
// per-file failure checkFile reports.
func loadSchemas() (*compiledSchemas, error) {
	c := jsonschema.NewCompiler()
	if err := addEmbedded(c, "schemas/agent-passport.schema.json", schemaPassport); err != nil {
		return nil, err
	}
	if err := addEmbedded(c, "schemas/agent-event.schema.json", schemaEventV01); err != nil {
		return nil, err
	}
	if err := addEmbedded(c, "schemas/agent-event.v0.2.schema.json", schemaEventV02); err != nil {
		return nil, err
	}

	passport, err := c.Compile(schemaPassport)
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", schemaPassport, err)
	}
	eventV01, err := c.Compile(schemaEventV01)
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", schemaEventV01, err)
	}
	eventV02, err := c.Compile(schemaEventV02)
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", schemaEventV02, err)
	}
	return &compiledSchemas{passport: passport, eventV01: eventV01, eventV02: eventV02}, nil
}

// addEmbedded reads embeddedPath from the embedded filesystem and
// registers it with c under url, ready for Compile(url).
func addEmbedded(c *jsonschema.Compiler, embeddedPath, url string) error {
	raw, err := embeddedSchemas.ReadFile(embeddedPath)
	if err != nil {
		return fmt.Errorf("read embedded %s: %w", embeddedPath, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("parse embedded %s: %w", embeddedPath, err)
	}
	if err := c.AddResource(url, doc); err != nil {
		return fmt.Errorf("register %s: %w", url, err)
	}
	return nil
}

// checkFile validates one file, printing one line per record checked
// (a Passport document is one record; an event stream is one record per
// NDJSON line), and returns whether every record in it conformed.
func checkFile(schemas *compiledSchemas, path string) bool {
	raw, err := os.ReadFile(path) // #nosec G304 G703 -- path is the operator's own CLI argument, same trust model as any file the invoking user names
	if err != nil {
		fmt.Printf("FAIL %s: %v\n", path, err)
		return false
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		fmt.Printf("FAIL %s: empty file\n", path)
		return false
	}

	if schemaName, ok := passportSchemaName(trimmed); ok {
		return checkRecord(schemas.passport, trimmed, fmt.Sprintf("%s (passport, %s)", path, schemaName))
	}

	return checkEventStream(schemas, trimmed, path)
}

// passportSchemaName reports whether raw parses as one JSON object whose
// "schema" field starts with the Passport schema's namespace prefix, and
// if so returns that field's value for display. A parse failure or a
// "schema" field naming something else (an event envelope, or nothing
// recognized) both return false -- the caller falls through to trying it
// as an event stream instead, mirroring exactly how Idryx's and Qryx's own
// connectors distinguish the two file kinds.
func passportSchemaName(raw []byte) (string, bool) {
	var doc struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", false
	}
	if strings.HasPrefix(doc.Schema, "taipanbox.dev/agent-passport/") {
		return doc.Schema, true
	}
	return "", false
}

// checkEventStream validates raw as NDJSON, one agent-event object per
// line, each against whichever of eventV01/eventV02 its own "schema"
// field selects. A line that is not valid JSON, or whose "schema" field
// names neither known version, is itself a failure -- this tool never
// silently skips a malformed line the way the stack's tolerant runtime
// connectors do, since flagging exactly that is its purpose.
func checkEventStream(schemas *compiledSchemas, raw []byte, path string) bool {
	allOK := true
	lineNo := 0
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		label := fmt.Sprintf("%s:%d", path, lineNo)

		var doc struct {
			Schema string `json:"schema"`
		}
		if err := json.Unmarshal(line, &doc); err != nil {
			fmt.Printf("FAIL %s: invalid JSON: %v\n", label, err)
			allOK = false
			continue
		}
		switch doc.Schema {
		case "taipanbox.dev/agent-event/v0.1":
			if !checkRecord(schemas.eventV01, line, label+" (event v0.1)") {
				allOK = false
			}
		case "taipanbox.dev/agent-event/v0.2":
			if !checkRecord(schemas.eventV02, line, label+" (event v0.2)") {
				allOK = false
			}
		default:
			fmt.Printf("FAIL %s: unrecognized schema %q (want a Passport document or an agent-event v0.1/v0.2 line)\n", label, doc.Schema)
			allOK = false
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Printf("FAIL %s: %v\n", path, err)
		return false
	}
	if lineNo == 0 {
		fmt.Printf("FAIL %s: no content recognized as a Passport document or an agent-event line\n", path)
		return false
	}
	return allOK
}

// checkRecord validates raw against schema, printing and returning a
// single pass/fail for it.
func checkRecord(schema *jsonschema.Schema, raw []byte, label string) bool {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		fmt.Printf("FAIL %s: invalid JSON: %v\n", label, err)
		return false
	}
	if err := schema.Validate(inst); err != nil {
		fmt.Printf("FAIL %s: %v\n", label, err)
		return false
	}
	fmt.Printf("OK   %s\n", label)
	return true
}
