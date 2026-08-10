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
//	agent-conform [-chain] <file>...
//
// With -chain, every event-stream file is ADDITIONALLY checked in two ways,
// against the two things the word "chain" means in this spec. They are
// reported separately because they mean different things to whoever reads
// the report: one says the file was altered after it was written, the other
// says the identity claim inside it never made sense.
//
//   - The prev_hash INTEGRITY chain (SPEC §6.5, via package event's
//     VerifyChain). A genuine break, a prev_hash that does not match the
//     hash of the line before it, fails the file. Chain restarts (a later
//     line with no prev_hash) and unverifiable links (after a malformed
//     line, or a stream that opens mid-chain, e.g. a rotated segment) are
//     reported but do not fail: the field is optional by spec, and only a
//     mismatch is evidence of tampering or loss.
//
//   - The on_behalf_of DELEGATION chain (SPEC §5.1, via package chain's
//     Validate). Acyclic, at most chain.MaxDepth (32) entries, every entry
//     an agent:// or user:// URI. Any violation fails the file. An empty
//     chain is valid and means the agent acted autonomously.
//
// Root-first ordering is deliberately NOT claimed here. It is a property of
// how a chain was built, one entry appended per hop by chain.Append, and a
// list of URIs after the fact carries nothing that could distinguish a
// root-first chain from a reversed one. A checker that said it verified
// ordering would be describing a check nobody can write.
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

	"github.com/TAIPANBOX/agent-stack-go/chain"
	"github.com/TAIPANBOX/agent-stack-go/event"
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
	schemaEventV03 = "https://taipanbox.dev/agent-passport/v0.3/agent-event.schema.json"    // #nosec G101 -- a public schema $id URL, not a credential
)

// version is stamped at link time by the release workflow
// (-ldflags "-X main.version=vX.Y.Z"). It stays "dev" in a plain `go build`,
// which is the honest answer for a binary nobody released.
//
// This is not decoration on a conformance checker. Its whole output is a
// verdict about somebody else's payload, and a verdict is worth what its
// checker is worth: two versions of this tool can legitimately disagree when a
// schema moves, so a report that cannot name the version that produced it is a
// report nobody can re-run.
var version = "dev"

func main() {
	args := os.Args[1:]
	chain := false
	for len(args) > 0 {
		switch args[0] {
		case "-chain":
			chain = true
			args = args[1:]
		case "-version", "--version", "version":
			fmt.Printf("agent-conform %s\n", version)
			return
		case "-h", "-help", "--help":
			fmt.Println("usage: agent-conform [-chain] <file>...")
			fmt.Println()
			fmt.Println("Validates passports and event envelopes against the embedded schemas.")
			fmt.Println("  -chain      also check both chains in an event stream, reported apart:")
			fmt.Println("              the prev_hash integrity chain (SPEC 6.5), and each event's")
			fmt.Println("              on_behalf_of delegation chain (SPEC 5.1: acyclic, at most 32")
			fmt.Println("              entries, every entry an agent:// or user:// URI)")
			fmt.Println("  -version    print the version and exit")
			fmt.Println()
			fmt.Println("Exit codes: 0 conformant, 1 not conformant, 2 could not be read.")
			return
		default:
			goto parsed
		}
	}
parsed:
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agent-conform [-chain] <file>...")
		os.Exit(2)
	}

	schemas, err := loadSchemas()
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent-conform: load embedded schemas:", err)
		os.Exit(2)
	}

	allOK := true
	for _, path := range args {
		if !checkFile(schemas, path, chain) {
			allOK = false
		}
	}
	if !allOK {
		os.Exit(1)
	}
}

// compiledSchemas holds the schemas this program validates against, compiled
// once at startup and reused for every file/line.
type compiledSchemas struct {
	passport *jsonschema.Schema
	eventV01 *jsonschema.Schema
	eventV02 *jsonschema.Schema
	eventV03 *jsonschema.Schema
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
	if err := addEmbedded(c, "schemas/agent-event.v0.3.schema.json", schemaEventV03); err != nil {
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
	eventV03, err := c.Compile(schemaEventV03)
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", schemaEventV03, err)
	}
	return &compiledSchemas{passport: passport, eventV01: eventV01, eventV02: eventV02, eventV03: eventV03}, nil
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
// NDJSON line), and returns whether every record in it conformed. With
// chain set, an event stream must additionally pass the SPEC §6.5
// prev_hash verification (checkChain) and the SPEC §5.1 delegation-chain
// rules (checkDelegation); -chain has no meaning for a Passport document,
// which is one object with no stream to chain and no on_behalf_of.
func checkFile(schemas *compiledSchemas, path string, chain bool) bool {
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

	ok := checkEventStream(schemas, trimmed, path)
	if chain {
		// Both, always, and never one instead of the other: a stream can be
		// unaltered and still carry a delegation chain that means nothing,
		// and a stream with impeccable delegation can have been edited.
		ok = checkChain(trimmed, path) && ok
		ok = checkDelegation(trimmed, path) && ok
	}
	return ok
}

// checkChain runs the SPEC §6.5 prev_hash verification over an event
// stream. Only a genuine break fails; restarts and unverifiable links are
// reported for the operator to see (they are legal, but an auditor deciding
// whether a stream is one unbroken chain wants them on the record).
func checkChain(raw []byte, path string) bool {
	report, err := event.VerifyChain(bytes.NewReader(raw))
	if err != nil {
		fmt.Printf("FAIL %s: chain: %v\n", path, err)
		return false
	}
	for _, b := range report.Breaks {
		fmt.Printf("FAIL %s:%d: chain break: prev_hash %s, expected %s\n", path, b.Line, b.Found, b.Expected)
	}
	if extra := len(report.HeadLines) - 1; extra > 0 {
		fmt.Printf("NOTE %s: %d chain restart(s) at line(s) %v\n", path, extra, report.HeadLines[1:])
	}
	if len(report.Unverifiable) > 0 {
		fmt.Printf("NOTE %s: %d unverifiable link(s) at line(s) %v\n", path, len(report.Unverifiable), report.Unverifiable)
	}
	if !report.Ok() {
		return false
	}
	fmt.Printf("PASS %s (hash chain: %d chained, %d head(s))\n", path, report.Chained, len(report.HeadLines))
	return true
}

// checkDelegation runs the SPEC §5.1 delegation-chain rules over every
// event in a stream: acyclic, at most chain.MaxDepth entries, every entry
// an agent:// or user:// URI. An absent or empty on_behalf_of is valid and
// means the agent acted autonomously, so it is neither a failure nor worth
// a line.
//
// This is a different question from checkChain's, and the output says which
// one failed. A prev_hash break says somebody altered the file after it was
// written. A delegation-chain violation says the identity claim inside it
// never made sense in the first place, and it was true the moment the line
// was emitted, so it points at the emitter rather than at whoever held the
// file since. Collapsing the two into one verdict would cost the reader the
// only thing that tells them where to look.
//
// The event schemas cannot carry this rule: they constrain the SHAPE of an
// on_behalf_of entry, a string matching ^(agent|user)://, with no cap and
// no uniqueness, both of which need to look at the array as a whole.
//
// Malformed lines are skipped in silence: checkEventStream has already
// failed the file for each of them, and saying it twice in different words
// reads like two problems.
func checkDelegation(raw []byte, path string) bool {
	allOK := true
	events, withChain, deepest, lineNo := 0, 0, 0, 0

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		e, err := event.Unmarshal(line)
		if err != nil {
			continue
		}
		events++
		if len(e.OnBehalfOf) == 0 {
			continue
		}
		withChain++
		if len(e.OnBehalfOf) > deepest {
			deepest = len(e.OnBehalfOf)
		}
		if err := chain.Validate(e.OnBehalfOf); err != nil {
			fmt.Printf("FAIL %s:%d: delegation chain (on_behalf_of, SPEC 5.1): %v\n", path, lineNo, err)
			allOK = false
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Printf("FAIL %s: delegation chain: %v\n", path, err)
		return false
	}
	if events == 0 {
		// Nothing parsed, so nothing was checked. Saying PASS here would be a
		// verdict about a file this function never read.
		fmt.Printf("NOTE %s: no parsable event, so no delegation chain was checked\n", path)
		return allOK
	}
	if !allOK {
		return false
	}
	fmt.Printf("PASS %s (delegation: %d event(s), %d carrying a chain, deepest %d of %d)\n",
		path, events, withChain, deepest, chain.MaxDepth)
	return true
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
		case "taipanbox.dev/agent-event/v0.3":
			// v0.3 is the version an observer stamps when agent_id carries a
			// CLAIMED subject (SPEC 3.3, 6.4). A consumer MAY refuse it; this
			// tool is a conformance checker rather than a consumer, so it
			// validates the line instead of judging what a claim means.
			if !checkRecord(schemas.eventV03, line, label+" (event v0.3)") {
				allOK = false
			}
		default:
			fmt.Printf("FAIL %s: unrecognized schema %q (want a Passport document or an agent-event v0.1/v0.2/v0.3 line)\n", label, doc.Schema)
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
