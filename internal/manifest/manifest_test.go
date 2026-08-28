// The declaration in components.json is only worth reading if this repository
// proves it, and proves it against the toolchain rather than by describing.
//
// estate-gates cannot do this. It has no Go toolchain, and building twenty-two
// repositories in its CI is a matrix it does not have. This repository already
// runs its suite on every push.
//
// What is proved here is exactly the `checked` bucket and nothing else. The
// `declared` bucket is not asserted against anything, on purpose: a test that
// pretended to verify a sentence about purpose would be the failure this whole
// design exists to avoid.
package manifest

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type component struct {
	Name    string `json:"name"`
	Class   string `json:"class"`
	Checked struct {
		Package                string         `json:"package"`
		Env                    map[string]any `json:"env"`
		ReadsNoEnvironment     bool           `json:"reads_no_environment"`
		ReproducibleBuildFlags []string       `json:"reproducible_build_flags"`
		FlagsDeclaredIn        []string       `json:"flags_declared_in"`
		VendoredSchemas        []string       `json:"vendored_schemas"`
	} `json:"checked"`
}

type manifest struct {
	Schema     string      `json:"schema"`
	Repo       string      `json:"repo"`
	Module     string      `json:"module"`
	Components []component `json:"components"`
}

func root(t *testing.T) string {
	t.Helper()
	out, err := runIn(t, ".", "git", "rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatalf("locating the repository root: %v", err)
	}
	return strings.TrimSpace(out)
}

func load(t *testing.T) (manifest, string) {
	t.Helper()
	r := root(t)
	b, err := os.ReadFile(filepath.Join(r, "components.json"))
	if err != nil {
		t.Fatalf("reading components.json: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parsing components.json: %v", err)
	}
	if len(m.Components) == 0 {
		t.Fatal("components.json declares no component, so every test here measured nothing")
	}
	return m, r
}

// THE ONE THAT CLOSES THE HOLE. A binary this repository builds and does not
// declare is invisible from outside by construction, which is what estate-gates
// invariant 18 says about its own `runs` field.
func TestEveryBinaryThisRepositoryBuildsIsDeclaredAndTheReverse(t *testing.T) {
	m, r := load(t)

	out, err := runIn(t, r, "go", "list", "-f", "{{if eq .Name \"main\"}}{{.ImportPath}}{{end}}", "./...")
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	built := map[string]bool{}
	for _, line := range strings.Fields(out) {
		built[line] = true
	}
	if len(built) == 0 {
		t.Fatal("go list found no main package in this repository, so this measured nothing")
	}

	declared := map[string]bool{}
	for _, c := range m.Components {
		if c.Checked.Package == "" {
			t.Errorf("component %q declares no package", c.Name)
			continue
		}
		declared[c.Checked.Package] = true
	}
	for p := range built {
		if !declared[p] {
			t.Errorf("this repository builds %s and components.json does not declare it", p)
		}
	}
	for p := range declared {
		if !built[p] {
			t.Errorf("components.json declares %s and this repository does not build it", p)
		}
	}
}

// The declared module path is the one go.mod actually declares. Nine sibling
// repositories import it, so a typo here would be a wrong answer to the only
// question anybody asks this file about the library half.
func TestTheDeclaredModulePathIsTheOneGoModDeclares(t *testing.T) {
	m, r := load(t)
	if m.Module == "" {
		t.Fatal("components.json records no module path, so this measured nothing")
	}
	b, err := os.ReadFile(filepath.Join(r, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	found := regexp.MustCompile(`(?m)^module\s+(\S+)`).FindSubmatch(b)
	if found == nil {
		t.Fatal("go.mod declares no module, so this measured nothing")
	}
	if got := string(found[1]); got != m.Module {
		t.Errorf("components.json says the module is %q; go.mod says %q", m.Module, got)
	}
}

// THE HALF THAT MATTERS MOST HERE, and the one ci.yml's own comment asks for.
//
// agent-conform decides whether somebody else's payload conforms, and a verdict
// is worth what its checker is worth: the person receiving it has to be able to
// rebuild the checker and get the same bytes. Three flags hold that and they
// live in TWO files, so losing one breaks reproducibility in silence.
//
// Both files are checked, and the test fails if either stops mentioning a flag.
func TestTheReproducibleBuildFlagsAreInEveryFileThatClaimsThem(t *testing.T) {
	m, r := load(t)

	checked := 0
	for _, c := range m.Components {
		if len(c.Checked.ReproducibleBuildFlags) == 0 {
			continue
		}
		if len(c.Checked.FlagsDeclaredIn) < 2 {
			t.Errorf("component %q claims reproducible build flags and names %d file(s). "+
				"The whole point is that they live in more than one place and losing one "+
				"is silent.", c.Name, len(c.Checked.FlagsDeclaredIn))
			continue
		}
		for _, file := range c.Checked.FlagsDeclaredIn {
			b, err := os.ReadFile(filepath.Join(r, file))
			if err != nil {
				t.Errorf("components.json names %s and it cannot be read: %v", file, err)
				continue
			}
			for _, flag := range c.Checked.ReproducibleBuildFlags {
				checked++
				if !strings.Contains(string(b), flag) {
					t.Errorf("%s does not mention %q, which components.json says holds "+
						"this binary's reproducibility", file, flag)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no component declares a reproducible build flag, so this measured nothing")
	}
}

// The vendored schema copy exists and is exactly what the manifest says.
//
// A copy with nothing comparing it drifts: on 2026-08-05 the vendored Passport
// schema was missing SPEC 4.4 and 4.5 entirely, and agent-conform read a mode
// the spec does not have and printed OK. `schemas-in-sync.sh` compares the
// CONTENT against the sibling; this compares the SET, so a schema quietly
// disappearing from the copy is visible here too.
func TestTheVendoredSchemaSetIsTheOneDeclared(t *testing.T) {
	m, r := load(t)

	checked := 0
	for _, c := range m.Components {
		if len(c.Checked.VendoredSchemas) == 0 {
			continue
		}
		checked++
		dir := filepath.Join(r, "cmd", "agent-conform", "schemas")
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		var onDisk []string
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") {
				onDisk = append(onDisk, e.Name())
			}
		}
		sort.Strings(onDisk)
		want := append([]string(nil), c.Checked.VendoredSchemas...)
		sort.Strings(want)
		if strings.Join(onDisk, ",") != strings.Join(want, ",") {
			t.Errorf("components.json says the vendored schemas are %v and the directory holds %v",
				want, onDisk)
		}
	}
	if checked == 0 {
		t.Fatal("no component declares a vendored schema set, so this measured nothing")
	}
}

// It reads no environment variable, and that is a claim rather than an absence.
// The reader is proved against a planted name first, so "found none" and "cannot
// find any" are not the same result, and the walk skips this package because the
// prover needs a name in its own source.
func TestItReadsNoEnvironmentAndTheReaderStillWorks(t *testing.T) {
	m, r := load(t)

	name := regexp.MustCompile(`AGENT_STACK_[A-Z0-9_]+`)
	if got := name.FindAllString("const n = \"AGENT_STACK_PLANTED\"", -1); len(got) != 1 {
		t.Fatalf("the reader found %v in a string containing exactly one name, so a "+
			"finding of none below would prove nothing", got)
	}

	var found []string
	err := filepath.Walk(r, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "vendor":
				return filepath.SkipDir
			}
			if path == filepath.Join(r, "internal", "manifest") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, n := range name.FindAllString(string(b), -1) {
			found = append(found, n+" in "+strings.TrimPrefix(path, r+"/"))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	for _, c := range m.Components {
		if !c.Checked.ReadsNoEnvironment {
			continue
		}
		for _, f := range found {
			t.Errorf("components.json says this repository reads no environment variable, "+
				"and here is one: %s", f)
		}
		if len(c.Checked.Env) != 0 {
			t.Errorf("components.json claims reads_no_environment and also declares %d "+
				"variable(s). Those cannot both be true.", len(c.Checked.Env))
		}
	}
}

func runIn(t *testing.T, dir string, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
