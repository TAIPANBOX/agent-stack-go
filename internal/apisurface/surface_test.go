package apisurface

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	update = flag.Bool("update", false, "rewrite api/surface.txt from the source")
	major  = flag.Bool("major", false, "a new major is being cut: a removed or changed line is reported, not failed")
)

const surfaceFile = "../../api/surface.txt"

// The promised surface is a file, and the source must still export exactly
// it. A removed or changed line is a breaking change (CLAUDE.md invariant 2)
// and fails, unless -major says a new major is being cut on purpose (a flag
// and not an environment variable: this module reads no environment, and
// components.json says so); an added line is additive and fails only until the
// file records it.
func TestTheSurfaceFileIsWhatTheSourceExports(t *testing.T) {
	now, err := Surface("../..")
	if err != nil {
		t.Fatalf("reading the surface measured nothing: %v", err)
	}
	if *update {
		if err := os.MkdirAll(filepath.Dir(surfaceFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(surfaceFile, []byte(strings.Join(now, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("rewrote %s with %d declarations", surfaceFile, len(now))
		return
	}
	raw, err := os.ReadFile(surfaceFile)
	if err != nil {
		t.Fatalf("%s is not there, so this check has no promised surface to compare against and measured nothing; regenerate it: go test ./internal/apisurface -update", surfaceFile)
	}
	promised := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l != "" {
			promised[l] = true
		}
	}
	if len(promised) == 0 {
		t.Fatalf("%s is empty, so this check measured nothing", surfaceFile)
	}
	current := map[string]bool{}
	for _, l := range now {
		current[l] = true
	}
	var removed, added []string
	for l := range promised {
		if !current[l] {
			removed = append(removed, l)
		}
	}
	for _, l := range now {
		if !promised[l] {
			added = append(added, l)
		}
	}
	if len(removed) > 0 && !*major {
		t.Errorf("the exported surface lost or changed what 1.0 promised (a new major, or a mistake):\n    - %s\n  to cut a major on purpose run with -major and regenerate %s", strings.Join(sortedCopy(removed), "\n    - "), surfaceFile)
	}
	if len(removed) > 0 && *major {
		t.Logf("a new major is being cut; these promised declarations are gone or changed:\n    - %s", strings.Join(sortedCopy(removed), "\n    - "))
	}
	if len(added) > 0 {
		t.Errorf("the exported surface grew and %s does not record it (an addition is a minor; record it: go test ./internal/apisurface -update):\n    + %s", surfaceFile, strings.Join(sortedCopy(added), "\n    + "))
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
