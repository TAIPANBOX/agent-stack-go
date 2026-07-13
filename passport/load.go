package passport

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Report summarizes one LoadDir call: how many files were attempted and how
// many failed to parse and were skipped.
type Report struct {
	Files     int
	Malformed int
}

// LoadDir reads every file reachable from dirOrGlob, in sorted-path order,
// and decodes each with parse.
//
// dirOrGlob is, in order of precedence:
//  1. an existing directory -- every "*.json" file directly inside it
//     (non-recursive) is read;
//  2. a glob pattern such as "passports/*.json";
//  3. otherwise tried as a literal file path, so a genuinely missing input
//     still produces a clear I/O error rather than a silently empty batch.
//
// A file that fails parse is counted in Report.Malformed and skipped; it
// never aborts the rest of the batch. LoadDir only returns an error for I/O
// failures (a bad glob pattern or an unreadable directory/file); content
// problems are tolerated and surfaced in the returned Report instead.
//
// id extracts the dedup key from a successfully parsed value. A duplicate
// key across two files keeps only the first occurrence in sorted-path
// order, so LoadDir's output is deterministic.
//
// This is the resolve-then-parse-then-dedupe shape that Wardryx's
// internal/passports and Idryx's internal/ingest/passport both need for
// batches of operator-supplied Passport files; it lives here so neither
// has to reimplement it, and so a third consumer never has to either.
func LoadDir[T any](dirOrGlob string, parse func([]byte) (T, error), id func(T) string) ([]T, Report, error) {
	matches, err := resolveDir(dirOrGlob)
	if err != nil {
		return nil, Report{}, err
	}
	sort.Strings(matches)

	rep := Report{}
	seen := map[string]bool{}
	var out []T
	for _, path := range matches {
		data, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied CLI argument/glob/directory listing, not untrusted input
		if err != nil {
			return nil, Report{}, fmt.Errorf("passport: read %s: %w", path, err)
		}
		rep.Files++
		v, err := parse(data)
		if err != nil {
			rep.Malformed++
			continue
		}
		key := id(v)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, v)
	}
	return out, rep, nil
}

// resolveDir expands dirOrGlob into the list of files to read, per LoadDir's
// documented precedence.
func resolveDir(dirOrGlob string) ([]string, error) {
	if info, err := os.Stat(dirOrGlob); err == nil && info.IsDir() {
		matches, err := filepath.Glob(filepath.Join(dirOrGlob, "*.json"))
		if err != nil {
			return nil, fmt.Errorf("passport: bad directory %q: %w", dirOrGlob, err)
		}
		return matches, nil
	}
	matches, err := filepath.Glob(dirOrGlob)
	if err != nil {
		return nil, fmt.Errorf("passport: bad glob %q: %w", dirOrGlob, err)
	}
	if len(matches) == 0 {
		// Not a glob (or a glob that matched nothing): try it as a literal
		// path so a missing file still produces a clear I/O error.
		matches = []string{dirOrGlob}
	}
	return matches, nil
}
