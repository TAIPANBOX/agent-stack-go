// Package apisurface reads the exported surface of this module's library
// packages, one declaration per line, in a stable order: every exported
// constant, variable, type (spelled out, so a field or method added or removed
// shows) and function, methods included.
//
// Its test compares that surface with api/surface.txt, the surface this module
// promised at 1.0 (CLAUDE.md invariant 2: a change to an exported type,
// constant or error value is a version decision, not an edit), and
// scripts/api-surface.sh is the gate that runs it. A line that disappears or
// changes is a breaking change and fails unless the test's -major flag says a
// new major is being cut; a line that appears is additive and the file is
// regenerated to record it (go test ./internal/apisurface -update).
//
// It reads source only: go/parser and go/printer, no build, no network, and no
// dependency beyond the standard library, so it can never widen the module's
// own dependency set (invariant 1). It is a package and not a binary on
// purpose: every binary this repository builds must be declared in
// components.json as a release artifact, and this is a check, not an artifact.
package apisurface

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Packages whose surface is promised. cmd/ and internal/ are not a surface
// anybody imports.
var Packages = []string{"chain", "delegation", "event", "passport"}

// Surface returns the promised packages' exported declarations under root, one
// per line, sorted. It refuses a package that yields no declaration at all,
// since that is a read that measured nothing rather than an empty surface.
func Surface(root string) ([]string, error) {
	var out []string
	for _, pkg := range Packages {
		lines, err := surface(filepath.Join(root, pkg), pkg)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pkg, err)
		}
		if len(lines) == 0 {
			return nil, fmt.Errorf("%s: no exported declaration read, which cannot be right", pkg)
		}
		out = append(out, lines...)
	}
	sort.Strings(out)
	return out, nil
}

func surface(dir, pkg string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var lines []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		for _, d := range f.Decls {
			lines = append(lines, declLines(fset, pkg, d)...)
		}
	}
	return lines, nil
}

func declLines(fset *token.FileSet, pkg string, d ast.Decl) []string {
	var lines []string
	switch d := d.(type) {
	case *ast.FuncDecl:
		if !d.Name.IsExported() {
			return nil
		}
		if d.Recv != nil {
			recv := d.Recv.List[0].Type
			base := recv
			if star, ok := recv.(*ast.StarExpr); ok {
				base = star.X
			}
			if id, ok := base.(*ast.Ident); ok && !id.IsExported() {
				return nil
			}
		}
		lines = append(lines, pkg+": "+render(fset, &ast.FuncDecl{Recv: d.Recv, Name: d.Name, Type: d.Type}))
	case *ast.GenDecl:
		for _, s := range d.Specs {
			switch s := s.(type) {
			case *ast.TypeSpec:
				if !s.Name.IsExported() {
					continue
				}
				lines = append(lines, pkg+": type "+render(fset, s))
			case *ast.ValueSpec:
				for i, n := range s.Names {
					if !n.IsExported() {
						continue
					}
					kind := "var"
					if d.Tok == token.CONST {
						kind = "const"
					}
					line := pkg + ": " + kind + " " + n.Name
					if s.Type != nil {
						line += " " + render(fset, s.Type)
					}
					if i < len(s.Values) {
						line += " = " + render(fset, s.Values[i])
					}
					lines = append(lines, line)
				}
			}
		}
	}
	return lines
}

// render prints a node on one line with comments stripped, so a doc-comment
// edit never reads as an API change and a signature change always does.
func render(fset *token.FileSet, n ast.Node) string {
	var buf bytes.Buffer
	cfg := printer.Config{Mode: printer.RawFormat}
	if err := cfg.Fprint(&buf, fset, n); err != nil {
		return fmt.Sprintf("<unprintable: %v>", err)
	}
	s := buf.String()
	// Struct and interface bodies span lines; fold them so one declaration is
	// one line and the diff a reader sees names the declaration.
	fields := strings.Split(s, "\n")
	for i := range fields {
		fields[i] = strings.TrimSpace(stripLineComment(fields[i]))
	}
	return strings.Join(fields, " ")
}

func stripLineComment(s string) string {
	if i := strings.Index(s, "//"); i >= 0 {
		return s[:i]
	}
	return s
}
