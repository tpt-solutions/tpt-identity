package api

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// routePattern matches route registrations in server.go, e.g. s.mux.HandleFunc("GET /api/v1/me", …).
var routePattern = regexp.MustCompile(`s\.mux\.HandleFunc\("([A-Z]+) ([^"]+)"`)

var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "patch": true, "delete": true,
}

// TestOpenAPISpecMatchesRoutes fails when a route is added to or removed from
// server.go without the same change to api/openapi.yaml.
func TestOpenAPISpecMatchesRoutes(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}

	code := map[string]bool{}
	for _, m := range routePattern.FindAllStringSubmatch(string(src), -1) {
		code[m[1]+" "+m[2]] = true
	}
	if len(code) == 0 {
		t.Fatal("found no route registrations in server.go; the pattern may be stale")
	}

	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openAPISpec, &doc); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}
	spec := map[string]bool{}
	for path, item := range doc.Paths {
		for method := range item {
			if httpMethods[method] {
				spec[strings.ToUpper(method)+" "+path] = true
			}
		}
	}

	if missing := diff(code, spec); len(missing) > 0 {
		t.Errorf("routes in server.go but not in openapi.yaml:\n  %s", strings.Join(missing, "\n  "))
	}
	if extra := diff(spec, code); len(extra) > 0 {
		t.Errorf("operations in openapi.yaml but not registered in server.go:\n  %s", strings.Join(extra, "\n  "))
	}
}

// TestOpenAPIRefsResolve checks that every local $ref points at an existing node.
func TestOpenAPIRefsResolve(t *testing.T) {
	var root any
	if err := yaml.Unmarshal(openAPISpec, &root); err != nil {
		t.Fatalf("parse openapi.yaml: %v", err)
	}

	var walk func(node any, where string)
	walk = func(node any, where string) {
		switch n := node.(type) {
		case map[string]any:
			if ref, ok := n["$ref"].(string); ok {
				if !resolves(root, ref) {
					t.Errorf("%s: unresolved $ref %q", where, ref)
				}
			}
			for k, v := range n {
				walk(v, where+"/"+k)
			}
		case []any:
			for i, v := range n {
				walk(v, where+"/"+strconv.Itoa(i))
			}
		}
	}
	walk(root, "#")
}

// diff returns the sorted keys in a that are not in b.
func diff(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// resolves reports whether a local JSON pointer ("#/a/b") points at a node in root.
func resolves(root any, ref string) bool {
	if !strings.HasPrefix(ref, "#/") {
		return false
	}
	node := root
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		m, ok := node.(map[string]any)
		if !ok {
			return false
		}
		node, ok = m[part]
		if !ok {
			return false
		}
	}
	return true
}

