package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Documented request bodies are checked against the handlers that decode them.
//
// The route table is prose written next to code, and prose drifts. This test
// reads the handlers' own decode structs out of the source and compares the
// field names, so a documented field that no handler reads — or a field a
// handler reads that nothing documents — fails here.
//
// It caught a real one: POST /api/v1/deploy was documented as accepting
// assignment_ids, key_id and async, none of which the handler has ever read,
// while prune and verify_auth went undocumented.
func TestDocumentedBodiesMatchTheHandlers(t *testing.T) {
	decoded := handlerRequestFields(t)
	s := &Server{}

	for _, route := range s.routes() {
		name := handlerName(route)
		fields, ok := decoded[name]
		if !ok {
			// The handler decodes into a named type rather than an inline
			// struct. Those are not readable from the syntax tree alone, and
			// guessing would produce noise rather than signal.
			continue
		}

		documented := make([]string, 0, len(route.Body))
		for _, f := range route.Body {
			documented = append(documented, f.Name)
		}
		sort.Strings(documented)
		sort.Strings(fields)

		if !reflect.DeepEqual(documented, fields) {
			t.Errorf("%s %s\n  documented: %v\n  handler reads: %v",
				route.Method, route.Path, documented, fields)
		}
	}
}

func handlerName(route Route) string {
	// The handler is a method value; its name is not recoverable at runtime in
	// a usable form, so the table's own path-to-handler mapping is rebuilt from
	// the source instead. Matching on the pattern is enough: routetable.go
	// names the handler on the same line as the path.
	return route.Method + " " + route.Path
}

// handlerRequestFields maps "METHOD /path" to the json tags of the struct the
// handler decodes the request body into.
func handlerRequestFields(t *testing.T) map[string][]string {
	t.Helper()

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parsing the package source: %v", err)
	}

	// First pass: handler function name -> json tags of its `var x struct{...}`.
	byFunc := map[string][]string{}
	// Second pass: "METHOD /path" -> handler function name, read from the table.
	byRoute := map[string]string{}

	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || fn.Body == nil {
					continue
				}
				if tags := requestTags(fn.Body); tags != nil {
					byFunc[fn.Name.Name] = tags
				}
			}
			if strings.HasSuffix(path, "routetable.go") {
				collectRouteHandlers(file, byRoute)
			}
		}
	}

	if len(byRoute) == 0 {
		t.Fatal("no routes were read from routetable.go; the test cannot check anything")
	}

	out := map[string][]string{}
	for route, fn := range byRoute {
		if tags, ok := byFunc[fn]; ok {
			out[route] = tags
		}
	}
	return out
}

// requestTags returns the json tags of the first `var x struct{...}` in a
// function body. Response payloads are written with maps and struct literals,
// not declared this way, so this picks out request bodies specifically.
func requestTags(body *ast.BlockStmt) []string {
	var tags []string
	found := false

	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		decl, ok := n.(*ast.DeclStmt)
		if !ok {
			return true
		}
		gen, ok := decl.Decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			return true
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			st, ok := value.Type.(*ast.StructType)
			if !ok {
				continue
			}
			for _, field := range st.Fields.List {
				if field.Tag == nil {
					continue
				}
				if name := jsonName(field.Tag.Value); name != "" && name != "-" {
					tags = append(tags, name)
				}
			}
			found = true
			return false
		}
		return true
	})
	return tags
}

func jsonName(rawTag string) string {
	tag := reflect.StructTag(strings.Trim(rawTag, "`"))
	value := tag.Get("json")
	if i := strings.IndexByte(value, ','); i >= 0 {
		value = value[:i]
	}
	return value
}

// collectRouteHandlers reads Method/Path/Handler out of the route table's
// composite literals.
func collectRouteHandlers(file *ast.File, out map[string]string) {
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}

		var method, path, handler string
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch key.Name {
			case "Method":
				method = literalString(kv.Value)
			case "Path":
				path = literalString(kv.Value)
			case "Handler":
				if sel, ok := kv.Value.(*ast.SelectorExpr); ok {
					handler = sel.Sel.Name
				}
			}
		}
		if method != "" && path != "" && handler != "" {
			out[method+" "+path] = handler
		}
		return true
	})
}

func literalString(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	return strings.Trim(lit.Value, `"`)
}
