package api

import "net/http"

// The route table.
//
// Routes live in one list rather than in a sequence of mux.Handle calls so
// that the OpenAPI document and the browsable reference are generated from the
// same data the router uses. Documentation kept alongside a router drifts from
// it; documentation generated from it cannot. If an endpoint exists, it is
// described here, and a test fails if a description is missing.
type Route struct {
	Method  string
	Path    string
	Handler http.HandlerFunc

	// Tag groups the route in the reference.
	Tag string
	// Summary is the one-line description shown in a listing.
	Summary string
	// Detail explains behaviour a caller could not guess from the path —
	// which is where most of the value in these docs actually is.
	Detail string

	// Permission is the authz permission the handler requires. Empty means the
	// route is public or self-service.
	Permission string
	// StepUp marks a route that also requires a second factor verified within
	// the recent past, not merely a valid session.
	StepUp bool
	// Public marks a route reachable without any credential.
	Public bool

	Query  []Param
	Body   []Field
	Return string
}

// Param documents a query parameter.
type Param struct {
	Name        string
	Type        string
	Description string
	Repeatable  bool
}

// Field documents one property of a request body.
type Field struct {
	Name        string
	Type        string
	Description string
	Required    bool
}

// pathParams extracts the {placeholders} from a route pattern.
func pathParams(path string) []string {
	var out []string
	for i := 0; i < len(path); i++ {
		if path[i] != '{' {
			continue
		}
		for j := i + 1; j < len(path); j++ {
			if path[j] == '}' {
				out = append(out, path[i+1:j])
				i = j
				break
			}
		}
	}
	return out
}
