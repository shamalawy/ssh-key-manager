package api

import (
	"net/http"
	"sort"
	"strings"

	"github.com/hamalawy/ssh-key-manager/backend/internal/events"
)

// Version is the API version reported in the OpenAPI document.
const Version = "1.0.0"

// handleOpenAPI renders the route table as an OpenAPI 3.1 document.
//
// It is generated rather than hand-written for the reason every generated spec
// is: a hand-written one is correct on the day it is written. This one is
// correct by construction, because the same slice produces the router.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	routes := s.routes()

	paths := map[string]map[string]any{}
	tagSet := map[string]bool{}

	for _, route := range routes {
		tagSet[route.Tag] = true

		op := map[string]any{
			"tags":        []string{route.Tag},
			"summary":     route.Summary,
			"operationId": operationID(route),
			"description": describe(route),
			"responses":   responsesFor(route),
		}

		if params := parametersFor(route); len(params) > 0 {
			op["parameters"] = params
		}
		if len(route.Body) > 0 {
			op["requestBody"] = requestBodyFor(route)
		}
		if route.Public {
			// An empty security list is how OpenAPI says "no credential needed"
			// for one operation inside a document that otherwise requires one.
			op["security"] = []any{}
		}

		if _, ok := paths[route.Path]; !ok {
			paths[route.Path] = map[string]any{}
		}
		paths[route.Path][strings.ToLower(route.Method)] = op
	}

	tags := make([]map[string]string, 0, len(tagSet))
	for name := range tagSet {
		tags = append(tags, map[string]string{"name": name})
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i]["name"] < tags[j]["name"] })

	writeJSON(w, http.StatusOK, map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "SKM — SSH Key Manager",
			"version":     Version,
			"description": apiDescription,
		},
		"servers": []map[string]string{{"url": "/"}},
		"tags":    tags,
		"paths":   paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":   "http",
					"scheme": "bearer",
					"description": "A session token from POST /api/v1/auth/login, or an API " +
						"token beginning skmt_. Send it as: Authorization: Bearer <token>.",
				},
			},
		},
		"security": []map[string][]string{{"bearerAuth": {}}},
		"x-events": events.All,
	})
}

const apiDescription = `Everything the web interface can do, this API can do — the interface is
built on it, so there is no second-class path.

Authentication. POST /api/v1/auth/login returns a session token. For
automation, mint an API token instead: it begins skmt_, it can be narrowed
below the rights of the account behind it, and it can be revoked without
disturbing anyone's session. Send either as Authorization: Bearer <token>.

Second factors. A handful of routes — revealing a private key, taking a full
backup, restoring one, rotating the master key — need a second factor verified
in the recent past, not merely at sign-in. Call POST /api/v1/auth/step-up
first. API tokens carry no second factor and so cannot use these routes at all,
which is deliberate: step-up exists so a person confirms a dangerous action in
the moment, and a value sitting in a CI variable confirms nothing.

Errors. Failures return {"error": {"code": "...", "message": "..."}} with a
status that means what it says: 400 for a request you can fix, 403 for a
permission you lack, 409 for a conflict with current state, 422 for a request
that is well-formed but impossible.

Lists. List endpoints return {"items": [...], "total": n}.`

// operationID builds a stable identifier from the method and path.
func operationID(route Route) string {
	parts := strings.FieldsFunc(route.Path, func(r rune) bool {
		return r == '/' || r == '{' || r == '}' || r == '-' || r == '.'
	})
	var b strings.Builder
	b.WriteString(strings.ToLower(route.Method))
	for _, p := range parts {
		if p == "api" || p == "v1" {
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]) + p[1:])
	}
	return b.String()
}

// describe folds the route's detail and its authorisation requirements into
// one prose block, because a caller reading the reference wants to know what a
// route needs before they call it, not after it returns 403.
func describe(route Route) string {
	var b strings.Builder
	if route.Detail != "" {
		b.WriteString(route.Detail)
		b.WriteString("\n\n")
	}
	switch {
	case route.Public:
		b.WriteString("No credential required.")
	case route.Permission == "":
		b.WriteString("Requires a session. Acts on the signed-in account.")
	default:
		b.WriteString("Requires the `" + route.Permission + "` permission.")
	}
	if route.StepUp {
		b.WriteString(" Also requires a recently verified second factor, so an API token cannot call it.")
	}
	if route.Return != "" {
		b.WriteString("\n\nReturns: " + route.Return)
	}
	return b.String()
}

func parametersFor(route Route) []map[string]any {
	var out []map[string]any

	for _, name := range pathParams(route.Path) {
		out = append(out, map[string]any{
			"name": name, "in": "path", "required": true,
			"schema":      map[string]any{"type": "string"},
			"description": "Identifier from a list response.",
		})
	}
	for _, p := range route.Query {
		schema := map[string]any{"type": jsonType(p.Type)}
		if p.Repeatable {
			schema = map[string]any{"type": "array", "items": map[string]any{"type": jsonType(p.Type)}}
		}
		out = append(out, map[string]any{
			"name": p.Name, "in": "query", "required": false,
			"schema": schema, "description": p.Description,
		})
	}
	return out
}

func requestBodyFor(route Route) map[string]any {
	props := map[string]any{}
	var required []string

	for _, f := range route.Body {
		props[f.Name] = fieldSchema(f)
		if f.Required {
			required = append(required, f.Name)
		}
	}

	schema := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	return map[string]any{
		"required": len(required) > 0,
		"content":  map[string]any{"application/json": map[string]any{"schema": schema}},
	}
}

func fieldSchema(f Field) map[string]any {
	schema := map[string]any{"description": f.Description}
	switch {
	case strings.HasSuffix(f.Type, "[]"):
		schema["type"] = "array"
		schema["items"] = map[string]any{"type": jsonType(strings.TrimSuffix(f.Type, "[]"))}
	default:
		schema["type"] = jsonType(f.Type)
	}
	return schema
}

func jsonType(t string) string {
	switch t {
	case "integer", "boolean", "object", "number":
		return t
	default:
		return "string"
	}
}

func responsesFor(route Route) map[string]any {
	ok := "200"
	description := "Success."
	switch route.Method {
	case http.MethodPost:
		if strings.Count(route.Path, "/") == 3 && len(pathParams(route.Path)) == 0 {
			ok = "201"
			description = "Created."
		}
	case http.MethodDelete:
		ok = "204"
		description = "Deleted."
	}

	out := map[string]any{
		ok: map[string]any{"description": description},
	}
	if !route.Public {
		out["401"] = map[string]any{"description": "Missing, expired, or revoked credential."}
		out["403"] = map[string]any{"description": "Authenticated, but not permitted."}
	}
	if len(route.Body) > 0 || len(route.Query) > 0 {
		out["400"] = map[string]any{"description": "The request is malformed or a value is out of range."}
	}
	return out
}
