package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hamalawy/ssh-key-manager/backend/internal/authz"
)

// The point of generating documentation from the route table is that the two
// cannot disagree. These tests hold that line: a route added without a
// description fails here rather than shipping as an undocumented endpoint.

func TestEveryRouteIsDescribed(t *testing.T) {
	s := &Server{}

	for _, route := range s.routes() {
		where := route.Method + " " + route.Path

		if route.Summary == "" {
			t.Errorf("%s has no summary", where)
		}
		if route.Tag == "" {
			t.Errorf("%s has no tag, so it appears in no section", where)
		}
		if route.Handler == nil {
			t.Errorf("%s has no handler", where)
		}
		if strings.HasSuffix(route.Summary, ".") == false {
			t.Errorf("%s: summary should read as a sentence: %q", where, route.Summary)
		}
	}
}

func TestRoutePermissionsAreReal(t *testing.T) {
	s := &Server{}

	for _, route := range s.routes() {
		if route.Permission == "" {
			continue
		}
		if !authz.IsKnown(authz.Permission(route.Permission)) {
			t.Errorf("%s %s documents permission %q, which this build does not define",
				route.Method, route.Path, route.Permission)
		}
	}
}

func TestRoutePatternsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	s := &Server{}

	for _, route := range s.routes() {
		key := route.Method + " " + route.Path
		if seen[key] {
			// ServeMux panics on a duplicate pattern, which would take the
			// whole server down at boot rather than at review time.
			t.Errorf("%s is registered twice", key)
		}
		seen[key] = true
	}
}

func TestOpenAPIDocumentIsWellFormed(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleOpenAPI(rec, httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}

	var doc struct {
		OpenAPI string                                `json:"openapi"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
		Tags    []map[string]string                   `json:"tags"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("the document is not valid JSON: %v", err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Errorf("openapi version %q", doc.OpenAPI)
	}

	operations := 0
	for _, methods := range doc.Paths {
		operations += len(methods)
	}
	if want := len(s.routes()); operations != want {
		t.Errorf("the document describes %d operations for %d routes", operations, want)
	}
	if len(doc.Tags) == 0 {
		t.Error("no tags, so the reference has no sections")
	}
}

func TestOperationIDsAreUnique(t *testing.T) {
	// A duplicate operationId makes generated clients collide, which is the
	// kind of thing only discovered by whoever generates the client.
	seen := map[string]string{}
	s := &Server{}

	for _, route := range s.routes() {
		id := operationID(route)
		if prior, ok := seen[id]; ok {
			t.Errorf("operationId %q is produced by both %s and %s %s",
				id, prior, route.Method, route.Path)
		}
		seen[id] = route.Method + " " + route.Path
	}
}

func TestStepUpRoutesAreTheSensitiveOnes(t *testing.T) {
	// Not a mirror of the implementation: this asserts the product decision
	// that every route emitting or accepting whole private keys is gated by a
	// second factor. Adding a new one without the gate should fail here.
	want := map[string]bool{
		"POST /api/v1/keys/{id}/reveal": true,
		"POST /api/v1/backups":          true,
		"POST /api/v1/restore":          true,
		"POST /api/v1/vault/rotate-kek": true,
	}

	s := &Server{}
	for _, route := range s.routes() {
		key := route.Method + " " + route.Path
		if want[key] && !route.StepUp {
			t.Errorf("%s should require a second factor", key)
		}
		if !want[key] && route.StepUp {
			t.Errorf("%s requires a second factor but is not on the list; "+
				"if that is deliberate, add it here", key)
		}
	}
}

func TestDocsPageRenders(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleAPIDocs(rec, httptest.NewRequest(http.MethodGet, "/api/v1/docs", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()

	// The page must be self-contained: a reference that needs the internet to
	// render is useless in exactly the situation it is reached for.
	for _, forbidden := range []string{"http://", "https://", "//cdn", "<script"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the reference page pulls in %q", forbidden)
		}
	}
	for _, want := range []string{"/api/v1/keys", "second factor", "openapi.json"} {
		if !strings.Contains(body, want) {
			t.Errorf("the reference page is missing %q", want)
		}
	}
}
