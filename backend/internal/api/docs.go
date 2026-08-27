package api

import (
	"html/template"
	"net/http"
	"sort"
	"strings"

	"github.com/hamalawy/ssh-key-manager/backend/internal/events"
)

// handleAPIDocs serves a browsable reference for the same route table the
// router is built from.
//
// It is server-rendered and self-contained — no script, no fonts, no
// stylesheet from anywhere else. Documentation is the thing you reach for when
// something is broken, and that is exactly when a page that needs the internet
// to render is least useful.
func (s *Server) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	routes := s.routes()

	groups := map[string][]Route{}
	for _, route := range routes {
		groups[route.Tag] = append(groups[route.Tag], route)
	}

	tags := make([]string, 0, len(groups))
	for tag := range groups {
		tags = append(tags, tag)
		sort.Slice(groups[tag], func(i, j int) bool {
			if groups[tag][i].Path != groups[tag][j].Path {
				return groups[tag][i].Path < groups[tag][j].Path
			}
			return methodOrder(groups[tag][i].Method) < methodOrder(groups[tag][j].Method)
		})
	}
	sort.Strings(tags)

	data := struct {
		Tags    []string
		Groups  map[string][]Route
		Events  []string
		Version string
		Count   int
		Intro   string
	}{tags, groups, events.All, Version, len(routes), apiDescription}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := docsTemplate.Execute(w, data); err != nil && s.Log != nil {
		s.Log.Error("rendering api docs", "error", err)
	}
}

func methodOrder(m string) int {
	switch m {
	case http.MethodGet:
		return 0
	case http.MethodPost:
		return 1
	case http.MethodPatch:
		return 2
	default:
		return 3
	}
}

var docsFuncs = template.FuncMap{
	"anchor": func(route Route) string {
		return strings.ToLower(route.Method) + strings.NewReplacer(
			"/", "-", "{", "", "}", "", ".", "-").Replace(route.Path)
	},
	"tagAnchor": func(tag string) string {
		return "tag-" + strings.ToLower(strings.ReplaceAll(tag, " ", "-"))
	},
	"pathParams": pathParams,
	"curl": func(route Route) string {
		var b strings.Builder
		b.WriteString("curl -sS")
		if route.Method != http.MethodGet {
			b.WriteString(" -X " + route.Method)
		}
		if !route.Public {
			b.WriteString(" \\\n  -H 'Authorization: Bearer $SKM_TOKEN'")
		}
		if len(route.Body) > 0 {
			b.WriteString(" \\\n  -H 'Content-Type: application/json'")
			var fields []string
			for _, f := range route.Body {
				if f.Required {
					fields = append(fields, `"`+f.Name+`": `+sampleValue(f))
				}
			}
			if len(fields) == 0 && len(route.Body) > 0 {
				fields = append(fields, `"`+route.Body[0].Name+`": `+sampleValue(route.Body[0]))
			}
			b.WriteString(" \\\n  -d '{" + strings.Join(fields, ", ") + "}'")
		}
		b.WriteString(" \\\n  \"$SKM_URL" + route.Path + "\"")
		return b.String()
	},
}

func sampleValue(f Field) string {
	switch {
	case strings.HasSuffix(f.Type, "[]"):
		return `["…"]`
	case f.Type == "boolean":
		return "true"
	case f.Type == "integer":
		return "0"
	case f.Type == "object":
		return "{}"
	default:
		return `"…"`
	}
}

var docsTemplate = template.Must(template.New("docs").Funcs(docsFuncs).Parse(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SKM API reference</title>
<style>
 :root {
   --bg:#0f1115; --panel:#161a21; --sunken:#0b0d11; --border:#262c36;
   --text:#dce3ec; --dim:#8b96a5; --accent:#5aa9e6;
   --get:#4ea1d3; --post:#4caf7d; --patch:#d6a44c; --delete:#d2686a;
   --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
 }
 @media (prefers-color-scheme: light) {
   :root { --bg:#fbfcfd; --panel:#fff; --sunken:#f3f5f8; --border:#dde3ea;
           --text:#1b2029; --dim:#5d6875; }
 }
 * { box-sizing:border-box; }
 body { margin:0; background:var(--bg); color:var(--text); display:flex;
        font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif; }
 nav { width:16rem; flex-shrink:0; border-right:1px solid var(--border);
       padding:1.5rem 1rem; position:sticky; top:0; height:100vh; overflow-y:auto; }
 nav h1 { font-size:1rem; margin:0 0 .2rem; }
 nav p { font-size:.78rem; color:var(--dim); margin:0 0 1.2rem; }
 nav a { display:block; color:var(--text); text-decoration:none; padding:.25rem 0;
         font-size:.87rem; }
 nav a:hover { color:var(--accent); }
 main { flex:1; padding:2rem 2.5rem; max-width:64rem; overflow-x:hidden; }
 h2 { margin:2.5rem 0 .8rem; padding-bottom:.4rem; border-bottom:1px solid var(--border); }
 h2:first-of-type { margin-top:0; }
 .intro { white-space:pre-wrap; color:var(--dim); font-size:.92rem; margin-bottom:2rem; }
 .ep { background:var(--panel); border:1px solid var(--border); border-radius:8px;
       padding:1rem 1.2rem; margin-bottom:1rem; }
 .sig { display:flex; align-items:center; gap:.7rem; flex-wrap:wrap; }
 .m { font:600 .74rem/1 var(--mono); letter-spacing:.06em; padding:.32rem .5rem;
      border-radius:4px; color:#fff; }
 .m.GET{background:var(--get)} .m.POST{background:var(--post)}
 .m.PATCH{background:var(--patch)} .m.DELETE{background:var(--delete)}
 .path { font-family:var(--mono); font-size:.9rem; }
 .sum { color:var(--dim); font-size:.9rem; margin:.5rem 0 0; }
 .detail { font-size:.9rem; margin:.7rem 0 0; }
 .badges { margin-top:.6rem; display:flex; gap:.4rem; flex-wrap:wrap; }
 .badge { font-size:.72rem; border:1px solid var(--border); border-radius:999px;
          padding:.1rem .55rem; color:var(--dim); font-family:var(--mono); }
 .badge.perm { color:var(--accent); border-color:var(--accent); }
 .badge.step { color:var(--patch); border-color:var(--patch); }
 .badge.open { color:var(--post); border-color:var(--post); }
 table { width:100%; border-collapse:collapse; margin-top:.8rem; font-size:.86rem; }
 th { text-align:left; color:var(--dim); font-weight:500; font-size:.78rem;
      border-bottom:1px solid var(--border); padding:.3rem .5rem .3rem 0; }
 td { padding:.35rem .5rem .35rem 0; border-bottom:1px solid var(--border);
      vertical-align:top; }
 td.n { font-family:var(--mono); white-space:nowrap; }
 td.t { color:var(--dim); font-family:var(--mono); font-size:.8rem; white-space:nowrap; }
 .req { color:var(--delete); font-size:.72rem; }
 pre { background:var(--sunken); border:1px solid var(--border); border-radius:6px;
       padding:.7rem .9rem; overflow-x:auto; font-family:var(--mono);
       font-size:.8rem; margin:.8rem 0 0; }
 .label { font-size:.75rem; color:var(--dim); text-transform:uppercase;
          letter-spacing:.06em; margin-top:1rem; }
 code { font-family:var(--mono); font-size:.85em; background:var(--sunken);
        padding:.05em .35em; border-radius:3px; }
 .events { display:flex; flex-wrap:wrap; gap:.4rem; }
</style>
</head><body>
<nav>
  <h1>SKM API</h1>
  <p>v{{.Version}} · {{.Count}} endpoints</p>
  {{range .Tags}}<a href="#{{tagAnchor .}}">{{.}}</a>{{end}}
  <a href="/api/v1/openapi.json" style="margin-top:1rem;color:var(--accent)">openapi.json</a>
</nav>
<main>
  <div class="intro">{{$.Intro}}</div>
  {{range $tag := .Tags}}
  <h2 id="{{tagAnchor $tag}}">{{$tag}}</h2>
  {{range $r := index $.Groups $tag}}
  <div class="ep" id="{{anchor $r}}">
    <div class="sig">
      <span class="m {{$r.Method}}">{{$r.Method}}</span>
      <span class="path">{{$r.Path}}</span>
    </div>
    <p class="sum">{{$r.Summary}}</p>
    {{if $r.Detail}}<p class="detail">{{$r.Detail}}</p>{{end}}
    <div class="badges">
      {{if $r.Public}}<span class="badge open">no credential</span>
      {{else if $r.Permission}}<span class="badge perm">{{$r.Permission}}</span>
      {{else}}<span class="badge">any session</span>{{end}}
      {{if $r.StepUp}}<span class="badge step">second factor</span>{{end}}
    </div>

    {{if pathParams $r.Path}}
    <div class="label">Path</div>
    <table><tbody>
      {{range pathParams $r.Path}}<tr><td class="n">{{.}}</td>
        <td>Identifier from a list response.</td></tr>{{end}}
    </tbody></table>
    {{end}}

    {{if $r.Query}}
    <div class="label">Query</div>
    <table><thead><tr><th>Name</th><th>Type</th><th>Description</th></tr></thead><tbody>
      {{range $r.Query}}<tr>
        <td class="n">{{.Name}}</td>
        <td class="t">{{.Type}}{{if .Repeatable}} (repeatable){{end}}</td>
        <td>{{.Description}}</td></tr>{{end}}
    </tbody></table>
    {{end}}

    {{if $r.Body}}
    <div class="label">Body</div>
    <table><thead><tr><th>Field</th><th>Type</th><th>Description</th></tr></thead><tbody>
      {{range $r.Body}}<tr>
        <td class="n">{{.Name}}{{if .Required}} <span class="req">required</span>{{end}}</td>
        <td class="t">{{.Type}}</td>
        <td>{{.Description}}</td></tr>{{end}}
    </tbody></table>
    {{end}}

    {{if $r.Return}}<div class="label">Returns</div><pre>{{$r.Return}}</pre>{{end}}
    <div class="label">Example</div>
    <pre>{{curl $r}}</pre>
  </div>
  {{end}}
  {{end}}

  <h2 id="events">Event types</h2>
  <p class="sum">Every type this build emits. A webhook may subscribe to any of
     them, or to none, which means all.</p>
  <div class="events">{{range .Events}}<span class="badge">{{.}}</span>{{end}}</div>
</main>
</body></html>
`))
