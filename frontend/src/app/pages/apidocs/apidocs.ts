import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { Api } from '../../core/api';
import type { OpenApiDoc, OpenApiOperation, OpenApiParam } from '../../core/models';
import { Alerts } from '../../shared/alerts';

/** One endpoint, flattened out of the OpenAPI document for rendering. */
interface Endpoint {
  method: string;
  path: string;
  op: OpenApiOperation;
  tag: string;
  search: string;
}

/**
 * The API reference, rendered from the server's own OpenAPI document.
 *
 * Nothing here is written by hand, which is the point: the document is
 * generated from the same route table the router is built from, so this screen
 * cannot describe an endpoint that does not exist or miss one that does.
 */
@Component({
  selector: 'skm-apidocs',
  imports: [FormsModule, Alerts],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .layout { display: grid; grid-template-columns: 12rem 1fr; gap: 1.5rem; align-items: start; }
    @media (max-width: 60rem) { .layout { grid-template-columns: 1fr; } }
    .toc { position: sticky; top: 1rem; }
    .toc a { display: block; padding: 0.2rem 0; font-size: 0.86rem;
             color: var(--text-muted); text-decoration: none; }
    .toc a:hover { color: var(--accent); }
    .intro { white-space: pre-wrap; font-size: 0.9rem; color: var(--text-muted);
             margin-bottom: 1.6rem; }
    .ep { border: 1px solid var(--border-soft); border-radius: var(--radius-md);
          padding: 0.9rem 1.1rem; margin-bottom: 0.7rem; background: var(--bg-panel); }
    .sig { display: flex; gap: 0.7rem; align-items: center; cursor: pointer; flex-wrap: wrap; }
    .m { font-family: var(--mono); font-size: 0.7rem; font-weight: 600; letter-spacing: 0.06em;
         padding: 0.22rem 0.45rem; border-radius: 4px; color: #fff; flex-shrink: 0; }
    .m.GET { background: #4ea1d3; } .m.POST { background: #4caf7d; }
    .m.PATCH { background: #d6a44c; } .m.DELETE { background: #d2686a; }
    .p { font-family: var(--mono); font-size: 0.87rem; }
    .sum { color: var(--text-muted); font-size: 0.86rem; }
    .body { margin-top: 0.9rem; border-top: 1px solid var(--border-soft); padding-top: 0.9rem; }
    .desc { white-space: pre-wrap; font-size: 0.88rem; margin: 0 0 0.8rem; }
    .lbl { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.06em;
           color: var(--text-dim); margin-top: 0.9rem; }
    table { width: 100%; border-collapse: collapse; font-size: 0.84rem; margin-top: 0.4rem; }
    td, th { text-align: left; padding: 0.3rem 0.6rem 0.3rem 0;
             border-bottom: 1px solid var(--border-soft); vertical-align: top; }
    th { font-size: 0.74rem; color: var(--text-dim); font-weight: 500; }
    td.n { font-family: var(--mono); white-space: nowrap; }
    td.t { font-family: var(--mono); font-size: 0.78rem; color: var(--text-dim); white-space: nowrap; }
    .req { color: var(--danger); font-size: 0.72rem; }
    pre { background: var(--bg-sunken); border: 1px solid var(--border-soft);
          border-radius: var(--radius-md); padding: 0.7rem 0.9rem; overflow-x: auto;
          font-family: var(--mono); font-size: 0.78rem; margin: 0.4rem 0 0; }
    .toolbar { display: flex; gap: 0.6rem; align-items: center; margin-bottom: 1.2rem;
               flex-wrap: wrap; }
    .toolbar input { max-width: 20rem; }
    .spacer { flex: 1; }
  `],
  template: `
    <div class="card-header">
      <h1>API reference</h1>
      <a class="ghost sm" href="/api/v1/openapi.json" target="_blank" rel="noopener">openapi.json</a>
    </div>

    <skm-alerts [error]="error" />

    <div class="toolbar">
      <input type="search" placeholder="Filter by path, summary, or permission…"
             [(ngModel)]="query" (ngModelChange)="filter.set($event)" name="q" />
      <span class="spacer"></span>
      <span class="small faint">{{ shown().length }} of {{ endpoints().length }} endpoints</span>
    </div>

    @if (doc(); as d) {
      <div class="intro">{{ d.info.description }}</div>

      <div class="layout">
        <nav class="toc">
          @for (tag of tags(); track tag) {
            <a [href]="'#tag-' + tag" (click)="jump($event, tag)">{{ tag }}</a>
          }
        </nav>

        <div>
          @for (tag of tags(); track tag) {
            @if (byTag(tag).length) {
              <h2 [id]="'tag-' + tag" style="margin-top: 1.6rem;">{{ tag }}</h2>
              @for (e of byTag(tag); track e.method + e.path) {
                <div class="ep">
                  <div class="sig" (click)="toggle(e)">
                    <span class="m" [class]="e.method">{{ e.method }}</span>
                    <span class="p">{{ e.path }}</span>
                    <span class="spacer"></span>
                    <span class="sum">{{ e.op.summary }}</span>
                  </div>

                  @if (open() === e.method + e.path) {
                    <div class="body">
                      <p class="desc">{{ e.op.description }}</p>

                      @if (params(e, 'path').length) {
                        <div class="lbl">Path</div>
                        <table><tbody>
                          @for (p of params(e, 'path'); track p.name) {
                            <tr><td class="n">{{ p.name }}</td><td>{{ p.description }}</td></tr>
                          }
                        </tbody></table>
                      }

                      @if (params(e, 'query').length) {
                        <div class="lbl">Query</div>
                        <table>
                          <thead><tr><th>Name</th><th>Type</th><th>Description</th></tr></thead>
                          <tbody>
                            @for (p of params(e, 'query'); track p.name) {
                              <tr><td class="n">{{ p.name }}</td>
                                  <td class="t">{{ p.schema.type }}</td>
                                  <td>{{ p.description }}</td></tr>
                            }
                          </tbody>
                        </table>
                      }

                      @if (bodyFields(e).length) {
                        <div class="lbl">Body</div>
                        <table>
                          <thead><tr><th>Field</th><th>Type</th><th>Description</th></tr></thead>
                          <tbody>
                            @for (f of bodyFields(e); track f.name) {
                              <tr>
                                <td class="n">{{ f.name }}
                                    @if (f.required) { <span class="req">required</span> }</td>
                                <td class="t">{{ f.type }}</td>
                                <td>{{ f.description }}</td>
                              </tr>
                            }
                          </tbody>
                        </table>
                      }

                      <div class="lbl">Example</div>
                      <pre>{{ curl(e) }}</pre>
                    </div>
                  }
                </div>
              }
            }
          }
        </div>
      </div>
    } @else if (!error()) {
      <div class="empty"><span class="spinner"></span> Loading the specification…</div>
    }
  `,
})
export class ApiDocsPage implements OnInit {
  private readonly api = inject(Api);

  protected readonly doc = signal<OpenApiDoc | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly open = signal<string | null>(null);
  protected readonly filter = signal('');

  protected query = '';

  /** Every operation, flattened once so filtering is a string match. */
  protected readonly endpoints = computed<Endpoint[]>(() => {
    const d = this.doc();
    if (!d) return [];

    const out: Endpoint[] = [];
    for (const [path, methods] of Object.entries(d.paths)) {
      for (const [method, op] of Object.entries(methods)) {
        out.push({
          method: method.toUpperCase(),
          path,
          op,
          tag: op.tags?.[0] ?? 'Other',
          search: `${method} ${path} ${op.summary} ${op.description}`.toLowerCase(),
        });
      }
    }
    return out.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
  });

  protected readonly shown = computed(() => {
    const q = this.filter().trim().toLowerCase();
    if (!q) return this.endpoints();
    return this.endpoints().filter((e) => e.search.includes(q));
  });

  protected readonly tags = computed(() => {
    const seen = new Set(this.shown().map((e) => e.tag));
    return [...seen].sort();
  });

  ngOnInit(): void {
    this.api.openApi().subscribe({
      next: (d) => this.doc.set(d),
      error: (err: Error) => this.error.set(err.message),
    });
  }

  protected byTag(tag: string): Endpoint[] {
    return this.shown().filter((e) => e.tag === tag);
  }

  protected toggle(e: Endpoint): void {
    const key = e.method + e.path;
    this.open.set(this.open() === key ? null : key);
  }

  protected jump(ev: Event, tag: string): void {
    ev.preventDefault();
    document.getElementById('tag-' + tag)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  protected params(e: Endpoint, where: 'path' | 'query'): OpenApiParam[] {
    return (e.op.parameters ?? []).filter((p) => p.in === where);
  }

  protected bodyFields(e: Endpoint): { name: string; type: string; description: string; required: boolean }[] {
    const schema = e.op.requestBody?.content['application/json'].schema;
    if (!schema?.properties) return [];

    const required = new Set(schema.required ?? []);
    return Object.entries(schema.properties).map(([name, prop]) => ({
      name,
      type: prop.type,
      description: prop.description,
      required: required.has(name),
    }));
  }

  /** A copyable example, built the same way the server's own page builds one. */
  protected curl(e: Endpoint): string {
    const lines = ['curl -sS'];
    if (e.method !== 'GET') lines[0] += ` -X ${e.method}`;
    lines.push(`  -H 'Authorization: Bearer $SKM_TOKEN'`);

    const fields = this.bodyFields(e).filter((f) => f.required);
    if (fields.length) {
      lines.push(`  -H 'Content-Type: application/json'`);
      const body = fields.map((f) => `"${f.name}": ${sample(f.type)}`).join(', ');
      lines.push(`  -d '{${body}}'`);
    }
    lines.push(`  "$SKM_URL${e.path}"`);
    return lines.join(' \\\n');
  }
}

function sample(type: string): string {
  switch (type) {
    case 'boolean': return 'true';
    case 'integer': return '0';
    case 'array': return '["…"]';
    case 'object': return '{}';
    default: return '"…"';
  }
}
