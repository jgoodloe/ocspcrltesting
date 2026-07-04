import { Fragment, useMemo, useState } from 'react';
import type { ResultStatus, TestResult } from '../lib/api';
import { formatDurationMs } from '../lib/format';
import { StatusPill } from './StatusPill';

type SortKey = 'category' | 'name' | 'status' | 'duration_ms';

const STATUS_ORDER: Record<ResultStatus, number> = {
  FAIL: 0,
  ERROR: 1,
  WARN: 2,
  PASS: 3,
  SKIP: 4,
};

const ALL_STATUSES: ResultStatus[] = ['PASS', 'FAIL', 'WARN', 'SKIP', 'ERROR'];

/** Well-known detail keys highlighted above the raw JSON drill-down. */
const HIGHLIGHT_FIELDS: Array<{ keys: string[]; label: string }> = [
  { keys: ['responder_id', 'responderId'], label: 'Responder ID' },
  { keys: ['signature_algorithm_oid', 'sig_alg_oid'], label: 'Signature algorithm OID' },
  { keys: ['this_update', 'thisUpdate'], label: 'thisUpdate' },
  { keys: ['next_update', 'nextUpdate'], label: 'nextUpdate' },
  { keys: ['produced_at', 'producedAt'], label: 'producedAt' },
  { keys: ['nonce_echoed'], label: 'Nonce echoed' },
  { keys: ['latency_ms', 'latency'], label: 'Latency' },
];

function detailValue(details: Record<string, unknown>, keys: string[]): unknown {
  for (const k of keys) {
    if (k in details && details[k] !== null && details[k] !== undefined) {
      return details[k];
    }
  }
  return undefined;
}

function renderScalar(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

interface HttpRecord {
  method?: string;
  url?: string;
  status_code?: number;
  reason?: string;
  error?: string;
  duration_ms?: number;
  request_bytes?: number;
  request_body_b64?: string;
  response_bytes?: number;
  response_body_b64?: string;
  response_content_type?: string;
  curl?: string;
  started_at?: string;
}

interface CommandRecord {
  command?: string;
  returncode?: number;
  error?: string;
  duration_ms?: number;
  stdout_excerpt?: string;
  stderr_excerpt?: string;
  started_at?: string;
}

interface Diagnostics {
  http?: HttpRecord[];
  commands?: CommandRecord[];
}

function getDiagnostics(details: Record<string, unknown>): Diagnostics | null {
  const diag = details['diagnostics'];
  if (!diag || typeof diag !== 'object') return null;
  const d = diag as Diagnostics;
  const http = Array.isArray(d.http) ? d.http : [];
  const commands = Array.isArray(d.commands) ? d.commands : [];
  if (http.length === 0 && commands.length === 0) return null;
  return { http, commands };
}

/**
 * Troubleshooting drill-down: every HTTP exchange and external command the
 * test performed, with reproduction hints and raw payloads.
 */
function DiagnosticsSection({ diag }: { diag: Diagnostics }) {
  const http = diag.http ?? [];
  const commands = diag.commands ?? [];
  return (
    <div className="diag-section">
      {http.length > 0 && (
        <>
          <h4 className="diag-heading">Network requests ({http.length})</h4>
          {http.map((h, i) => (
            <details className="diag-item" key={i}>
              <summary>
                <span className="mono diag-summary-main">
                  {h.method ?? '?'} {h.url ?? '?'}
                </span>
                <span className="diag-summary-meta">
                  {h.error
                    ? `failed: ${h.error}`
                    : `HTTP ${h.status_code ?? '?'}${h.reason ? ` ${h.reason}` : ''}`}
                  {typeof h.response_bytes === 'number' ? ` · ${h.response_bytes} B` : ''}
                  {typeof h.duration_ms === 'number' ? ` · ${h.duration_ms} ms` : ''}
                </span>
              </summary>
              <div className="diag-body">
                {h.curl && (
                  <div className="diag-field">
                    <span className="kv-key">Reproduce with curl</span>
                    <pre className="details-json diag-pre">{h.curl}</pre>
                  </div>
                )}
                {h.request_body_b64 && (
                  <div className="diag-field">
                    <span className="kv-key">
                      Request body ({h.request_bytes ?? '?'} bytes, base64 DER)
                    </span>
                    <pre className="details-json diag-pre">{h.request_body_b64}</pre>
                  </div>
                )}
                {h.response_body_b64 && (
                  <div className="diag-field">
                    <span className="kv-key">
                      Response body ({h.response_bytes ?? '?'} bytes
                      {h.response_content_type ? `, ${h.response_content_type}` : ''}, base64)
                    </span>
                    <pre className="details-json diag-pre">{h.response_body_b64}</pre>
                  </div>
                )}
              </div>
            </details>
          ))}
        </>
      )}
      {commands.length > 0 && (
        <>
          <h4 className="diag-heading">Commands executed ({commands.length})</h4>
          {commands.map((c, i) => (
            <details className="diag-item" key={i}>
              <summary>
                <span className="mono diag-summary-main">{c.command ?? '?'}</span>
                <span className="diag-summary-meta">
                  {c.error ? `failed: ${c.error}` : `exit ${c.returncode ?? '?'}`}
                  {typeof c.duration_ms === 'number' ? ` · ${c.duration_ms} ms` : ''}
                </span>
              </summary>
              <div className="diag-body">
                {c.stdout_excerpt && (
                  <div className="diag-field">
                    <span className="kv-key">stdout</span>
                    <pre className="details-json diag-pre">{c.stdout_excerpt}</pre>
                  </div>
                )}
                {c.stderr_excerpt && (
                  <div className="diag-field">
                    <span className="kv-key">stderr</span>
                    <pre className="details-json diag-pre">{c.stderr_excerpt}</pre>
                  </div>
                )}
                {!c.stdout_excerpt && !c.stderr_excerpt && (
                  <div className="faint">No captured output.</div>
                )}
              </div>
            </details>
          ))}
        </>
      )}
    </div>
  );
}

function ResultDetails({ result }: { result: TestResult }) {
  const details = result.details ?? {};
  const diagnostics = getDiagnostics(details);
  const highlights = HIGHLIGHT_FIELDS.map((f) => ({
    label: f.label,
    value: detailValue(details, f.keys),
  })).filter((f) => f.value !== undefined);
  const rfcRefs = Array.isArray(details['rfc_refs'])
    ? (details['rfc_refs'] as unknown[]).map(renderScalar)
    : [];

  return (
    <div className="detail-drawer">
      {result.message && (
        <p style={{ marginTop: 0 }}>
          <span className="kv-key">Message</span> {result.message}
        </p>
      )}
      {(highlights.length > 0 || rfcRefs.length > 0) && (
        <div className="kv-grid">
          {highlights.map((h) => (
            <div className="kv" key={h.label}>
              <span className="kv-key">{h.label}</span>
              <span className="kv-value">{renderScalar(h.value)}</span>
            </div>
          ))}
          {rfcRefs.length > 0 && (
            <div className="kv">
              <span className="kv-key">RFC references</span>
              <span className="rfc-refs">
                {rfcRefs.map((r) => (
                  <span key={r} className="rfc-ref">
                    {r}
                  </span>
                ))}
              </span>
            </div>
          )}
        </div>
      )}
      {diagnostics && <DiagnosticsSection diag={diagnostics} />}
      {result.details && Object.keys(result.details).length > 0 ? (
        <details className="diag-item" style={{ marginTop: 8 }}>
          <summary>
            <span className="diag-summary-main">Raw test details (JSON)</span>
          </summary>
          <pre className="details-json" style={{ marginTop: 6 }}>
            {JSON.stringify(result.details, null, 2)}
          </pre>
        </details>
      ) : (
        <div className="faint">No structured details for this test.</div>
      )}
    </div>
  );
}

/**
 * Sortable, filterable results table with an expandable drill-down row.
 * Grows live as `result` stream events arrive.
 */
export function ResultsTable({ results }: { results: TestResult[] }) {
  const [sortKey, setSortKey] = useState<SortKey>('category');
  const [sortAsc, setSortAsc] = useState(true);
  const [statusFilter, setStatusFilter] = useState<Set<ResultStatus>>(new Set());
  const [categoryFilter, setCategoryFilter] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState('');
  const [openId, setOpenId] = useState<string | null>(null);

  const categories = useMemo(
    () => Array.from(new Set(results.map((r) => r.category))).sort(),
    [results],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    let rows = results;
    if (statusFilter.size > 0) rows = rows.filter((r) => statusFilter.has(r.status));
    if (categoryFilter.size > 0) rows = rows.filter((r) => categoryFilter.has(r.category));
    if (q) {
      rows = rows.filter(
        (r) =>
          r.name.toLowerCase().includes(q) ||
          r.message.toLowerCase().includes(q) ||
          r.category.toLowerCase().includes(q),
      );
    }
    const dir = sortAsc ? 1 : -1;
    return [...rows].sort((a, b) => {
      switch (sortKey) {
        case 'status':
          return (STATUS_ORDER[a.status] - STATUS_ORDER[b.status]) * dir;
        case 'duration_ms':
          return ((a.duration_ms ?? -1) - (b.duration_ms ?? -1)) * dir;
        case 'name':
          return a.name.localeCompare(b.name) * dir;
        case 'category':
        default:
          return (
            (a.category.localeCompare(b.category) || a.name.localeCompare(b.name)) * dir
          );
      }
    });
  }, [results, statusFilter, categoryFilter, query, sortKey, sortAsc]);

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) {
      setSortAsc((v) => !v);
    } else {
      setSortKey(key);
      setSortAsc(true);
    }
  };

  const toggleSet = <T,>(set: Set<T>, value: T, apply: (next: Set<T>) => void) => {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    apply(next);
  };

  const header = (key: SortKey, label: string) => (
    <th
      className="sortable"
      aria-sort={sortKey === key ? (sortAsc ? 'ascending' : 'descending') : 'none'}
      scope="col"
    >
      <button type="button" className="th-sort" onClick={() => toggleSort(key)}>
        {label}
        {sortKey === key && (
          <span className="sort-arrow" aria-hidden="true">
            {sortAsc ? '▲' : '▼'}
          </span>
        )}
      </button>
    </th>
  );

  return (
    <div>
      <div className="toolbar" style={{ marginBottom: 10 }}>
        <input
          className="input"
          type="search"
          placeholder="Search results…"
          style={{ maxWidth: 240 }}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Search results"
        />
        <div className="filter-chips">
          {ALL_STATUSES.map((s) => (
            <button
              key={s}
              type="button"
              className={`filter-chip${statusFilter.has(s) ? ' on' : ''}`}
              aria-pressed={statusFilter.has(s)}
              onClick={() => toggleSet(statusFilter, s, setStatusFilter)}
            >
              {s}
            </button>
          ))}
        </div>
      </div>
      {categories.length > 1 && (
        <div className="filter-chips" style={{ marginBottom: 10 }}>
          {categories.map((c) => (
            <button
              key={c}
              type="button"
              className={`filter-chip${categoryFilter.has(c) ? ' on' : ''}`}
              aria-pressed={categoryFilter.has(c)}
              onClick={() => toggleSet(categoryFilter, c, setCategoryFilter)}
            >
              {c}
            </button>
          ))}
        </div>
      )}
      <div className="table-wrap" style={{ maxHeight: 560, overflow: 'auto' }}>
        <table className="data">
          <thead>
            <tr>
              {header('category', 'Category')}
              {header('name', 'Test')}
              {header('status', 'Status')}
              {header('duration_ms', 'Duration')}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={4}>
                  <div className="table-empty">
                    {results.length === 0
                      ? 'No results yet — they appear here as tests complete.'
                      : 'No results match the current filters.'}
                  </div>
                </td>
              </tr>
            ) : (
              filtered.map((r) => (
                <Fragment key={r.id}>
                  <tr
                    className={`clickable${openId === r.id ? ' selected' : ''}`}
                    onClick={() => setOpenId(openId === r.id ? null : r.id)}
                  >
                    <td className="nowrap muted">{r.category}</td>
                    <td>
                      <button
                        type="button"
                        className="row-toggle"
                        aria-expanded={openId === r.id}
                        onClick={(e) => {
                          e.stopPropagation();
                          setOpenId(openId === r.id ? null : r.id);
                        }}
                      >
                        {r.name}
                      </button>
                    </td>
                    <td>
                      <StatusPill status={r.status} />
                    </td>
                    <td className="nowrap mono">{formatDurationMs(r.duration_ms)}</td>
                  </tr>
                  {openId === r.id && (
                    <tr className="selected">
                      <td colSpan={4} style={{ padding: 0 }}>
                        <ResultDetails result={r} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))
            )}
          </tbody>
        </table>
      </div>
      <div className="pager">
        <span>
          {filtered.length} of {results.length} results
        </span>
      </div>
    </div>
  );
}
