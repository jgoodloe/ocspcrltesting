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

function ResultDetails({ result }: { result: TestResult }) {
  const details = result.details ?? {};
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
      {result.details && Object.keys(result.details).length > 0 ? (
        <pre className="details-json">{JSON.stringify(result.details, null, 2)}</pre>
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
      onClick={() => toggleSort(key)}
      aria-sort={sortKey === key ? (sortAsc ? 'ascending' : 'descending') : 'none'}
      scope="col"
    >
      {label}
      {sortKey === key && <span className="sort-arrow">{sortAsc ? '▲' : '▼'}</span>}
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
                    <td>{r.name}</td>
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
