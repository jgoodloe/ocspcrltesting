import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { CountChips } from '../components/CountChips';
import { StatusPill } from '../components/StatusPill';
import {
  ApiError,
  deleteRun,
  listRuns,
  type RunStatus,
  type RunSummary,
} from '../lib/api';
import { formatDateTime, formatDurationMs, statusLabel } from '../lib/format';

const PAGE_SIZE = 20;

const STATUS_OPTIONS: Array<RunStatus | ''> = [
  '',
  'queued',
  'running',
  'completed',
  'failed',
  'cancelled',
  'timed_out',
];

export function RunsHistory() {
  const navigate = useNavigate();
  const [runs, setRuns] = useState<RunSummary[] | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [status, setStatus] = useState<RunStatus | ''>('');
  const [query, setQuery] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<RunSummary | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await listRuns({ limit: PAGE_SIZE, offset, status });
      setRuns(res.items);
      setTotal(res.total);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : 'Could not reach the API.');
    }
  }, [offset, status]);

  useEffect(() => {
    void load();
  }, [load]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q || !runs) return runs ?? [];
    return runs.filter(
      (r) =>
        (r.name ?? '').toLowerCase().includes(q) ||
        r.ocsp_url.toLowerCase().includes(q),
    );
  }, [runs, query]);

  const handleDelete = async () => {
    if (!pendingDelete) return;
    try {
      await deleteRun(pendingDelete.id);
      setPendingDelete(null);
      void load();
    } catch (err) {
      setPendingDelete(null);
      setError(err instanceof ApiError ? err.detail : 'Delete failed.');
    }
  };

  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">Runs</h1>
          <p className="page-subtitle">All test runs, newest first.</p>
        </div>
        <Link to="/runs/new" className="btn btn-primary">
          New test run
        </Link>
      </div>

      {error && (
        <div className="form-error" role="alert">
          <span className="err-status">Error</span>
          {error}
        </div>
      )}

      <div className="panel">
        <div className="toolbar" style={{ marginBottom: 12 }}>
          <input
            className="input"
            type="search"
            placeholder="Search by name or URL…"
            style={{ maxWidth: 280 }}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Search runs"
          />
          <select
            className="select"
            style={{ maxWidth: 180 }}
            value={status}
            onChange={(e) => {
              setStatus(e.target.value as RunStatus | '');
              setOffset(0);
            }}
            aria-label="Filter by status"
          >
            {STATUS_OPTIONS.map((s) => (
              <option key={s || 'all'} value={s}>
                {s ? statusLabel(s) : 'All statuses'}
              </option>
            ))}
          </select>
        </div>

        {runs === null ? (
          <div className="loading">Loading…</div>
        ) : visible.length === 0 ? (
          <div className="table-empty">No runs match.</div>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Run</th>
                  <th scope="col">Status</th>
                  <th scope="col">Results</th>
                  <th scope="col">Median latency</th>
                  <th scope="col">Created</th>
                  <th scope="col" aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {visible.map((run) => (
                  <tr
                    key={run.id}
                    className="clickable"
                    onClick={() => navigate(`/runs/${run.id}`)}
                  >
                    <td>
                      <Link to={`/runs/${run.id}`} onClick={(e) => e.stopPropagation()}>
                        {run.name || run.ocsp_url}
                      </Link>
                      {run.name && (
                        <div className="faint mono truncate">{run.ocsp_url}</div>
                      )}
                    </td>
                    <td>
                      <StatusPill status={run.status} />
                    </td>
                    <td>
                      <CountChips totals={run.totals} />
                    </td>
                    <td className="nowrap mono muted">
                      {run.latency ? formatDurationMs(run.latency.median_ms) : '—'}
                    </td>
                    <td className="nowrap muted">{formatDateTime(run.created_at)}</td>
                    <td className="nowrap" style={{ textAlign: 'right' }}>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          setPendingDelete(run);
                        }}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="pager">
          <span>
            Page {page} of {pages} · {total} runs
          </span>
          <button
            type="button"
            className="btn btn-sm"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          >
            ← Prev
          </button>
          <button
            type="button"
            className="btn btn-sm"
            disabled={offset + PAGE_SIZE >= total}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >
            Next →
          </button>
        </div>
      </div>

      {pendingDelete && (
        <ConfirmDialog
          title="Delete this run?"
          confirmLabel="Delete run"
          danger
          onConfirm={() => void handleDelete()}
          onCancel={() => setPendingDelete(null)}
        >
          {`Deletes “${pendingDelete.name || pendingDelete.ocsp_url}” with its results and logs.`}
        </ConfirmDialog>
      )}
    </>
  );
}
