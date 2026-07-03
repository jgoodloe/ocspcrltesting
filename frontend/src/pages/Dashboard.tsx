import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { CountChips } from '../components/CountChips';
import { StatCard } from '../components/StatCard';
import { StatusPill } from '../components/StatusPill';
import { ApiError, listRuns, type RunSummary } from '../lib/api';
import { formatDateTime, formatRelative } from '../lib/format';

const REFRESH_MS = 8000;

export function Dashboard() {
  const navigate = useNavigate();
  const [runs, setRuns] = useState<RunSummary[] | null>(null);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const load = async () => {
      try {
        const res = await listRuns({ limit: 10, offset: 0 });
        if (cancelled) return;
        setRuns(res.items);
        setTotal(res.total);
        setError(null);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.detail : 'Could not reach the API.');
      } finally {
        if (!cancelled) {
          timer = setTimeout(() => void load(), REFRESH_MS);
        }
      }
    };
    void load();
    return () => {
      cancelled = true;
      if (timer !== null) clearTimeout(timer);
    };
  }, []);

  const stats = useMemo(() => {
    const list = runs ?? [];
    const sums = { pass: 0, fail: 0, warn: 0, error: 0 };
    for (const r of list) {
      sums.pass += r.totals?.pass ?? 0;
      sums.fail += r.totals?.fail ?? 0;
      sums.warn += r.totals?.warn ?? 0;
      sums.error += r.totals?.error ?? 0;
    }
    const lastRun = list[0] ?? null;
    const lastCompleted = list.find((r) => r.status === 'completed' && r.latency) ?? null;
    return { sums, lastRun, lastCompleted };
  }, [runs]);

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">
            OCSP / CRL / PKI responder test overview
          </p>
        </div>
        <Link to="/runs/new" className="btn btn-primary">
          New test run
        </Link>
      </div>

      {error && (
        <div className="form-error">
          <span className="err-status">API error</span>
          {error}
        </div>
      )}

      <div className="stat-grid">
        <StatCard label="Total runs" value={total} sub="all time" />
        <StatCard
          label="Pass"
          value={stats.sums.pass}
          tone="pass"
          sub="recent 10 runs"
        />
        <StatCard
          label="Fail"
          value={stats.sums.fail}
          tone={stats.sums.fail > 0 ? 'fail' : undefined}
          sub="recent 10 runs"
        />
        <StatCard
          label="Warn"
          value={stats.sums.warn}
          tone={stats.sums.warn > 0 ? 'warn' : undefined}
          sub="recent 10 runs"
        />
        <StatCard
          label="Error"
          value={stats.sums.error}
          tone={stats.sums.error > 0 ? 'error' : undefined}
          sub="recent 10 runs"
        />
        <StatCard
          label="Last run"
          value={stats.lastRun ? formatRelative(stats.lastRun.created_at) : '—'}
          sub={stats.lastRun ? formatDateTime(stats.lastRun.created_at) : 'no runs yet'}
        />
        <StatCard
          label="Median latency"
          value={
            stats.lastCompleted?.latency
              ? `${stats.lastCompleted.latency.median_ms} ms`
              : '—'
          }
          tone="accent"
          sub={
            stats.lastCompleted
              ? `latest completed run (${stats.lastCompleted.latency?.samples ?? 0} samples)`
              : 'no completed run'
          }
        />
      </div>

      <div className="panel">
        <div className="panel-header">
          <h2 className="section-label" style={{ margin: 0 }}>
            Recent runs
          </h2>
          <Link to="/runs" className="btn btn-ghost btn-sm">
            View all →
          </Link>
        </div>
        {runs === null ? (
          <div className="loading">Loading…</div>
        ) : runs.length === 0 ? (
          <div className="table-empty">
            No runs yet. Start with a{' '}
            <Link to="/runs/new">new test run</Link>.
          </div>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Run</th>
                  <th scope="col">Status</th>
                  <th scope="col">Results</th>
                  <th scope="col">Created</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
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
                    <td className="nowrap muted" title={formatDateTime(run.created_at)}>
                      {formatRelative(run.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
