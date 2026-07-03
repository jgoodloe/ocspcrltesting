import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { CountChips } from '../components/CountChips';
import { LogViewer } from '../components/LogViewer';
import { ResultsTable } from '../components/ResultsTable';
import { RunProgress } from '../components/RunProgress';
import { StatusPill } from '../components/StatusPill';
import {
  ApiError,
  cancelRun,
  deleteRun,
  exportCsvUrl,
  exportJsonUrl,
  getLogs,
  getResults,
  getRun,
  isTerminalStatus,
  type LogLine,
  type ProgressData,
  type RunDetail,
  type TestResult,
} from '../lib/api';
import { formatDateTime, formatDurationMs } from '../lib/format';
import {
  connectRunStream,
  type StreamConnectionState,
  type StreamHandle,
  type StreamTransport,
} from '../lib/stream';

export function RunDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [run, setRun] = useState<RunDetail | null>(null);
  const [results, setResults] = useState<TestResult[]>([]);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [progress, setProgress] = useState<ProgressData | null>(null);
  const [conn, setConn] = useState<{
    state: StreamConnectionState;
    transport: StreamTransport;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [cancelling, setCancelling] = useState(false);

  const seenLogSeqs = useRef<Set<number>>(new Set());

  const upsertResult = useCallback((incoming: TestResult) => {
    setResults((prev) => {
      const idx = prev.findIndex((r) => r.id === incoming.id);
      if (idx === -1) return [...prev, incoming];
      const next = [...prev];
      next[idx] = incoming;
      return next;
    });
  }, []);

  const appendLog = useCallback((line: LogLine) => {
    if (seenLogSeqs.current.has(line.seq)) return;
    seenLogSeqs.current.add(line.seq);
    setLogs((prev) => [...prev, line]);
  }, []);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    let stream: StreamHandle | null = null;
    seenLogSeqs.current = new Set();
    setRun(null);
    setResults([]);
    setLogs([]);
    setProgress(null);
    setError(null);

    const start = async () => {
      try {
        // Initial state from REST, then resume the stream from last_seq —
        // this makes reload/reconnect lossless.
        const [runRes, resultsRes, logsRes] = await Promise.all([
          getRun(id),
          getResults(id),
          getLogs(id),
        ]);
        if (cancelled) return;
        setRun(runRes);
        setResults(resultsRes.items);
        for (const line of logsRes.items) seenLogSeqs.current.add(line.seq);
        setLogs(logsRes.items);

        if (isTerminalStatus(runRes.status)) return;

        stream = connectRunStream(id, logsRes.last_seq ?? 0, {
          onStateChange: (state, transport) => {
            if (!cancelled) setConn({ state, transport });
          },
          onEvent: (event) => {
            if (cancelled) return;
            switch (event.type) {
              case 'log':
                appendLog({ seq: event.seq, ...event.data });
                break;
              case 'progress':
                setProgress(event.data);
                break;
              case 'result':
                upsertResult(event.data);
                break;
              case 'run_status':
                setRun((prev) =>
                  prev ? { ...prev, ...event.data } : (event.data as RunDetail),
                );
                break;
            }
          },
        });
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.detail : 'Could not load the run.');
      }
    };
    void start();

    return () => {
      cancelled = true;
      stream?.close();
    };
  }, [id, appendLog, upsertResult]);

  const handleCancel = async () => {
    if (!id) return;
    setCancelling(true);
    setActionError(null);
    try {
      const updated = await cancelRun(id);
      setRun((prev) => (prev ? { ...prev, ...updated } : prev));
    } catch (err) {
      setActionError(err instanceof ApiError ? err.detail : 'Cancel failed.');
    } finally {
      setCancelling(false);
    }
  };

  const handleDelete = async () => {
    if (!id) return;
    setActionError(null);
    try {
      await deleteRun(id);
      navigate('/runs');
    } catch (err) {
      setConfirmDelete(false);
      setActionError(err instanceof ApiError ? err.detail : 'Delete failed.');
    }
  };

  if (!id) return null;

  if (error) {
    return (
      <>
        <div className="page-header">
          <h1 className="page-title">Test run</h1>
        </div>
        <div className="form-error" role="alert">
          <span className="err-status">Error</span>
          {error}
        </div>
        <Link to="/runs" className="btn">
          ← Back to runs
        </Link>
      </>
    );
  }

  if (!run) {
    return <div className="loading">Loading run…</div>;
  }

  const active = run.status === 'queued' || run.status === 'running';

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">{run.name || 'Test run'}</h1>
          <p className="page-subtitle mono">{run.ocsp_url}</p>
        </div>
        <div className="toolbar">
          {conn && active && (
            <span className={`conn-badge ${conn.state}`}>
              {conn.transport} {conn.state}
            </span>
          )}
          <StatusPill status={run.status} />
          {active && (
            <button
              type="button"
              className="btn btn-danger"
              onClick={() => void handleCancel()}
              disabled={cancelling}
            >
              {cancelling ? 'Cancelling…' : 'Cancel run'}
            </button>
          )}
          <a className="btn" href={exportJsonUrl(run.id)} download>
            Export JSON
          </a>
          <a className="btn" href={exportCsvUrl(run.id)} download>
            Export CSV
          </a>
          <button
            type="button"
            className="btn btn-danger"
            onClick={() => setConfirmDelete(true)}
          >
            Delete
          </button>
        </div>
      </div>

      {actionError && (
        <div className="form-error" role="alert">
          <span className="err-status">Error</span>
          {actionError}
        </div>
      )}

      {run.error && (
        <div className="form-error" role="alert">
          <span className="err-status">Run error</span>
          {run.error}
        </div>
      )}

      <div className="panel">
        <RunProgress
          status={run.status}
          progress={progress}
          currentActivity={run.current_activity}
        />
        <div className="toolbar" style={{ marginTop: 12, fontSize: 12 }}>
          <CountChips totals={run.totals} />
          <span className="spacer" />
          <span className="faint">
            created {formatDateTime(run.created_at)}
            {run.started_at ? ` · started ${formatDateTime(run.started_at)}` : ''}
            {run.finished_at ? ` · finished ${formatDateTime(run.finished_at)}` : ''}
            {run.latency
              ? ` · median latency ${formatDurationMs(run.latency.median_ms)}`
              : ''}
          </span>
        </div>
      </div>

      <div className="run-panels" style={{ marginTop: 16 }}>
        <div className="panel">
          <h2 className="section-label">Live log</h2>
          <LogViewer logs={logs} />
        </div>
        <div className="panel">
          <h2 className="section-label">Results ({results.length})</h2>
          <ResultsTable results={results} />
        </div>
      </div>

      {confirmDelete && (
        <ConfirmDialog
          title="Delete this run?"
          confirmLabel="Delete run"
          danger
          onConfirm={() => void handleDelete()}
          onCancel={() => setConfirmDelete(false)}
        >
          This permanently removes the run record, its results, logs, and
          uploaded certificate workspace.
        </ConfirmDialog>
      )}
    </>
  );
}
