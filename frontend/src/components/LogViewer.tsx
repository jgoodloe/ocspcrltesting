import { useEffect, useMemo, useRef, useState } from 'react';
import type { LogLine } from '../lib/api';

function formatLogTs(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleTimeString(undefined, { hour12: false });
}

/**
 * Monospace live log viewer: level-colored prefixes, free-text filter, and
 * auto-scroll with a "follow" toggle that disengages when the user scrolls up.
 */
export function LogViewer({ logs }: { logs: LogLine[] }) {
  const [follow, setFollow] = useState(true);
  const [verbose, setVerbose] = useState(false);
  const [query, setQuery] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);

  const debugCount = useMemo(
    () => logs.reduce((n, l) => (l.level.toUpperCase() === 'DEBUG' ? n + 1 : n), 0),
    [logs],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    let rows = logs;
    if (!verbose) rows = rows.filter((l) => l.level.toUpperCase() !== 'DEBUG');
    if (!q) return rows;
    return rows.filter(
      (l) =>
        l.message.toLowerCase().includes(q) || l.level.toLowerCase().includes(q),
    );
  }, [logs, query, verbose]);

  useEffect(() => {
    if (follow && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [filtered, follow]);

  const onScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
    if (!atBottom && follow) setFollow(false);
  };

  return (
    <div className="log-viewer">
      <div className="log-toolbar">
        <input
          className="input"
          type="search"
          placeholder="Filter log lines…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filter log lines"
        />
        <label className="checkbox-row nowrap">
          <input
            type="checkbox"
            checked={verbose}
            onChange={(e) => setVerbose(e.target.checked)}
          />
          Verbose{debugCount > 0 ? ` (${debugCount})` : ''}
        </label>
        <label className="checkbox-row nowrap">
          <input
            type="checkbox"
            checked={follow}
            onChange={(e) => setFollow(e.target.checked)}
          />
          Follow
        </label>
      </div>
      <div className="log-scroll" ref={scrollRef} onScroll={onScroll}>
        {filtered.length === 0 ? (
          <div className="faint">{logs.length === 0 ? 'No log output yet.' : 'No lines match the filter.'}</div>
        ) : (
          filtered.map((line) => (
            <div key={line.seq} className="log-line">
              <span className="log-ts">{formatLogTs(line.ts)}</span>
              <span className={`log-level ${line.level.toUpperCase()}`}>
                {line.level.toUpperCase().padEnd(5)}
              </span>
              <span>{line.message}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
