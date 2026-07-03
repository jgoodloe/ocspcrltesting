import type { RunTotals } from '../lib/api';

/** Colored per-status count chips for a run's totals. Zero counts are dimmed out. */
export function CountChips({ totals }: { totals: RunTotals }) {
  const entries: Array<{ key: keyof RunTotals; cls: string; label: string }> = [
    { key: 'pass', cls: 'pass', label: 'P' },
    { key: 'fail', cls: 'fail', label: 'F' },
    { key: 'warn', cls: 'warn', label: 'W' },
    { key: 'skip', cls: 'skip', label: 'S' },
    { key: 'error', cls: 'error', label: 'E' },
  ];
  const visible = entries.filter((e) => (totals?.[e.key] ?? 0) > 0);
  if (visible.length === 0) {
    return <span className="faint">—</span>;
  }
  return (
    <span className="count-chips">
      {visible.map((e) => (
        <span key={e.key} className={`count-chip ${e.cls}`} title={e.key}>
          {e.label} {totals[e.key]}
        </span>
      ))}
    </span>
  );
}
