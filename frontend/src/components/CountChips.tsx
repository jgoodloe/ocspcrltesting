import type { RunTotals } from '../lib/api';

/**
 * Per-status count chips for a run's totals. Zero counts are omitted.
 * Icons + accessible labels ensure meaning without relying on color
 * (Section 508 / WCAG 1.4.1).
 */
export function CountChips({ totals }: { totals: RunTotals }) {
  const entries: Array<{
    key: keyof RunTotals;
    cls: string;
    glyph: string;
    word: string;
  }> = [
    { key: 'pass', cls: 'pass', glyph: '✓', word: 'passed' },
    { key: 'fail', cls: 'fail', glyph: '✕', word: 'failed' },
    { key: 'warn', cls: 'warn', glyph: '▲', word: 'warnings' },
    { key: 'skip', cls: 'skip', glyph: '−', word: 'skipped' },
    { key: 'error', cls: 'error', glyph: '!', word: 'errors' },
  ];
  const visible = entries.filter((e) => (totals?.[e.key] ?? 0) > 0);
  if (visible.length === 0) {
    return <span className="faint">—</span>;
  }
  return (
    <span className="count-chips">
      {visible.map((e) => (
        <span
          key={e.key}
          className={`count-chip ${e.cls}`}
          title={`${totals[e.key]} ${e.word}`}
          aria-label={`${totals[e.key]} ${e.word}`}
        >
          <span aria-hidden="true">
            {e.glyph} {totals[e.key]}
          </span>
        </span>
      ))}
    </span>
  );
}
