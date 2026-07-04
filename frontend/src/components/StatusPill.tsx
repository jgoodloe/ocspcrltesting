import type { ResultStatus, RunStatus } from '../lib/api';
import { statusLabel } from '../lib/format';

/**
 * Each status pairs a distinct icon with its text label so state is never
 * conveyed by color alone (Section 508 / WCAG 1.4.1).
 */
const STATUS_GLYPHS: Record<string, string> = {
  // Result statuses
  PASS: '✓',
  FAIL: '✕',
  WARN: '▲',
  SKIP: '−',
  ERROR: '!',
  // Run statuses
  queued: '○',
  running: '●',
  completed: '✓',
  failed: '✕',
  cancelled: '−',
  timed_out: '!',
};

/** Tinted pill for run statuses (lowercase) and result statuses (UPPERCASE). */
export function StatusPill({ status }: { status: RunStatus | ResultStatus }) {
  return (
    <span className={`pill ${status}`}>
      <span className="pill-icon" aria-hidden="true">
        {STATUS_GLYPHS[status] ?? '•'}
      </span>
      {statusLabel(status)}
    </span>
  );
}
