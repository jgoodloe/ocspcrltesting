import type { ResultStatus, RunStatus } from '../lib/api';
import { statusLabel } from '../lib/format';

/** Tinted pill for run statuses (lowercase) and result statuses (UPPERCASE). */
export function StatusPill({ status }: { status: RunStatus | ResultStatus }) {
  return (
    <span className={`pill ${status}`}>
      <span className="pill-dot" aria-hidden="true" />
      {statusLabel(status)}
    </span>
  );
}
