import type { ProgressData, RunStatus } from '../lib/api';
import { isTerminalStatus } from '../lib/api';

export function RunProgress({
  status,
  progress,
  currentActivity,
}: {
  status: RunStatus;
  progress: ProgressData | null;
  currentActivity: string | null;
}) {
  const terminal = isTerminalStatus(status);
  const percent = terminal
    ? 100
    : Math.max(0, Math.min(100, progress?.percent ?? (status === 'running' ? 2 : 0)));
  const barClass =
    status === 'completed'
      ? 'progress-inner done'
      : status === 'failed' || status === 'timed_out'
        ? 'progress-inner bad'
        : 'progress-inner';
  const activity = terminal ? null : (progress?.current_activity ?? currentActivity);

  return (
    <div>
      <div
        className="progress-outer"
        role="progressbar"
        aria-label="Run progress"
        aria-valuenow={Math.round(percent)}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div className={barClass} style={{ width: `${percent}%` }} />
      </div>
      <div className="current-activity" aria-live="polite">
        {activity ? (
          <>
            <span>{activity}</span>
            {progress && progress.categories_total > 0 && (
              <span className="faint">
                ({progress.categories_done}/{progress.categories_total} categories)
              </span>
            )}
          </>
        ) : (
          <span className="faint">
            {terminal ? `Run ${status.replace('_', ' ')}` : 'Waiting for activity…'}
          </span>
        )}
      </div>
    </div>
  );
}
