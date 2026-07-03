import type { ReactNode } from 'react';

export function StatCard({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  tone?: 'pass' | 'fail' | 'warn' | 'error' | 'accent';
}) {
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className={`stat-value${tone ? ` tone-${tone}` : ''}`}>{value}</div>
      {sub !== undefined && <div className="stat-sub">{sub}</div>}
    </div>
  );
}
