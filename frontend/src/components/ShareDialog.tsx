import { useEffect, useMemo, useState } from 'react';
import { useAuth } from '../lib/auth';

/**
 * Pick a target workspace to copy a profile or saved certificate into.
 *
 * Only workspaces where the current user is a member or admin (never a viewer)
 * and that are not the current source workspace are offered — mirroring the
 * server-side check, which is authoritative.
 */
export function ShareDialog({
  title,
  itemName,
  sourceWorkspaceId,
  busy,
  onShare,
  onClose,
}: {
  title: string;
  itemName: string;
  sourceWorkspaceId: number | null;
  busy: boolean;
  onShare: (targetWorkspaceId: number) => void;
  onClose: () => void;
}) {
  const { workspaces } = useAuth();

  const targets = useMemo(
    () =>
      workspaces.filter(
        (w) =>
          w.id !== sourceWorkspaceId &&
          (w.role === 'member' || w.role === 'admin'),
      ),
    [workspaces, sourceWorkspaceId],
  );

  const [targetId, setTargetId] = useState<number | null>(targets[0]?.id ?? null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="dialog-backdrop" onMouseDown={onClose}>
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <h3>{title}</h3>
        {targets.length === 0 ? (
          <p className="muted">
            You don’t have any other workspace where you are a member or admin.
            Sharing copies into workspaces where you can contribute — viewer
            access is not enough.
          </p>
        ) : (
          <>
            <p className="muted" style={{ marginTop: 0 }}>
              Copy <strong>{itemName}</strong> into another workspace. The copy
              is independent of the original.
            </p>
            <div className="field">
              <label className="field-label" htmlFor="share-target">
                Target workspace
              </label>
              <select
                id="share-target"
                className="select"
                value={targetId ?? ''}
                onChange={(e) => setTargetId(Number(e.target.value))}
              >
                {targets.map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.name} ({w.role})
                  </option>
                ))}
              </select>
            </div>
          </>
        )}
        <div className="dialog-actions">
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy || targetId === null || targets.length === 0}
            onClick={() => {
              if (targetId !== null) onShare(targetId);
            }}
          >
            {busy ? 'Sharing…' : 'Share'}
          </button>
        </div>
      </div>
    </div>
  );
}
