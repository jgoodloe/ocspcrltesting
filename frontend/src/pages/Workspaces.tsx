import { useCallback, useEffect, useState, type FormEvent } from 'react';
import {
  ApiError,
  addMember,
  changeMemberRole,
  createWorkspace,
  getWorkspaceAudit,
  listMembers,
  removeMember,
  updateWorkspace,
  type AuditEntry,
  type Member,
  type Role,
  type RunVisibility,
} from '../lib/api';
import { useAuth } from '../lib/auth';

const ROLES: Role[] = ['viewer', 'member', 'admin'];

export function Workspaces() {
  const { workspaces, activeWorkspace, setActiveWorkspace, refresh, me } = useAuth();
  const isGlobalAdmin = me?.user.is_global_admin ?? false;
  const canAdmin = activeWorkspace?.role === 'admin' || isGlobalAdmin;

  const [error, setError] = useState<string | null>(null);
  const [newName, setNewName] = useState('');

  const onCreate = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const ws = await createWorkspace(newName);
      setNewName('');
      await refresh();
      setActiveWorkspace(ws.id);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : String(err));
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Workspaces</h1>
          <p className="page-subtitle">
            Runs, profiles and saved certificates belong to a workspace. Members
            have a role: viewers read, members run tests, admins manage the
            workspace and its members.
          </p>
        </div>
      </div>

      {error && <p className="err-status" role="alert">{error}</p>}

      <div className="panel">
        <div className="section-label">Your workspaces</div>
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Your role</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {workspaces.map((w) => (
                <tr key={w.id}>
                  <td>{w.name}</td>
                  <td className="muted">{w.kind}</td>
                  <td>{w.role ?? '—'}</td>
                  <td className="nowrap">
                    {activeWorkspace?.id === w.id ? (
                      <span className="muted">active</span>
                    ) : (
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => setActiveWorkspace(w.id)}
                      >
                        Switch to
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <form onSubmit={onCreate} className="toolbar" style={{ marginTop: '0.75rem' }}>
          <input
            className="input"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="New workspace name"
            required
          />
          <button className="btn btn-primary btn-sm" type="submit">
            Create workspace
          </button>
        </form>
      </div>

      {activeWorkspace && (
        <WorkspaceSettings
          key={activeWorkspace.id}
          canAdmin={canAdmin}
        />
      )}
    </div>
  );
}

function WorkspaceSettings({ canAdmin }: { canAdmin: boolean }) {
  const { activeWorkspace, refresh } = useAuth();
  const ws = activeWorkspace!;

  const [name, setName] = useState(ws.name);
  const [visibility, setVisibility] = useState<RunVisibility>(ws.run_visibility);
  const [allowPrivate, setAllowPrivate] = useState(ws.allow_private_targets);
  const [maxRuns, setMaxRuns] = useState(ws.max_concurrent_runs);
  const [oidcGroup, setOidcGroup] = useState(ws.oidc_group ?? '');
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSave = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSaved(false);
    try {
      await updateWorkspace(ws.id, {
        name,
        run_visibility: visibility,
        allow_private_targets: allowPrivate,
        max_concurrent_runs: maxRuns,
        oidc_group: oidcGroup || null,
      });
      setSaved(true);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : String(err));
    }
  };

  return (
    <>
      <div className="panel">
        <div className="section-label">Settings — {ws.name}</div>
        {!canAdmin && (
          <p className="muted">You need the admin role to change these settings.</p>
        )}
        <form onSubmit={onSave} className="form-grid">
          <div className="field">
            <label className="field-label" htmlFor="ws-name">
              Name
            </label>
            <input
              id="ws-name"
              className="input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={!canAdmin}
            />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="ws-vis">
              Run visibility
            </label>
            <select
              id="ws-vis"
              className="input"
              value={visibility}
              onChange={(e) => setVisibility(e.target.value as RunVisibility)}
              disabled={!canAdmin}
            >
              <option value="all">All members see all runs</option>
              <option value="own">Members see only their own runs</option>
            </select>
          </div>
          <div className="field">
            <label className="field-label" htmlFor="ws-max">
              Max concurrent runs
            </label>
            <input
              id="ws-max"
              className="input"
              type="number"
              min={1}
              max={64}
              value={maxRuns}
              onChange={(e) => setMaxRuns(Number(e.target.value))}
              disabled={!canAdmin}
            />
            <p className="field-hint">Capped by the deployment ceiling.</p>
          </div>
          <div className="field">
            <label className="field-label" htmlFor="ws-group">
              OIDC group (auto-membership)
            </label>
            <input
              id="ws-group"
              className="input"
              value={oidcGroup}
              onChange={(e) => setOidcGroup(e.target.value)}
              placeholder="optional"
              disabled={!canAdmin}
            />
          </div>
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={allowPrivate}
              onChange={(e) => setAllowPrivate(e.target.checked)}
              disabled={!canAdmin}
            />
            Allow private/loopback OCSP &amp; CRL targets (if the deployment permits)
          </label>
          {error && <p className="form-error" role="alert">{error}</p>}
          {saved && <p className="muted">Saved.</p>}
          {canAdmin && (
            <button className="btn btn-primary" type="submit">
              Save settings
            </button>
          )}
        </form>
      </div>

      <MembersPanel canAdmin={canAdmin} />
      {canAdmin && <AuditPanel />}
    </>
  );
}

function MembersPanel({ canAdmin }: { canAdmin: boolean }) {
  const { activeWorkspace } = useAuth();
  const ws = activeWorkspace!;
  const [members, setMembers] = useState<Member[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<Role>('member');

  const load = useCallback(() => {
    listMembers(ws.id)
      .then((r) => setMembers(r.items))
      .catch((e) => setError(e instanceof ApiError ? e.detail : String(e)));
  }, [ws.id]);

  useEffect(load, [load]);

  const onAdd = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await addMember(ws.id, { email, role });
      setEmail('');
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : String(err));
    }
  };

  const onRole = async (userId: number, r: Role) => {
    setError(null);
    try {
      await changeMemberRole(ws.id, userId, r);
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : String(err));
    }
  };

  const onRemove = async (userId: number) => {
    setError(null);
    try {
      await removeMember(ws.id, userId);
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : String(err));
    }
  };

  return (
    <div className="panel">
      <div className="section-label">Members</div>
      {error && <p className="err-status" role="alert">{error}</p>}
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>User</th>
              <th>Provider</th>
              <th>Role</th>
              {canAdmin && <th />}
            </tr>
          </thead>
          <tbody>
            {members.length === 0 && (
              <tr>
                <td colSpan={canAdmin ? 4 : 3} className="table-empty">
                  No members.
                </td>
              </tr>
            )}
            {members.map((m) => (
              <tr key={m.user_id}>
                <td>{m.display_name || m.email || `#${m.user_id}`}</td>
                <td className="muted">{m.provider}</td>
                <td>
                  {canAdmin ? (
                    <select
                      className="input input-inline"
                      value={m.role}
                      onChange={(e) => onRole(m.user_id, e.target.value as Role)}
                    >
                      {ROLES.map((r) => (
                        <option key={r} value={r}>
                          {r}
                        </option>
                      ))}
                    </select>
                  ) : (
                    m.role
                  )}
                </td>
                {canAdmin && (
                  <td className="nowrap">
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() => onRemove(m.user_id)}
                    >
                      Remove
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {canAdmin && (
        <form onSubmit={onAdd} className="toolbar" style={{ marginTop: '0.75rem' }}>
          <input
            className="input"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="User email (must have logged in once)"
            type="email"
            required
          />
          <select
            className="input"
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <button className="btn btn-primary btn-sm" type="submit">
            Add member
          </button>
        </form>
      )}
    </div>
  );
}

function AuditPanel() {
  const { activeWorkspace } = useAuth();
  const ws = activeWorkspace!;
  const [entries, setEntries] = useState<AuditEntry[]>([]);

  useEffect(() => {
    getWorkspaceAudit(ws.id, 50)
      .then((r) => setEntries(r.items))
      .catch(() => setEntries([]));
  }, [ws.id]);

  return (
    <div className="panel">
      <div className="section-label">Recent activity</div>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Event</th>
              <th>Target</th>
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 && (
              <tr>
                <td colSpan={4} className="table-empty">
                  No activity recorded.
                </td>
              </tr>
            )}
            {entries.map((a) => (
              <tr key={a.id}>
                <td className="muted nowrap">{new Date(a.ts).toLocaleString()}</td>
                <td>{a.actor ?? '—'}</td>
                <td className="mono">{a.event}</td>
                <td className="muted truncate">{a.target ?? ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
