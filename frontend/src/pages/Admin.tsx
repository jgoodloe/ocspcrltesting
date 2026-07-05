import { useEffect, useState, type FormEvent } from 'react';
import {
  ApiError,
  createLocalUser,
  getGlobalAudit,
  listUsers,
  setUserActive,
  type AuditEntry,
  type User,
} from '../lib/api';
import { useAuth } from '../lib/auth';

export function Admin() {
  const { me } = useAuth();
  const isGlobalAdmin = me?.user.is_global_admin ?? false;

  if (!isGlobalAdmin) {
    return (
      <div>
        <h1 className="page-title">Administration</h1>
        <p className="err-status">Global admin access is required for this page.</p>
      </div>
    );
  }
  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Administration</h1>
          <p className="page-subtitle">
            Manage local accounts and review the deployment-wide audit log.
            Local accounts are admin-created only — there is no self-registration.
          </p>
        </div>
      </div>
      <UsersPanel />
      <GlobalAuditPanel />
    </div>
  );
}

function UsersPanel() {
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [globalAdmin, setGlobalAdmin] = useState(false);

  const load = () => {
    listUsers()
      .then(setUsers)
      .catch((e) => setError(e instanceof ApiError ? e.detail : String(e)));
  };
  useEffect(load, []);

  const onCreate = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await createLocalUser({
        username,
        password,
        display_name: displayName || null,
        is_global_admin: globalAdmin,
      });
      setUsername('');
      setPassword('');
      setDisplayName('');
      setGlobalAdmin(false);
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : String(err));
    }
  };

  const onToggleActive = async (u: User) => {
    setError(null);
    try {
      await setUserActive(u.id, !u.is_active);
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : String(err));
    }
  };

  return (
    <div className="panel">
      <div className="section-label">Users</div>
      {error && <p className="err-status" role="alert">{error}</p>}
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>User</th>
              <th>Provider</th>
              <th>Global admin</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>
                  {u.display_name || u.subject}
                  {u.email && <span className="muted"> · {u.email}</span>}
                </td>
                <td className="muted">{u.provider}</td>
                <td>{u.is_global_admin ? 'yes' : ''}</td>
                <td className={u.is_active ? '' : 'muted'}>
                  {u.is_active ? 'active' : 'disabled'}
                </td>
                <td className="nowrap">
                  <button
                    className="btn btn-ghost btn-sm"
                    onClick={() => onToggleActive(u)}
                  >
                    {u.is_active ? 'Disable' : 'Enable'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <form onSubmit={onCreate} className="form-grid" style={{ marginTop: '0.75rem' }}>
        <div className="section-label">Create local user</div>
        <div className="field">
          <label className="field-label" htmlFor="u-name">
            Username
          </label>
          <input
            id="u-name"
            className="input"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>
        <div className="field">
          <label className="field-label" htmlFor="u-display">
            Display name
          </label>
          <input
            id="u-display"
            className="input"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="optional"
          />
        </div>
        <div className="field">
          <label className="field-label" htmlFor="u-pw">
            Password (min 8 characters)
          </label>
          <input
            id="u-pw"
            className="input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            minLength={8}
            required
          />
        </div>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={globalAdmin}
            onChange={(e) => setGlobalAdmin(e.target.checked)}
          />
          Grant global admin
        </label>
        <button className="btn btn-primary" type="submit">
          Create user
        </button>
      </form>
    </div>
  );
}

function GlobalAuditPanel() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);

  useEffect(() => {
    getGlobalAudit(200)
      .then((r) => setEntries(r.items))
      .catch(() => setEntries([]));
  }, []);

  return (
    <div className="panel">
      <div className="section-label">Audit log</div>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Event</th>
              <th>Workspace</th>
              <th>Target</th>
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 && (
              <tr>
                <td colSpan={5} className="table-empty">
                  No activity recorded.
                </td>
              </tr>
            )}
            {entries.map((a) => (
              <tr key={a.id}>
                <td className="muted nowrap">{new Date(a.ts).toLocaleString()}</td>
                <td>{a.actor ?? '—'}</td>
                <td className="mono">{a.event}</td>
                <td className="muted">{a.workspace_id ?? ''}</td>
                <td className="muted truncate">{a.target ?? ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
