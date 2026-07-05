import { useEffect, useState, type FormEvent } from 'react';
import {
  ApiError,
  createToken,
  listTokens,
  revokeToken,
  type ApiToken,
  type Role,
} from '../lib/api';
import { useAuth } from '../lib/auth';

export function Tokens() {
  const { workspaces } = useAuth();
  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [name, setName] = useState('');
  const [workspaceId, setWorkspaceId] = useState<string>('');
  const [roleCeiling, setRoleCeiling] = useState<Role>('viewer');
  const [created, setCreated] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    listTokens()
      .then((r) => setTokens(r.items))
      .catch((e) => setError(e instanceof ApiError ? e.detail : String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const onCreate = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const t = await createToken({
        name,
        workspace_id: workspaceId ? Number(workspaceId) : null,
        role_ceiling: roleCeiling,
      });
      setCreated(t.token);
      setName('');
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : String(err));
    }
  };

  const onRevoke = async (id: number) => {
    setError(null);
    try {
      await revokeToken(id);
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : String(err));
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">API tokens</h1>
          <p className="page-subtitle">
            Personal tokens for scripted access. Send as{' '}
            <code>Authorization: Bearer &lt;token&gt;</code>. A token can never
            exceed its role ceiling, and can be scoped to a single workspace.
          </p>
        </div>
      </div>

      {error && <p className="err-status" role="alert">{error}</p>}

      {created && (
        <div className="panel notice-ok">
          <strong>New token — copy it now, it will not be shown again:</strong>
          <pre className="mono token-reveal">{created}</pre>
          <button className="btn btn-sm" onClick={() => setCreated(null)}>
            Dismiss
          </button>
        </div>
      )}

      <div className="panel">
        <form onSubmit={onCreate} className="form-grid">
          <div className="field">
            <label className="field-label" htmlFor="tok-name">
              Name
            </label>
            <input
              id="tok-name"
              className="input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. CI pipeline"
              required
            />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="tok-ws">
              Workspace scope
            </label>
            <select
              id="tok-ws"
              className="input"
              value={workspaceId}
              onChange={(e) => setWorkspaceId(e.target.value)}
            >
              <option value="">All my workspaces</option>
              {workspaces.map((w) => (
                <option key={w.id} value={w.id}>
                  {w.name}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label className="field-label" htmlFor="tok-role">
              Role ceiling
            </label>
            <select
              id="tok-role"
              className="input"
              value={roleCeiling}
              onChange={(e) => setRoleCeiling(e.target.value as Role)}
            >
              <option value="viewer">viewer</option>
              <option value="member">member</option>
              <option value="admin">admin</option>
            </select>
          </div>
          <button className="btn btn-primary" type="submit">
            Create token
          </button>
        </form>
      </div>

      <div className="panel">
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>Name</th>
                <th>Scope</th>
                <th>Ceiling</th>
                <th>Last used</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={5} className="loading">
                    Loading…
                  </td>
                </tr>
              )}
              {!loading && tokens.length === 0 && (
                <tr>
                  <td colSpan={5} className="table-empty">
                    No active tokens.
                  </td>
                </tr>
              )}
              {tokens.map((t) => (
                <tr key={t.id}>
                  <td>{t.name}</td>
                  <td className="muted">
                    {t.workspace_id
                      ? workspaces.find((w) => w.id === t.workspace_id)?.name ??
                        `#${t.workspace_id}`
                      : 'All workspaces'}
                  </td>
                  <td>{t.role_ceiling}</td>
                  <td className="muted nowrap">
                    {t.last_used_at
                      ? new Date(t.last_used_at).toLocaleString()
                      : 'never'}
                  </td>
                  <td className="nowrap">
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() => onRevoke(t.id)}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
