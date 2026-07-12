import { useState, type FormEvent } from 'react';
import { ApiError } from '../lib/api';
import { useAuth } from '../lib/auth';

export function Login() {
  const { config, login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const localEnabled = config?.local_login_enabled ?? true;
  const oidcUrl = config?.oidc_enabled ? config.oidc_login_url : null;

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(username, password);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : 'Login failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-shell">
      <div className="login-card panel">
        <div className="login-brand">
          <svg
            width="28"
            height="28"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
          <span>OCSP CRL Testing</span>
        </div>
        <h1 className="page-title">Sign in</h1>

        {oidcUrl && (
          <>
            <a className="btn btn-primary btn-block" href={oidcUrl}>
              Continue with single sign-on
            </a>
            {localEnabled && <div className="login-divider">or</div>}
          </>
        )}

        {localEnabled && (
          <form onSubmit={onSubmit} className="form-grid">
            <div className="field">
              <label className="field-label" htmlFor="login-username">
                Username
              </label>
              <input
                id="login-username"
                className="input"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                autoFocus
              />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="login-password">
                Password
              </label>
              <input
                id="login-password"
                className="input"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            {error && (
              <p className="form-error" role="alert">
                {error}
              </p>
            )}
            <button className="btn btn-primary btn-block" type="submit" disabled={busy}>
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
        )}

        {!localEnabled && !oidcUrl && (
          <p className="muted">No login methods are configured.</p>
        )}
      </div>
    </div>
  );
}
