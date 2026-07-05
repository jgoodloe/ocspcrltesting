import { useEffect, useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { getVersion, type VersionInfo } from './lib/api';
import { useAuth } from './lib/auth';

const ICONS = {
  dashboard: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="3" y="3" width="7" height="9" rx="1" />
      <rect x="14" y="3" width="7" height="5" rx="1" />
      <rect x="14" y="12" width="7" height="9" rx="1" />
      <rect x="3" y="16" width="7" height="5" rx="1" />
    </svg>
  ),
  newRun: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="9" />
      <path d="M12 8v8M8 12h8" />
    </svg>
  ),
  runs: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M8 6h13M8 12h13M8 18h13" />
      <path d="M3 6h.01M3 12h.01M3 18h.01" />
    </svg>
  ),
  profiles: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4z" />
    </svg>
  ),
  caLibrary: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="9" r="6" />
      <path d="M9 14.5L7.5 21l4.5-2.5L16.5 21 15 14.5" />
      <circle cx="12" cy="9" r="2.5" />
    </svg>
  ),
  settings: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1.03 1.56V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1.03-1.56 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.56-1.03H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.56-1.03 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34h.01A1.7 1.7 0 0 0 10 4.09V4a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1.03 1.56h.01a1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87v.01A1.7 1.7 0 0 0 20.91 11H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.51 1z" />
    </svg>
  ),
  shield: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  ),
};

const ICONS_EXTRA = {
  workspaces: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="3" y="4" width="18" height="6" rx="1" />
      <rect x="3" y="14" width="18" height="6" rx="1" />
    </svg>
  ),
  tokens: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="8" cy="15" r="4" />
      <path d="M10.8 12.2 20 3M17 6l2 2M14 9l2 2" />
    </svg>
  ),
  admin: (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21v-1a6 6 0 0 1 12 0v1" />
      <path d="M19 8v6M16 11h6" />
    </svg>
  ),
};

export function App() {
  const [version, setVersion] = useState<VersionInfo | null>(null);
  const {
    config,
    me,
    workspaces,
    activeWorkspace,
    setActiveWorkspace,
    logout,
  } = useAuth();
  const authRequired = config?.auth_required ?? false;
  const isGlobalAdmin = me?.user.is_global_admin ?? false;

  useEffect(() => {
    let cancelled = false;
    getVersion()
      .then((v) => {
        if (!cancelled) setVersion(v);
      })
      .catch(() => {
        /* backend not up yet; footer stays empty */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `nav-link${isActive ? ' active' : ''}`;

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <aside className="sidebar">
        <div className="sidebar-brand">
          {ICONS.shield}
          OCSP Testing
        </div>
        <nav className="sidebar-nav" aria-label="Main">
          <NavLink to="/" end className={linkClass}>
            {ICONS.dashboard}
            Dashboard
          </NavLink>
          <NavLink to="/runs/new" className={linkClass}>
            {ICONS.newRun}
            New run
          </NavLink>
          <NavLink to="/runs" end className={linkClass}>
            {ICONS.runs}
            Runs
          </NavLink>
          <NavLink to="/profiles" className={linkClass}>
            {ICONS.profiles}
            Profiles
          </NavLink>
          <NavLink to="/ca-library" className={linkClass}>
            {ICONS.caLibrary}
            CA Library
          </NavLink>
          <NavLink to="/workspaces" className={linkClass}>
            {ICONS_EXTRA.workspaces}
            Workspaces
          </NavLink>
          <NavLink to="/tokens" className={linkClass}>
            {ICONS_EXTRA.tokens}
            API tokens
          </NavLink>
          {isGlobalAdmin && (
            <NavLink to="/admin" className={linkClass}>
              {ICONS_EXTRA.admin}
              Admin
            </NavLink>
          )}
          <NavLink to="/settings" className={linkClass}>
            {ICONS.settings}
            Settings
          </NavLink>
        </nav>
        {workspaces.length > 0 && (
          <div className="sidebar-workspace">
            <label className="sidebar-ws-label" htmlFor="ws-switch">
              Workspace
            </label>
            <select
              id="ws-switch"
              className="input input-sm"
              value={activeWorkspace?.id ?? ''}
              onChange={(e) => setActiveWorkspace(Number(e.target.value))}
            >
              {workspaces.map((w) => (
                <option key={w.id} value={w.id}>
                  {w.name}
                </option>
              ))}
            </select>
          </div>
        )}
        <div className="sidebar-footer">
          {authRequired && me && (
            <div className="sidebar-user">
              <span className="sidebar-user-name" title={me.user.email ?? me.user.subject}>
                {me.user.display_name || me.user.subject}
              </span>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => {
                  void logout();
                }}
              >
                Sign out
              </button>
            </div>
          )}
          {version ? `${version.name} v${version.version}` : ''}
        </div>
      </aside>
      <main className="content" id="main-content" tabIndex={-1}>
        {/* Remount the routed page when the active workspace changes so each
            page re-fetches its now workspace-scoped data. */}
        <div className="content-inner" key={activeWorkspace?.id ?? 'none'}>
          <Outlet />
        </div>
      </main>
    </div>
  );
}
