import { useEffect, useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { getVersion, type VersionInfo } from './lib/api';

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
  shield: (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  ),
};

export function App() {
  const [version, setVersion] = useState<VersionInfo | null>(null);

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
        </nav>
        <div className="sidebar-footer">
          {version ? `${version.name} v${version.version}` : ''}
        </div>
      </aside>
      <main className="content">
        <div className="content-inner">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
