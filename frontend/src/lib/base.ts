/**
 * Base-path helpers. The app is reverse-proxy/subpath safe: the backend
 * rewrites `<base href="/">` in index.html at serve time (e.g. to
 * `<base href="/ocsp/">`), and everything here derives from that tag.
 * No URLs are hardcoded anywhere in the app.
 */

/**
 * Returns the deploy base path derived from `document.baseURI`, without a
 * trailing slash. Empty string when deployed at the root.
 */
export function getBasePath(): string {
  const pathname = new URL(document.baseURI).pathname;
  const trimmed = pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
  return trimmed;
}

/** Builds an HTTP API URL, e.g. apiUrl('/health') -> `${base}/api/health`. */
export function apiUrl(path: string): string {
  return `${getBasePath()}/api${path}`;
}

// ---------------------------------------------------------------------------
// Active workspace: workspace-scoped API calls carry a `workspace_id` query
// parameter for the currently selected workspace. When unset the backend
// falls back to the caller's personal/default workspace (single-user use).
// ---------------------------------------------------------------------------

let activeWorkspaceId: number | null = null;

export function setActiveWorkspaceId(id: number | null): void {
  activeWorkspaceId = id;
}

export function getActiveWorkspaceId(): number | null {
  return activeWorkspaceId;
}

const SCOPED_PREFIXES = ['/test-runs', '/profiles', '/ca-certs'];

/** Append the active workspace id to a workspace-scoped API path. */
export function withWorkspace(path: string): string {
  if (activeWorkspaceId == null) return path;
  const base = path.split('?')[0];
  const scoped = SCOPED_PREFIXES.some(
    (p) => base === p || base.startsWith(`${p}/`),
  );
  // `/ca-certs/well-known` is global; the extra param is harmless but omit it.
  if (!scoped) return path;
  const sep = path.includes('?') ? '&' : '?';
  return `${path}${sep}workspace_id=${activeWorkspaceId}`;
}

/** Builds a WebSocket URL for the same host, honoring https -> wss. */
export function wsUrl(path: string): string {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${location.host}${getBasePath()}/api${path}`;
}
