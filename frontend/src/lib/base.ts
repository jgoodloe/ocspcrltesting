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

/** Builds a WebSocket URL for the same host, honoring https -> wss. */
export function wsUrl(path: string): string {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${location.host}${getBasePath()}/api${path}`;
}
