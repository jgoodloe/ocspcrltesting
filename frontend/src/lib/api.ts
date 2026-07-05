/**
 * Typed API client mirroring docs/API.md exactly.
 * All requests go through apiUrl() so the app is subpath safe.
 */
import { apiUrl, getActiveWorkspaceId, withWorkspace } from './base';

/** Fired when any API call returns 401 so the auth layer can react (log out). */
export const AUTH_UNAUTHORIZED_EVENT = 'ocspweb:unauthorized';

// ---------------------------------------------------------------------------
// Types (mirror API.md)
// ---------------------------------------------------------------------------

export type RunStatus =
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'timed_out';

export type ResultStatus = 'PASS' | 'FAIL' | 'WARN' | 'SKIP' | 'ERROR';

export type RequestMethod = 'auto' | 'get' | 'post';

export type TrustAnchorType = 'root' | 'intermediate';

export interface CategoryFlags {
  protocol: boolean;
  status: boolean;
  crl: boolean;
  path_validation: boolean;
  ikev2: boolean;
  federal: boolean;
  performance: boolean;
  security: boolean;
}

export type TestSelectionMode = 'all' | 'global' | 'custom';

/**
 * Fine-grained choice of which individual tests run.
 * `tests` maps a category key to the selected test names; a category absent
 * from the map runs all of its tests.
 */
export interface TestSelection {
  mode: TestSelectionMode;
  tests: Record<string, string[]>;
}

export interface RunConfig {
  name?: string | null;
  ocsp_url: string;
  crl_urls: string[];
  request_method: RequestMethod;
  nonce_enabled: boolean;
  nonce_length: number; // 1..128, default 32 (RFC 9654)
  latency_samples: number; // 1..100
  enable_load_test: boolean;
  load_concurrency: number; // 1..64
  load_requests: number; // 1..2000
  timeout_seconds: number; // per-request, 1..120
  run_timeout_seconds: number; // whole run, 30..7200
  max_age_hours: number;
  trust_anchor_type: TrustAnchorType;
  require_explicit_policy: boolean;
  inhibit_policy_mapping: boolean;
  categories: CategoryFlags;
  test_selection: TestSelection;
  /** Saved CA library references: {upload slot -> CACertificate id}. */
  saved_certs: Record<string, number>;
  profile_id?: number | null;
}

/** Slots that may be filled from the saved CA library instead of an upload. */
export const SAVED_CERT_SLOTS = [
  'issuer_cert',
  'good_cert',
  'revoked_cert',
  'unknown_ca_cert',
  'trust_anchor',
] as const;

export type SavedCertSlot = (typeof SAVED_CERT_SLOTS)[number];

export interface CatalogTest {
  name: string;
  description: string;
  /** Name is a stable prefix; the run may emit one result per input (e.g. per CRL URL). */
  dynamic: boolean;
  /** What the test exercises: 'ocsp' | 'crl' | 'crl+ocsp' | 'path' | 'ikev2'. */
  scope: string;
}

export interface CACert {
  id: number;
  name: string;
  subject: string;
  issuer: string;
  serial_number: string;
  fingerprint_sha256: string;
  not_before: string;
  not_after: string;
  is_ca: boolean;
  expired: boolean;
  self_signed: boolean;
  source: string;
  source_url: string | null;
  created_at: string;
}

export interface CACertImportResult {
  created: CACert[];
  skipped_duplicates: number;
}

export interface WellKnownCA {
  key: string;
  name: string;
  url: string;
  description: string;
}

export interface CatalogCategory {
  key: string;
  label: string;
  tests: CatalogTest[];
}

export interface TestCatalog {
  categories: CatalogCategory[];
}

/** Server-wide default selection; `tests = null` means run everything. */
export interface GlobalTestSelection {
  tests: Record<string, string[]> | null;
  updated_at: string | null;
}

export interface RunTotals {
  pass: number;
  fail: number;
  warn: number;
  skip: number;
  error: number;
  total: number;
}

export interface RunLatency {
  median_ms: number;
  min_ms: number;
  max_ms: number;
  samples: number;
}

export interface RunSummary {
  id: string;
  name: string | null;
  ocsp_url: string;
  status: RunStatus;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  totals: RunTotals;
  latency: RunLatency | null;
  categories: string[];
  current_activity: string | null;
  error: string | null;
}

/** GET /api/test-runs/{id}: RunSummary plus the sanitized config. */
export interface RunDetail extends RunSummary {
  config: RunConfig & Record<string, unknown>;
}

export interface TestResult {
  id: string;
  category: string;
  name: string;
  status: ResultStatus;
  message: string;
  details: Record<string, unknown> | null;
  started_at: string | null;
  ended_at: string | null;
  duration_ms: number | null;
}

export interface LogLine {
  seq: number;
  ts: string;
  level: string;
  message: string;
}

export interface Profile {
  id: number;
  name: string;
  description: string | null;
  config: RunConfig;
  created_at: string;
  updated_at: string;
}

export interface CertMetadata {
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  key_algorithm: string;
  signature_algorithm: string;
  signature_algorithm_oid: string;
  ski: string | null;
  aki: string | null;
  aia_ocsp_urls: string[];
  aia_ca_issuers: string[];
  crl_distribution_points: string[];
  is_ca: boolean;
  expired: boolean;
  self_signed: boolean;
}

export interface HealthInfo {
  status: string;
  database: string;
  openssl: string;
  time: string;
}

export interface VersionInfo {
  name: string;
  version: string;
  engine: string;
}

export interface ProgressData {
  current_activity: string;
  categories_done: number;
  categories_total: number;
  percent: number;
}

export type StreamEvent =
  | { seq: number; type: 'log'; run_id: string; data: Omit<LogLine, 'seq'> }
  | { seq: number; type: 'progress'; run_id: string; data: ProgressData }
  | { seq: number; type: 'result'; run_id: string; data: TestResult }
  | { seq: number; type: 'run_status'; run_id: string; data: RunSummary };

export interface RunListResponse {
  items: RunSummary[];
  total: number;
}

export interface ResultsResponse {
  items: TestResult[];
  total: number;
}

export interface LogsResponse {
  items: LogLine[];
  last_seq: number;
}

export interface ProfileListResponse {
  items: Profile[];
}

/** Named optional certificate/key uploads for POST /api/test-runs.
 * issuer_cert may be omitted when config.saved_certs provides it. */
export interface RunFiles {
  issuer_cert?: File | null;
  good_cert?: File | null;
  revoked_cert?: File | null;
  unknown_ca_cert?: File | null;
  trust_anchor?: File | null;
  client_cert?: File | null;
  client_key?: File | null;
}

export const TERMINAL_STATUSES: ReadonlyArray<RunStatus> = [
  'completed',
  'failed',
  'cancelled',
  'timed_out',
];

export function isTerminalStatus(status: RunStatus): boolean {
  return TERMINAL_STATUSES.includes(status);
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

export class ApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

async function extractDetail(res: Response): Promise<string> {
  try {
    const body: unknown = await res.json();
    if (body && typeof body === 'object' && 'detail' in body) {
      const detail = (body as { detail: unknown }).detail;
      if (typeof detail === 'string') return detail;
      // FastAPI 422 validation structure: detail is a list of error objects.
      if (Array.isArray(detail)) {
        return detail
          .map((d: unknown) => {
            if (d && typeof d === 'object' && 'msg' in d) {
              const item = d as { msg?: unknown; loc?: unknown };
              const loc = Array.isArray(item.loc) ? item.loc.join('.') : '';
              return loc ? `${loc}: ${String(item.msg)}` : String(item.msg);
            }
            return JSON.stringify(d);
          })
          .join('; ');
      }
    }
  } catch {
    // Non-JSON error body; fall through.
  }
  return `${res.status} ${res.statusText}`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(apiUrl(withWorkspace(path)), init);
  if (!res.ok) {
    if (res.status === 401 && typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent(AUTH_UNAUTHORIZED_EVENT));
    }
    throw new ApiError(res.status, await extractDetail(res));
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

function jsonInit(method: string, body: unknown): RequestInit {
  return {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  };
}

// ---------------------------------------------------------------------------
// Health and metadata
// ---------------------------------------------------------------------------

export function getHealth(): Promise<HealthInfo> {
  return request<HealthInfo>('/health');
}

export function getVersion(): Promise<VersionInfo> {
  return request<VersionInfo>('/version');
}

// ---------------------------------------------------------------------------
// Certificate inspection
// ---------------------------------------------------------------------------

export function inspectCertificate(file: File): Promise<CertMetadata> {
  const form = new FormData();
  form.append('file', file, file.name);
  return request<CertMetadata>('/certificates/inspect', {
    method: 'POST',
    body: form,
  });
}

// ---------------------------------------------------------------------------
// Test runs
// ---------------------------------------------------------------------------

export function createRun(config: RunConfig, files: RunFiles): Promise<RunSummary> {
  const form = new FormData();
  form.append('config', JSON.stringify(config));
  const optional: Array<[string, File | null | undefined]> = [
    ['issuer_cert', files.issuer_cert],
    ['good_cert', files.good_cert],
    ['revoked_cert', files.revoked_cert],
    ['unknown_ca_cert', files.unknown_ca_cert],
    ['trust_anchor', files.trust_anchor],
    ['client_cert', files.client_cert],
    ['client_key', files.client_key],
  ];
  for (const [field, file] of optional) {
    if (file) form.append(field, file, file.name);
  }
  return request<RunSummary>('/test-runs', { method: 'POST', body: form });
}

export interface ListRunsParams {
  limit?: number;
  offset?: number;
  status?: RunStatus | '';
}

export function listRuns(params: ListRunsParams = {}): Promise<RunListResponse> {
  const qs = new URLSearchParams();
  if (params.limit !== undefined) qs.set('limit', String(params.limit));
  if (params.offset !== undefined) qs.set('offset', String(params.offset));
  if (params.status) qs.set('status', params.status);
  const suffix = qs.toString() ? `?${qs.toString()}` : '';
  return request<RunListResponse>(`/test-runs${suffix}`);
}

export function getRun(runId: string): Promise<RunDetail> {
  return request<RunDetail>(`/test-runs/${encodeURIComponent(runId)}`);
}

export interface ResultsFilter {
  category?: string;
  /** Comma-separated list of statuses, e.g. "FAIL,ERROR". */
  status?: string;
  q?: string;
}

export function getResults(
  runId: string,
  filter: ResultsFilter = {},
): Promise<ResultsResponse> {
  const qs = new URLSearchParams();
  if (filter.category) qs.set('category', filter.category);
  if (filter.status) qs.set('status', filter.status);
  if (filter.q) qs.set('q', filter.q);
  const suffix = qs.toString() ? `?${qs.toString()}` : '';
  return request<ResultsResponse>(
    `/test-runs/${encodeURIComponent(runId)}/results${suffix}`,
  );
}

export function getLogs(
  runId: string,
  afterSeq = 0,
  limit = 1000,
): Promise<LogsResponse> {
  return request<LogsResponse>(
    `/test-runs/${encodeURIComponent(runId)}/logs?after_seq=${afterSeq}&limit=${limit}`,
  );
}

export function exportJsonUrl(runId: string): string {
  return apiUrl(withWorkspace(`/test-runs/${encodeURIComponent(runId)}/export/json`));
}

export function exportCsvUrl(runId: string): string {
  return apiUrl(withWorkspace(`/test-runs/${encodeURIComponent(runId)}/export/csv`));
}

export function cancelRun(runId: string): Promise<RunSummary> {
  return request<RunSummary>(`/test-runs/${encodeURIComponent(runId)}/cancel`, {
    method: 'POST',
  });
}

/** Start a new run reusing this run's config and certificates. */
export function rerunRun(runId: string): Promise<RunSummary> {
  return request<RunSummary>(`/test-runs/${encodeURIComponent(runId)}/rerun`, {
    method: 'POST',
  });
}

export function deleteRun(runId: string): Promise<void> {
  return request<void>(`/test-runs/${encodeURIComponent(runId)}`, {
    method: 'DELETE',
  });
}

/** Save an existing run's configuration as a reusable profile. */
export function saveRunAsProfile(
  runId: string,
  input: { name: string; description?: string | null },
): Promise<Profile> {
  return request<Profile>(
    `/test-runs/${encodeURIComponent(runId)}/profile`,
    jsonInit('POST', input),
  );
}

// ---------------------------------------------------------------------------
// Saved CA certificate library
// ---------------------------------------------------------------------------

export function listCACerts(): Promise<{ items: CACert[] }> {
  return request<{ items: CACert[] }>('/ca-certs');
}

export function listWellKnownCAs(): Promise<{ items: WellKnownCA[] }> {
  return request<{ items: WellKnownCA[] }>('/ca-certs/well-known');
}

export function uploadCACert(file: File, name?: string): Promise<CACertImportResult> {
  const form = new FormData();
  form.append('file', file, file.name);
  const qs = name ? `?name=${encodeURIComponent(name)}` : '';
  return request<CACertImportResult>(`/ca-certs${qs}`, { method: 'POST', body: form });
}

export function fetchCACert(url: string, name?: string): Promise<CACertImportResult> {
  return request<CACertImportResult>(
    '/ca-certs/fetch',
    jsonInit('POST', { url, name: name || null }),
  );
}

export function renameCACert(id: number, name: string): Promise<CACert> {
  return request<CACert>(`/ca-certs/${id}`, jsonInit('PATCH', { name }));
}

export function deleteCACert(id: number): Promise<void> {
  return request<void>(`/ca-certs/${id}`, { method: 'DELETE' });
}

// ---------------------------------------------------------------------------
// Test catalog and global test selection
// ---------------------------------------------------------------------------

export function getTestCatalog(): Promise<TestCatalog> {
  return request<TestCatalog>('/test-catalog');
}

export function getGlobalTestSelection(): Promise<GlobalTestSelection> {
  return request<GlobalTestSelection>('/settings/test-selection');
}

export function putGlobalTestSelection(
  tests: Record<string, string[]> | null,
): Promise<GlobalTestSelection> {
  return request<GlobalTestSelection>(
    '/settings/test-selection',
    jsonInit('PUT', { tests }),
  );
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

export function listProfiles(): Promise<ProfileListResponse> {
  return request<ProfileListResponse>('/profiles');
}

export interface ProfileInput {
  name: string;
  description?: string | null;
  config: RunConfig;
}

export function createProfile(input: ProfileInput): Promise<Profile> {
  return request<Profile>('/profiles', jsonInit('POST', input));
}

export function updateProfile(
  profileId: number,
  input: ProfileInput,
): Promise<Profile> {
  return request<Profile>(`/profiles/${profileId}`, jsonInit('PUT', input));
}

export function deleteProfile(profileId: number): Promise<void> {
  return request<void>(`/profiles/${profileId}`, { method: 'DELETE' });
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Multi-user: auth, workspaces, members, API tokens, admin
// ---------------------------------------------------------------------------

export type Role = 'viewer' | 'member' | 'admin';
export type RunVisibility = 'all' | 'own';
export type WorkspaceKind = 'personal' | 'shared';

export interface User {
  id: number;
  provider: 'oidc' | 'local';
  subject: string;
  email: string | null;
  display_name: string | null;
  is_global_admin: boolean;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface Workspace {
  id: number;
  name: string;
  kind: WorkspaceKind;
  run_visibility: RunVisibility;
  allow_private_targets: boolean;
  max_concurrent_runs: number;
  oidc_group_admin: string | null;
  oidc_group: string | null; // member tier
  oidc_group_viewer: string | null;
  role: Role | null;
  created_at: string;
}

export interface AuthConfig {
  auth_required: boolean;
  local_login_enabled: boolean;
  oidc_enabled: boolean;
  oidc_login_url: string | null;
}

export interface Me {
  user: User;
  workspaces: Workspace[];
}

export interface Member {
  user_id: number;
  role: Role;
  email: string | null;
  display_name: string | null;
  provider: string | null;
  source?: string | null; // "manual" | "oidc"
}

export interface ApiToken {
  id: number;
  name: string;
  workspace_id: number | null;
  role_ceiling: Role;
  created_at: string;
  last_used_at: string | null;
}

export interface ApiTokenCreated extends ApiToken {
  token: string;
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor: string | null;
  event: string;
  workspace_id: number | null;
  target: string | null;
  detail: Record<string, unknown>;
}

export function getAuthConfig(): Promise<AuthConfig> {
  return request<AuthConfig>('/auth/config');
}

export function login(username: string, password: string): Promise<User> {
  return request<User>('/auth/login', jsonInit('POST', { username, password }));
}

export function logout(): Promise<void> {
  return request<void>('/auth/logout', { method: 'POST' });
}

export function getMe(): Promise<Me> {
  return request<Me>('/auth/me');
}

export function listWorkspaces(): Promise<Workspace[]> {
  return request<Workspace[]>('/workspaces');
}

export function createWorkspace(name: string): Promise<Workspace> {
  return request<Workspace>('/workspaces', jsonInit('POST', { name }));
}

export interface WorkspaceUpdate {
  name?: string;
  run_visibility?: RunVisibility;
  allow_private_targets?: boolean;
  max_concurrent_runs?: number;
  oidc_group_admin?: string | null;
  oidc_group?: string | null;
  oidc_group_viewer?: string | null;
}

export function updateWorkspace(id: number, patch: WorkspaceUpdate): Promise<Workspace> {
  return request<Workspace>(`/workspaces/${id}`, jsonInit('PATCH', patch));
}

export function deleteWorkspace(id: number): Promise<void> {
  return request<void>(`/workspaces/${id}`, { method: 'DELETE' });
}

export function listMembers(workspaceId: number): Promise<{ items: Member[] }> {
  return request<{ items: Member[] }>(`/workspaces/${workspaceId}/members`);
}

export function addMember(
  workspaceId: number,
  input: { user_id?: number | null; email?: string | null; role: Role },
): Promise<Member> {
  return request<Member>(`/workspaces/${workspaceId}/members`, jsonInit('POST', input));
}

export function changeMemberRole(
  workspaceId: number,
  userId: number,
  role: Role,
): Promise<Member> {
  return request<Member>(
    `/workspaces/${workspaceId}/members/${userId}`,
    jsonInit('PATCH', { role }),
  );
}

export function removeMember(workspaceId: number, userId: number): Promise<void> {
  return request<void>(`/workspaces/${workspaceId}/members/${userId}`, {
    method: 'DELETE',
  });
}

export function getWorkspaceAudit(
  workspaceId: number,
  limit = 100,
): Promise<{ items: AuditEntry[]; total: number }> {
  return request<{ items: AuditEntry[]; total: number }>(
    `/workspaces/${workspaceId}/audit?limit=${limit}`,
  );
}

export function listTokens(): Promise<{ items: ApiToken[] }> {
  return request<{ items: ApiToken[] }>('/tokens');
}

export function createToken(input: {
  name: string;
  workspace_id?: number | null;
  role_ceiling: Role;
}): Promise<ApiTokenCreated> {
  return request<ApiTokenCreated>('/tokens', jsonInit('POST', input));
}

export function revokeToken(id: number): Promise<void> {
  return request<void>(`/tokens/${id}`, { method: 'DELETE' });
}

export function listUsers(): Promise<User[]> {
  return request<User[]>('/admin/users');
}

export function createLocalUser(input: {
  username: string;
  password: string;
  display_name?: string | null;
  is_global_admin?: boolean;
}): Promise<User> {
  return request<User>('/admin/users', jsonInit('POST', input));
}

export function setUserActive(userId: number, active: boolean): Promise<User> {
  return request<User>(`/admin/users/${userId}/active?active=${active}`, {
    method: 'POST',
  });
}

export function getGlobalAudit(
  limit = 200,
  offset = 0,
): Promise<{ items: AuditEntry[]; total: number }> {
  return request<{ items: AuditEntry[]; total: number }>(
    `/admin/audit?limit=${limit}&offset=${offset}`,
  );
}

export { getActiveWorkspaceId };

export function defaultRunConfig(): RunConfig {
  return {
    name: '',
    ocsp_url: '',
    crl_urls: [],
    request_method: 'auto',
    nonce_enabled: true,
    nonce_length: 32,
    latency_samples: 5,
    enable_load_test: false,
    load_concurrency: 5,
    load_requests: 50,
    timeout_seconds: 10,
    run_timeout_seconds: 900,
    max_age_hours: 24,
    trust_anchor_type: 'root',
    require_explicit_policy: false,
    inhibit_policy_mapping: false,
    categories: {
      protocol: true,
      status: true,
      crl: true,
      path_validation: true,
      ikev2: false,
      federal: false,
      performance: false,
      security: true,
    },
    test_selection: { mode: 'all', tests: {} },
    saved_certs: {},
    profile_id: null,
  };
}
