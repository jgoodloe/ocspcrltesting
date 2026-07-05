/**
 * Authentication + active-workspace context.
 *
 * On mount it reads `/auth/config`; if auth is not required (open mode) the app
 * behaves exactly as before. Otherwise it loads `/auth/me`, tracks the active
 * workspace (persisted to localStorage), and reacts to global 401s by clearing
 * the session so the UI falls back to the login screen.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import {
  AUTH_UNAUTHORIZED_EVENT,
  getAuthConfig,
  getMe,
  login as apiLogin,
  logout as apiLogout,
  type AuthConfig,
  type Me,
  type Workspace,
} from './api';
import { setActiveWorkspaceId } from './base';

const ACTIVE_WS_KEY = 'ocspweb.activeWorkspace';

interface AuthState {
  loading: boolean;
  config: AuthConfig | null;
  me: Me | null;
  workspaces: Workspace[];
  activeWorkspace: Workspace | null;
  /** True when the user must log in (auth required and no session). */
  needsLogin: boolean;
  setActiveWorkspace: (id: number) => void;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

function readStoredWorkspace(): number | null {
  const raw = localStorage.getItem(ACTIVE_WS_KEY);
  if (!raw) return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [loading, setLoading] = useState(true);
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [activeId, setActiveId] = useState<number | null>(readStoredWorkspace());

  const workspaces = me?.workspaces ?? [];

  const activeWorkspace = useMemo(() => {
    if (workspaces.length === 0) return null;
    return workspaces.find((w) => w.id === activeId) ?? workspaces[0];
  }, [workspaces, activeId]);

  // Keep the api layer's active workspace id in sync.
  useEffect(() => {
    setActiveWorkspaceId(activeWorkspace ? activeWorkspace.id : null);
  }, [activeWorkspace]);

  const loadMe = useCallback(async () => {
    const data = await getMe();
    setMe(data);
    // Default the active workspace to a personal one when nothing valid is set.
    setActiveId((prev) => {
      if (prev && data.workspaces.some((w) => w.id === prev)) return prev;
      const personal = data.workspaces.find((w) => w.kind === 'personal');
      return (personal ?? data.workspaces[0])?.id ?? null;
    });
  }, []);

  const bootstrap = useCallback(async () => {
    setLoading(true);
    try {
      const cfg = await getAuthConfig();
      setConfig(cfg);
      // In open mode /auth/me still works (anonymous admin). Load it either way
      // so the workspace list is populated.
      try {
        await loadMe();
      } catch {
        setMe(null);
      }
    } finally {
      setLoading(false);
    }
  }, [loadMe]);

  useEffect(() => {
    void bootstrap();
  }, [bootstrap]);

  // Global 401 -> drop the session so the login screen shows.
  useEffect(() => {
    const handler = () => setMe(null);
    window.addEventListener(AUTH_UNAUTHORIZED_EVENT, handler);
    return () => window.removeEventListener(AUTH_UNAUTHORIZED_EVENT, handler);
  }, []);

  const setActiveWorkspace = useCallback((id: number) => {
    localStorage.setItem(ACTIVE_WS_KEY, String(id));
    setActiveId(id);
  }, []);

  const login = useCallback(
    async (username: string, password: string) => {
      await apiLogin(username, password);
      await loadMe();
    },
    [loadMe],
  );

  const logout = useCallback(async () => {
    await apiLogout();
    setMe(null);
  }, []);

  const needsLogin = Boolean(config?.auth_required && me === null && !loading);

  const value: AuthState = {
    loading,
    config,
    me,
    workspaces,
    activeWorkspace,
    needsLogin,
    setActiveWorkspace,
    login,
    logout,
    refresh: loadMe,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
