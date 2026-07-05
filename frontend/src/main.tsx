import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import { App } from './App';
import { getBasePath } from './lib/base';
import { AuthProvider, useAuth } from './lib/auth';
import { Admin } from './pages/Admin';
import { CALibrary } from './pages/CALibrary';
import { Dashboard } from './pages/Dashboard';
import { Login } from './pages/Login';
import { NewRun } from './pages/NewRun';
import { Profiles } from './pages/Profiles';
import { RunDetailPage } from './pages/RunDetail';
import { RunsHistory } from './pages/RunsHistory';
import { Settings } from './pages/Settings';
import { Tokens } from './pages/Tokens';
import { Workspaces } from './pages/Workspaces';
import './styles.css';

const router = createBrowserRouter(
  [
    {
      path: '/',
      element: <App />,
      children: [
        { index: true, element: <Dashboard /> },
        { path: 'runs', element: <RunsHistory /> },
        { path: 'runs/new', element: <NewRun /> },
        { path: 'runs/:id', element: <RunDetailPage /> },
        { path: 'profiles', element: <Profiles /> },
        { path: 'ca-library', element: <CALibrary /> },
        { path: 'workspaces', element: <Workspaces /> },
        { path: 'tokens', element: <Tokens /> },
        { path: 'admin', element: <Admin /> },
        { path: 'settings', element: <Settings /> },
      ],
    },
  ],
  { basename: getBasePath() || '/' },
);

function Root() {
  const { loading, needsLogin } = useAuth();
  if (loading) {
    return <div className="app-loading">Loading…</div>;
  }
  if (needsLogin) {
    return <Login />;
  }
  return <RouterProvider router={router} />;
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthProvider>
      <Root />
    </AuthProvider>
  </StrictMode>,
);
