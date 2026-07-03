import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import { App } from './App';
import { getBasePath } from './lib/base';
import { Dashboard } from './pages/Dashboard';
import { NewRun } from './pages/NewRun';
import { Profiles } from './pages/Profiles';
import { RunDetailPage } from './pages/RunDetail';
import { RunsHistory } from './pages/RunsHistory';
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
      ],
    },
  ],
  { basename: getBasePath() || '/' },
);

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
