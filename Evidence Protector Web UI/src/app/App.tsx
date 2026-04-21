import { RouterProvider } from './router';
import { Root } from './Root';
import { Dashboard } from './pages/Dashboard';
import { Scan } from './pages/Scan';
import { Sign } from './pages/Sign';
import { Results } from './pages/Results';
import { History } from './pages/History';
import { Verify } from './pages/Verify';
import { Baselines } from './pages/Baselines';
import { Compare } from './pages/Compare';
import { Audit } from './pages/Audit';
import { Guide } from './pages/Guide';
import { ReleaseEvidence } from './pages/ReleaseEvidence';
import { NotFound } from './pages/NotFound';

const routes = [
  { path: '/', Component: Dashboard },
  { path: '/scan', Component: Scan },
  { path: '/sign', Component: Sign },
  { path: '/verify', Component: Verify },
  { path: '/history', Component: History },
  { path: '/baselines', Component: Baselines },
  { path: '/compare', Component: Compare },
  { path: '/audit', Component: Audit },
  { path: '/guide', Component: Guide },
  { path: '/release-evidence', Component: ReleaseEvidence },
  { path: '/results/:id', Component: Results },
  { path: '*', Component: NotFound },
];

export default function App() {
  return <RouterProvider routes={routes} layout={Root} />;
}
