import { lazy, Suspense } from 'react';
import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { AuthProvider } from './auth/AuthProvider';
import { RequireAuth } from './auth/RequireAuth';
import { Shell } from './components/Shell';
import { IncidentDetail } from './screens/IncidentDetail';
import { IncidentList } from './screens/IncidentList';
import { Landing } from './screens/Landing';
import { LiveFeed } from './screens/LiveFeed';
import { Login } from './screens/Login';
import { Overview } from './screens/Overview';
import { ResponseCenter } from './screens/ResponseCenter';
import { Sensors } from './screens/Sensors';
import { TranscriptReplay } from './screens/TranscriptReplay';
import { NotFound } from './screens/Stub';
import { LiveStoreProvider } from './state/LiveStore';

/**
 * Read here, as in api/client.ts, so a normal build sees a constant false and
 * drops the evidence lab and its development fixtures from the bundle.
 */
const MOCK = import.meta.env.VITE_USE_FIXTURES === '1';
const EvidenceLab = MOCK
  ? lazy(() => import('./screens/EvidenceLab').then((module) => ({ default: module.EvidenceLab })))
  : null;

// ChakraView pulls in three.js; load it only when someone opens it.
const GraphRoute = lazy(() =>
  import('./screens/GraphRoute').then((module) => ({ default: module.GraphRoute })),
);

/** Routes match DESIGN_SPEC.md section 1, plus /welcome, /login and /sensors. */
export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/welcome" element={<Landing />} />
          <Route path="/login" element={<Login />} />
          <Route
            element={
              <RequireAuth>
                <LiveStoreProvider>
                  <Shell />
                </LiveStoreProvider>
              </RequireAuth>
            }
          >
            <Route index element={<Overview />} />
            <Route path="events" element={<LiveFeed />} />
            <Route path="incidents" element={<IncidentList />} />
            <Route path="incidents/:incidentId" element={<IncidentDetail />} />
            <Route
              path="incidents/:incidentId/transcript/:sessionId"
              element={<TranscriptReplay />}
            />
            <Route
              path="graph"
              element={
                <Suspense fallback={<div className="page chakra3d__loading">Loading ChakraView…</div>}>
                  <GraphRoute />
                </Suspense>
              }
            />
            <Route path="response" element={<ResponseCenter />} />
            <Route path="sensors" element={<Sensors />} />
            {EvidenceLab ? (
              <Route
                path="dev/evidence"
                element={
                  <Suspense fallback={<div className="page">Loading evidence lab…</div>}>
                    <EvidenceLab />
                  </Suspense>
                }
              />
            ) : null}
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
