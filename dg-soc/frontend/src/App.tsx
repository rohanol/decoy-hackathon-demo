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
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
