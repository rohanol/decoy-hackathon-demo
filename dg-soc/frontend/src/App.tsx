import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { Shell } from './components/Shell';
import { GraphRoute } from './screens/GraphRoute';
import { IncidentDetail } from './screens/IncidentDetail';
import { IncidentList } from './screens/IncidentList';
import { LiveFeed } from './screens/LiveFeed';
import { Overview } from './screens/Overview';
import { ResponseCenter } from './screens/ResponseCenter';
import { TranscriptReplay } from './screens/TranscriptReplay';
import { NotFound } from './screens/Stub';
import { LiveStoreProvider } from './state/LiveStore';

/** Routes match DESIGN_SPEC.md section 1. */
export function App() {
  return (
    <BrowserRouter>
      <LiveStoreProvider>
        <Routes>
          <Route element={<Shell />}>
            <Route index element={<Overview />} />
            <Route path="events" element={<LiveFeed />} />
            <Route path="incidents" element={<IncidentList />} />
            <Route path="incidents/:incidentId" element={<IncidentDetail />} />
            <Route
              path="incidents/:incidentId/transcript/:sessionId"
              element={<TranscriptReplay />}
            />
            <Route path="graph" element={<GraphRoute />} />
            <Route path="response" element={<ResponseCenter />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </LiveStoreProvider>
    </BrowserRouter>
  );
}
