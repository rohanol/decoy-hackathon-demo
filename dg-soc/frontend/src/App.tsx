import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { Shell } from './components/Shell';
import { IncidentDetail } from './screens/IncidentDetail';
import { LiveFeed } from './screens/LiveFeed';
import {
  AttackGraph,
  IncidentList,
  NotFound,
  Overview,
  ResponseCenter,
  TranscriptReplay,
} from './screens/Stub';
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
            <Route path="graph" element={<AttackGraph />} />
            <Route path="response" element={<ResponseCenter />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </LiveStoreProvider>
    </BrowserRouter>
  );
}
