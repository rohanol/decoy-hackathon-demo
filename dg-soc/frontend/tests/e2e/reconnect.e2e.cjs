/**
 * Browser check for review T14 against the REAL backend: a WebSocket drop
 * during new events, then a reconnect whose snapshot response is held back
 * while more events arrive live, must leave the Live Feed with every event id
 * exactly once.
 *
 * Prerequisites (nothing is started for you):
 *   backend:  cd dg-soc && DG_DB_PATH=/tmp/reconnect.db python -m backend.main   (fresh DB)
 *   frontend: cd dg-soc/frontend && VITE_AUTH_DEV_BYPASS=1 npm run dev           (live mode, no fixtures)
 *   then:     node tests/e2e/reconnect.e2e.cjs        (needs the playwright package)
 *
 * It ingests synthetic lab events only (DGLAB run id, 192.168.77.10) into the
 * local backend on loopback. Exit code 0 = pass.
 */
const { chromium } = require('playwright');

const API = process.env.API_BASE || 'http://127.0.0.1:8000';
const UI = process.env.UI_BASE || 'http://127.0.0.1:5173';
const RUN = `run-reconnect-${Date.now()}`;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let counter = 0;
function syntheticEvent() {
  counter += 1;
  return {
    schema_version: '1.0',
    source_record_id: `${RUN}-${counter}`,
    sensor_id: 'ssh-decoy-01',
    event_type: 'connection_open',
    occurred_at: new Date(Date.UTC(2026, 10, 1, 6, 0, 0, counter)).toISOString().replace(/\.\d+Z$/, 'Z'),
    src_ip: '192.168.77.10',
    src_port: 40000 + counter,
    session_id: `s-${counter}`,
    lab_run_id: RUN,
    capture_mode: 'live',
    attributes: { client_version: 'SSH-2.0-reconnect-test' },
  };
}

async function ingest(n) {
  for (let i = 0; i < n; i += 1) {
    const response = await fetch(`${API}/api/ingest/events`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ events: [syntheticEvent()] }),
    });
    const body = await response.json();
    if (body.accepted !== 1) throw new Error(`ingest rejected: ${JSON.stringify(body)}`);
    await sleep(40);
  }
}

async function backendIds() {
  const ids = [];
  let cursor = 0;
  for (;;) {
    const page = await (await fetch(`${API}/api/events?since_seq=${cursor}&limit=200`)).json();
    ids.push(...page.items.map((e) => e.event_id));
    if (page.items.length < 200) break;
    cursor = page.next_seq;
  }
  return ids;
}

(async () => {
  const browser = await chromium.launch(process.env.DG_BROWSER_CHANNEL ? { channel: process.env.DG_BROWSER_CHANNEL } : {});
  const page = await browser.newPage({ viewport: { width: 1500, height: 1000 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));

  // A socket we can drop on demand, proxied to the real backend.
  let pageSide = null;
  let connections = 0;
  await page.routeWebSocket(/\/ws\/events$/, (ws) => {
    connections += 1;
    pageSide = ws;
    ws.connectToServer();
  });

  // Hold snapshot responses AFTER the backend has answered: exactly the race.
  let holdMs = 0;
  let heldSnapshots = 0;
  await page.route(/\/api\/events\?/, async (route) => {
    if (holdMs === 0) return route.continue();
    const response = await route.fetch(); // the query has run on the backend now
    heldSnapshots += 1;
    await sleep(holdMs);
    return route.fulfill({ response });
  });

  await ingest(10);
  await page.goto(`${UI}/events?dev=1`, { waitUntil: 'networkidle' });
  await page.waitForSelector('tr[data-event-id]');

  await ingest(5); // steady live delivery
  await sleep(800);

  // Drop the socket, and keep producing while disconnected.
  holdMs = 2500;
  pageSide.close({ code: 1006, reason: 'test drop' });
  await ingest(8);

  // The client reconnects within ~0.5-1 s; its snapshot answer is now held
  // for 2.5 s while these arrive over the new socket.
  const deadline = Date.now() + 5000;
  while (connections < 2 && Date.now() < deadline) await sleep(50);
  await sleep(200);
  await ingest(6);
  await sleep(3500);
  holdMs = 0;
  await ingest(3);
  await sleep(1500);

  const shown = await page.$$eval('tr[data-event-id]', (rows) => rows.map((r) => r.getAttribute('data-event-id')));
  const truth = await backendIds();
  const shownSet = new Set(shown);
  const missing = truth.filter((id) => !shownSet.has(id));
  const extra = shown.filter((id) => !truth.includes(id));
  const duplicates = shown.length - shownSet.size;

  console.log(JSON.stringify({
    run: RUN, backend_events: truth.length, shown_rows: shown.length,
    missing: missing.length, duplicates, extra: extra.length,
    socket_connections: connections, held_snapshots: heldSnapshots, page_errors: errors.length,
  }));
  if (missing.length) console.log('missing ids:', missing.join(' '));
  await page.screenshot({ path: process.env.SHOT || '/tmp/reconnect-e2e.png' });
  await browser.close();

  const ok = missing.length === 0 && duplicates === 0 && extra.length === 0 && connections >= 2 && heldSnapshots >= 1 && errors.length === 0;
  console.log(ok ? 'PASS' : 'FAIL');
  process.exit(ok ? 0 : 1);
})().catch((error) => {
  console.error(error);
  process.exit(2);
});
