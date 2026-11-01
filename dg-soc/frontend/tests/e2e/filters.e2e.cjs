/**
 * Request/session filters against the REAL backend with producers' records.
 *
 * Records: the web records from M3's contract v1.1 examples
 * (tests/fixtures/m3_events_v1_1.json, from m3/evidence-boundaries @ 9dde437),
 * which carry attributes.request_id. M4's generator was not pushed when this
 * was written and the v1.1 examples still have web session_id null, so a second
 * copy carries a session cookie id in session_id, the shape v1.1 asks M4 to
 * emit; it is labelled SYNTHETIC SESSION below. Re-run with M4's real output
 * once pushed (RECORDS=path/to/web.json, one JSON object per line).
 *
 * Prerequisites: backend (fresh DB) on 127.0.0.1:8000, `VITE_AUTH_DEV_BYPASS=1 npm run dev`.
 */
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const API = process.env.API_BASE || 'http://127.0.0.1:8000';
const UI = process.env.UI_BASE || 'http://127.0.0.1:5173';
const SHOTS = process.env.SHOT_DIR || '/tmp/filter-shots';
const STAMP = Date.now();
const RUN = `run-filters-${STAMP}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const checks = [];
const check = (name, ok, detail = '') => { checks.push(ok); console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`); };

function loadRecords() {
  if (process.env.RECORDS) {
    return fs.readFileSync(process.env.RECORDS, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  }
  return JSON.parse(fs.readFileSync(path.join(__dirname, '../fixtures/m3_events_v1_1.json'), 'utf8')).events
    .filter((e) => e.sensor_id === 'web-decoy-01');
}

async function ingest(event) {
  const r = await fetch(`${API}/api/ingest/events`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ events: [event] }) });
  return r.json();
}

(async () => {
  fs.mkdirSync(SHOTS, { recursive: true });
  const records = loadRecords();
  const base = Date.now() - 5 * 60 * 1000;
  const prepared = [];
  records.forEach((record, i) => {
    // The backend on main accepts schema_version "1.0" only. v1.1 is additive, so the
    // same record under a 1.0 envelope (request_id and session_id are allowed extras)
    // is what a producer adopting v1.1 fields early sends. v1.1-only event types
    // such as bait_served are still refused, and reported below.
    const common = { ...record, schema_version: '1.0', lab_run_id: RUN, capture_mode: 'live', occurred_at: new Date(base + i * 1000).toISOString().replace(/\.\d+Z$/, 'Z') };
    prepared.push({ ...common, source_record_id: `${STAMP}-a-${i}` });
    if (!process.env.RECORDS) {
      // SYNTHETIC SESSION: the shape v1.1 asks M4 to emit (session cookie id in session_id).
      prepared.push({ ...common, source_record_id: `${STAMP}-b-${i}`, session_id: 'wsess_synthetic_01',
        attributes: { ...common.attributes, request_id: `${common.attributes.request_id}_s` } });
    }
  });
  const accepted = [], refused = [];
  for (const event of prepared) {
    const out = await ingest(event);
    (out.accepted === 1 ? accepted : refused).push({ event, out });
  }
  console.log(`ingested ${accepted.length}, refused by backend ${refused.length}: ${[...new Set(refused.map((r) => `${r.event.event_type} (${r.out.rejected?.[0]?.reason})`))].join(', ') || 'none'}`);
  check('v1.1-only event types are refused by the v1.0 backend, not silently dropped by the UI',
    refused.every((r) => r.event.event_type === 'bait_served'));

  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  const rowsFor = async (query) => {
    await page.goto(`${UI}/events?${query}&dev=1`, { waitUntil: 'networkidle' });
    await sleep(400);
    return page.$$eval('tr[data-event-id]', (rows) => rows.length);
  };
  const expect = (pred) => accepted.filter(({ event }) => pred(event)).length;

  const reqId = accepted.find(({ event }) => event.attributes.request_id)?.event.attributes.request_id;
  check('request filter enabled once records carry request_id', reqId !== undefined);
  const byRequest = await rowsFor(`run=${RUN}&request=${encodeURIComponent(reqId)}`);
  check(`request filter "${reqId}" shows exactly its records`, byRequest === expect((e) => (e.attributes.request_id || '').includes(reqId)), `${byRequest} rows`);
  await page.screenshot({ path: `${SHOTS}/filter-request.png` });

  const sessions = [...new Set(accepted.map(({ event }) => event.session_id).filter(Boolean))];
  for (const session of sessions) {
    const n = await rowsFor(`run=${RUN}&session=${encodeURIComponent(session)}`);
    check(`session filter "${session}" shows exactly its records`, n === expect((e) => e.session_id === session), `${n} rows`);
  }
  if (sessions.length) await page.screenshot({ path: `${SHOTS}/filter-session.png` });
  const runRows = await rowsFor(`run=${RUN}&mode=live`);
  check('run + mode filters show the whole run', runRows === accepted.length, `${runRows} rows`);
  check('no page errors', errors.length === 0, errors.join(' | '));
  await browser.close();
  process.exit(checks.every(Boolean) ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(2); });
