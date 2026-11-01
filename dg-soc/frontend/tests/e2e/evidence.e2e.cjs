/**
 * Live-backend browser evidence for the evidence/health/response UI.
 *
 * Drives the REAL backend (with M2's merged response router) through the REAL
 * UI in live mode, asserts each display rule, and saves screenshots.
 *
 * Prerequisites (nothing is started for you):
 *   backend:  cd dg-soc && DG_DB_PATH=/tmp/evidence.db python -m backend.main   (fresh DB)
 *   frontend: cd dg-soc/frontend && VITE_AUTH_DEV_BYPASS=1 npm run dev          (live mode)
 *   then:     SHOT_DIR=/tmp/shots node tests/e2e/evidence.e2e.cjs
 *
 * Ingests synthetic lab data only (contracts/examples/events_p3.json re-timed,
 * plus a second client and escaping probes) on loopback, and applies one 120 s
 * block through the router, which writes deployment/state/ (gitignored).
 * Exit code 0 = every check passed.
 */
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const API = process.env.API_BASE || 'http://127.0.0.1:8000';
const UI = process.env.UI_BASE || 'http://127.0.0.1:5173';
const SHOTS = process.env.SHOT_DIR || '/tmp/evidence-shots';
const STAMP = Date.now();
const RUN_LIVE = `run-live-${STAMP}`;
const RUN_REPLAY = `run-replay-${STAMP}`;
const XSS_USER = '<img src=x onerror=alert(1)>';
const XSS_AGENT = '<script>alert("ua")</script>';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const checks = [];
function check(name, ok, detail = '') {
  checks.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);
}

async function api(pathname, body) {
  const response = await fetch(`${API}${pathname}`, body === undefined ? undefined : {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  return response.json();
}

function story() {
  const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, '../../../contracts/examples/events_p3.json'), 'utf8')).events;
  const base = Date.parse(fixture[0].occurred_at);
  const t0 = STAMP - 10 * 60 * 1000;
  const retime = (iso) => new Date(t0 + (Date.parse(iso) - base)).toISOString().replace(/\.\d+Z$/, 'Z');
  const attack = fixture.filter((event) => event.event_type !== 'blocked_request');
  const live = attack.map((event, index) => ({
    ...event, source_record_id: `live-${STAMP}-${index}`, lab_run_id: RUN_LIVE, capture_mode: 'live',
    occurred_at: retime(event.occurred_at),
  }));
  const replay = attack.map((event, index) => ({
    ...event, source_record_id: `replay-${STAMP}-${index}`, lab_run_id: RUN_REPLAY, capture_mode: 'replay',
    occurred_at: retime(event.occurred_at),
  }));
  // A second client behind the same address: its own SSH session, its own claims.
  const at = (seconds) => new Date(t0 + seconds * 1000).toISOString().replace(/\.\d+Z$/, 'Z');
  const second = [
    { sensor_id: 'ssh-decoy-01', event_type: 'connection_open', occurred_at: at(400), session_id: 'cli2', attributes: { client_version: 'SSH-2.0-PuTTY_Release_0.81' } },
    { sensor_id: 'ssh-decoy-01', event_type: 'auth_failure', occurred_at: at(401), session_id: 'cli2', attributes: { username: 'backup' } },
    { sensor_id: 'ssh-decoy-01', event_type: 'auth_failure', occurred_at: at(403), session_id: 'cli2', attributes: { username: XSS_USER } },
    { sensor_id: 'web-decoy-01', event_type: 'http_request', occurred_at: at(410), session_id: null, attributes: { method: 'GET', path: '/', status_code: 200, response_class: 'normal', user_agent: XSS_AGENT } },
  ].map((event, index) => ({
    schema_version: '1.0', source_record_id: `second-${STAMP}-${index}`, src_ip: '192.168.77.10',
    src_port: 51000 + index, lab_run_id: RUN_LIVE, capture_mode: 'live', ...event,
  }));
  return { live, replay, second };
}

async function ingestAll(events) {
  for (const event of events) {
    const result = await api('/api/ingest/events', { events: [event] });
    if (result.accepted !== 1) throw new Error(`ingest: ${JSON.stringify(result)} for ${event.source_record_id}`);
  }
}

(async () => {
  fs.mkdirSync(SHOTS, { recursive: true });
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const pageErrors = [];
  const dialogs = [];
  page.on('pageerror', (error) => pageErrors.push(String(error)));
  page.on('dialog', async (dialog) => { dialogs.push(dialog.message()); await dialog.dismiss(); });
  // Viewport shots, scrolled to the section: element shots of tall sections
  // pick up the sticky top bar.
  const shot = async (name, locator) => {
    if (locator) {
      await locator.first().evaluate((el) => el.scrollIntoView({ block: 'start' }));
      await page.evaluate(() => document.querySelector('.main')?.scrollBy(0, -70));
      await sleep(300);
    }
    await page.screenshot({ path: `${SHOTS}/${name}.png` });
  };

  const { live, replay, second } = story();
  await ingestAll([...live.slice(0, 12), ...second, ...live.slice(12)]);
  await ingestAll(replay);

  const incidents = (await api('/api/incidents')).items;
  const liveIncident = incidents.find((incident) => incident.lab_run_id === RUN_LIVE);
  const replayIncident = incidents.find((incident) => incident.lab_run_id === RUN_REPLAY);
  check('live and replay runs are separate incidents', liveIncident && replayIncident && liveIncident.incident_id !== replayIncident.incident_id);

  // ---- Sensors: health separate from activity
  await page.goto(`${UI}/sensors?dev=1`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.healthdims');
  const healthText = await page.locator('.healthdims').innerText();
  check('collection health is reported as not reported, not green', /Not reported/i.test(healthText));
  check('attacker activity is listed on its own', /last event/i.test(healthText));
  await shot('01-sensors-health');

  // ---- Live feed: session filter
  await page.goto(`${UI}/events?session=sess01&run=${RUN_LIVE}&dev=1`, { waitUntil: 'networkidle' });
  await page.waitForSelector('tr[data-event-id]');
  const sessionRows = await page.locator('tr[data-event-id]').count();
  const sess01 = live.filter((event) => event.session_id === 'sess01').length;
  check('session filter shows exactly that session', sessionRows === sess01, `${sessionRows} rows, ${sess01} expected`);
  await shot('02-feed-session-filter');

  // ---- Incident: evidence structure
  await page.goto(`${UI}/incidents/${liveIncident.incident_id}?dev=1`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.casecard');
  const caseIds = await page.$$eval('.casecard', (cards) => cards.map((card) => card.getAttribute('data-case-id')));
  check('second client stays its own session case', caseIds.some((id) => id && id.endsWith('/cli2')) && caseIds.some((id) => id && id.endsWith('/sess01')), caseIds.join(', '));
  check('cases are not scored per case under v1.0', (await page.locator('.casecard .casescore--none').count()) === caseIds.length);
  check('hero score is labelled as a v1.0 source score', /Source score/.test(await page.locator('.inchero__score-label').innerText()));
  const relationText = await page.locator('.rellist').innerText();
  check('token relation does not claim the bait was served', /serving not recorded/i.test(relationText));
  check('relations carry a no-identity caveat', /not a conclusion|not identity/i.test(relationText));
  check('no approved parent before the analyst decides', (await page.locator('.evcard--parent').count()) === 0);
  check('escaped attacker text renders literally', (await page.getByText(XSS_USER, { exact: false }).count()) > 0);
  check('no injected element from attacker text', (await page.locator('[onerror]').count()) === 0 && dialogs.length === 0);
  await shot('03-incident-evidence', page.locator('section[aria-label="Evidence structure"]'));
  await shot('04-incident-mapping', page.locator('.mappinglist'));

  // ---- Analyst confirms the token relation through the real modal
  await page.locator('.relcard--strong_candidate').getByRole('button', { name: /Confirm or reject/ }).click();
  await page.locator('textarea').fill('Portal credential from notes.txt reused on the web login');
  await page.getByRole('button', { name: /^Confirm/ }).last().click();
  await page.waitForSelector('.evcard--parent', { timeout: 8000 });
  check('approved parent appears only after confirmation', (await page.locator('.evcard--parent').count()) === 1);
  await shot('05-parent-approved', page.locator('.evcard--parent'));

  // ---- Response: live source is eligible; apply through the real modal
  const blockButton = page.locator('.page__head [data-eligible]');
  check('block is offered for a live source', (await blockButton.getAttribute('data-eligible')) === 'true');
  await blockButton.click();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.locator('.modal textarea, .modal input[type="text"]').first().fill('demo containment');
  await page.locator('.modal input[type="checkbox"]').check();
  await page.getByRole('button', { name: 'Apply block' }).click();
  await sleep(1500);
  await page.keyboard.press('Escape');
  const closeButton = page.locator('.modal').getByRole('button', { name: /Close|Done/ });
  if (await closeButton.count()) await closeButton.first().click();
  await page.waitForSelector('.vtimeline', { timeout: 8000 });
  await sleep(500);
  check('committed but pending before any denied request', /Pending verification\s*now/i.test(await page.locator('.vtimeline').first().innerText()));
  await shot('06-block-committed-pending', page.locator('.incsummary__side'));

  const action = (await api('/api/response/actions')).items.find((item) => item.target_ip === '192.168.77.10' && item.status === 'applied');
  await ingestAll([{
    schema_version: '1.0', source_record_id: `bounce-${STAMP}`, sensor_id: 'web-decoy-01', event_type: 'blocked_request',
    occurred_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'), src_ip: '192.168.77.10', src_port: 52000, session_id: null,
    lab_run_id: RUN_LIVE, capture_mode: 'live',
    attributes: { method: 'GET', path: '/', status_code: 403, response_class: 'blocked', block_action_id: action.action_id },
  }]);
  await page.waitForFunction(() => document.querySelector('.vstage--k-verified.vstage--done') !== null, null, { timeout: 8000 });
  check('verified denial only after a matching blocked request', true, action.action_id);
  await shot('07-block-verified', page.locator('.incsummary__side'));

  // ---- Replay incident: response withheld, reasons shown
  await page.goto(`${UI}/incidents/${replayIncident.incident_id}?dev=1`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.eligibility');
  check('block is withheld for a replay-only source', (await page.locator('.page__head [data-eligible]').getAttribute('data-eligible')) === 'false');
  check('eligibility notice names the reason', /replay_data/.test(await page.locator('.eligibility').innerText()));
  await shot('08-replay-withheld', page.locator('.incsummary__side'));

  // ---- Response Center
  await page.goto(`${UI}/response?dev=1`, { waitUntil: 'networkidle' });
  await page.waitForSelector('.vtimeline');
  await shot('09-response-center');

  // ---- Graph fallbacks still work
  await page.goto(`${UI}/graph?dev=1`, { waitUntil: 'networkidle' });
  await sleep(2500);
  const twoD = page.getByRole('button', { name: /^2D$/i });
  if (await twoD.count()) await twoD.first().click();
  await sleep(1200);
  check('2D ChakraView renders', (await page.locator('svg.chakra__svg, .chakra__svg').count()) > 0);
  await shot('10-chakra-2d');
  await page.goto(`${UI}/graph?view=network&dev=1`, { waitUntil: 'networkidle' });
  await sleep(1200);
  check('network graph fallback renders', (await page.locator('.graph__svg').count()) > 0);
  await shot('11-network-fallback');

  check('no page errors', pageErrors.length === 0, pageErrors.join(' | '));
  await browser.close();
  const failed = checks.filter((item) => !item.ok);
  console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
  process.exit(failed.length === 0 ? 0 : 1);
})().catch((error) => {
  console.error(error);
  process.exit(2);
});
