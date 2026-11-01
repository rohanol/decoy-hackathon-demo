/** Integrated synthetic acceptance. Start tests/e2e/prototype_stack.py and a live Vite server first. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');
const API = process.env.API_BASE || 'http://127.0.0.1:18011';
const UI = process.env.UI_BASE || 'http://127.0.0.1:15173';
const CONTROL = process.env.CONTROL_BASE || 'http://127.0.0.1:18182';
const SHOTS = process.env.SHOT_DIR || path.resolve('prototype-shots');
async function get(route) { return (await fetch(API + route)).json(); }

(async () => {
  const status = await (await fetch(CONTROL)).json();
  const browser = await chromium.launch(process.env.DG_BROWSER_CHANNEL ? { channel: process.env.DG_BROWSER_CHANNEL } : {});
  const checks = [];
  const check = (name) => { checks.push(name); console.log('PASS ' + name); };
  fs.mkdirSync(SHOTS, { recursive: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
    const errors = [];
    const dialogs = [];
    page.on('pageerror', error => errors.push(String(error)));
    page.on('dialog', async dialog => { dialogs.push(dialog.message()); await dialog.dismiss(); });
    const escapedUser = '<img src=x onerror=alert(1)>';
    const escapedAgent = '<script>alert("ua")</script>';
    const stamp = Date.now();
    const escapeProbe = [
      { sensor_id: 'ssh-decoy-01', event_type: 'auth_failure', session_id: 'escaping-probe', attributes: { username: escapedUser } },
      { sensor_id: 'web-decoy-01', event_type: 'http_request', session_id: 'escaping-web', attributes: { method: 'GET', path: '/', user_agent: escapedAgent } },
    ].map((row, index) => ({ schema_version: '1.1', source_record_id: `escaping-${stamp}-${index}`,
      src_ip: '192.168.77.10', lab_run_id: status.run, capture_mode: 'live', occurred_at: new Date().toISOString(), ...row }));
    const ingested = await (await fetch(API + '/api/ingest/events', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ events: escapeProbe }) })).json();
    assert.equal(ingested.accepted, 2);
    await page.goto(UI + '/sensors?dev=1', { waitUntil: 'networkidle' });
    await page.waitForSelector('.collector');
    const actualHealth = await get('/api/health');
    assert.equal(await page.locator('.collector').count(), Object.keys(actualHealth.sensor_health ?? actualHealth.sensors).length);
    assert.equal(await page.locator('.collector .healthdim__val').filter({ hasText: /^running$/ }).count(),
      Object.values(actualHealth.sensor_health ?? {}).filter(row => row.process_state === 'running').length);
    check('actual collector heartbeats reach the Sensors screen');
    await page.screenshot({ path: path.join(SHOTS, '01-health.png') });

    await page.goto(`${UI}/incidents/${status.ssh_case}?dev=1`, { waitUntil: 'networkidle' });
    await page.getByText('Case score', { exact: true }).waitFor();
    const cards = page.locator('.casecard');
    assert.ok(await cards.count() >= 3);
    assert.equal(await cards.locator('.authtag').filter({ hasText: 'backend case' }).count(), await cards.count());
    assert.equal(await page.getByText('Source score · v1.0', { exact: true }).count(), 0);
    check('backend cases and scores display with authoritative labels');
    assert.ok(await page.getByText(escapedUser, { exact: false }).count() > 0);
    assert.equal(await page.locator('[onerror]').count(), 0);
    assert.deepEqual(dialogs, []);
    check('attacker text is displayed literally without injected HTML');
    const relation = page.locator(`[data-relation-id="${status.link_id}"]`);
    await relation.waitFor();
    assert.match(await relation.innerText(), /served/i);
    assert.equal(await relation.locator('.bait__step--missing').count(), 0);
    check('actual bait serving and token presentation have their evidence chain');
    await page.screenshot({ path: path.join(SHOTS, '02-cases-and-bait.png') });

    const currentLink = (await get('/api/links')).items.find(item => item.link_id === status.link_id);
    if (currentLink.status !== 'confirmed') {
      await relation.getByRole('button', { name: /Confirm or reject|Change decision/ }).click();
      const dialog = page.getByRole('dialog', { name: 'Cross-decoy link decision' });
      await dialog.getByRole('textbox').fill('Reviewed synthetic serving and token presentation evidence.');
      await dialog.getByRole('button', { name: 'Confirm link', exact: true }).click();
    }
    await page.locator('.evcard--parent').waitFor();
    assert.match(await page.locator('.evcard--parent').innerText(), /Investigation/i);
    const confirmedCases = (await get('/api/incidents')).items;
    const parent = confirmedCases.find(item => item.case_kind === 'investigation' && item.status === 'open');
    assert.ok(parent && parent.children.length >= 2);
    check('analyst confirmation creates a backend investigation');
    await page.screenshot({ path: path.join(SHOTS, '03-investigation.png') });

    const capture = process.env.DG_CAPTURE_FIXTURE;
    if (capture) {
      const fixture = JSON.parse(fs.readFileSync(capture, 'utf8'));
      fixture.confirmed = { incident: await get(`/api/incidents/${status.ssh_case}`), cases: confirmedCases };
      fs.writeFileSync(capture, JSON.stringify(fixture, null, 2) + '\n');
    }

    await page.getByRole('button', { name: 'Block source', exact: true }).click();
    const block = page.getByRole('dialog', { name: 'Block flow' });
    await block.getByRole('button', { name: 'Continue', exact: true }).click();
    await block.getByRole('textbox').fill('Verify scoped denial in the isolated synthetic prototype.');
    await block.getByRole('checkbox').check();
    await block.getByRole('button', { name: /Apply block/ }).click();
    await block.locator('.action--applied').waitFor();
    assert.doesNotMatch(await block.innerText(), /NaN|Invalid Date|undefined/);
    check('preview and apply show a complete action without invented verification');
    const denial = await (await fetch(CONTROL + '/probe', { method: 'POST' })).json();
    assert.equal(denial.portal_status, 403);
    await block.locator('.action--verified').waitFor({ timeout: 10000 });
    check('denied web request traverses the adapter and verifies the action');
    await page.screenshot({ path: path.join(SHOTS, '04-verified-block.png') });
    await block.getByRole('button', { name: /Undo|Revoke/ }).click();
    await block.locator('.action--revoked').waitFor();
    assert.doesNotMatch(await block.innerText(), /NaN|Invalid Date|undefined/);
    const allowed = await (await fetch(CONTROL + '/probe', { method: 'POST' })).json();
    assert.equal(allowed.portal_status, 200);
    check('revoke restores access and renders the full action');
    await block.getByRole('button', { name: 'Done', exact: true }).click();

    const confirmed = page.locator(`[data-relation-id="${status.link_id}"]`);
    await confirmed.getByRole('button', { name: 'Change decision…' }).click();
    const reversal = page.getByRole('dialog', { name: 'Cross-decoy link decision' });
    await reversal.getByRole('textbox').fill('Reverse the synthetic relation while preserving observations.');
    await reversal.getByRole('button', { name: 'Reject', exact: true }).click();
    await page.waitForFunction(() => !document.querySelector('.evcard--parent'));
    const after = (await get('/api/incidents')).items.find(item => item.incident_id === parent.incident_id);
    assert.equal(after.status, 'dissolved');
    check('reversing confirmation dissolves the investigation');

    await page.goto(`${UI}/incidents/${status.replay_case}?dev=1`, { waitUntil: 'networkidle' });
    const replayBlock = page.getByRole('button', { name: 'Block source', exact: true });
    await replayBlock.waitFor();
    assert.equal(await replayBlock.isDisabled(), true);
    check('backend replay eligibility disables the action in the browser');
    await page.goto(UI + '/graph?dev=1', { waitUntil: 'networkidle' });
    const twoD = page.getByRole('button', { name: /^2D$/i });
    if (await twoD.count()) await twoD.first().click();
    await page.locator('svg.chakra__svg, .chakra__svg').waitFor();
    check('2D ChakraView renders the integrated backend');
    await page.goto(UI + '/graph?view=network&dev=1', { waitUntil: 'networkidle' });
    await page.locator('.graph__svg').waitFor();
    check('network graph fallback renders the integrated backend');
    assert.deepEqual(errors, []);
    check('no browser page errors during the full flow');
    fs.writeFileSync(path.join(SHOTS, 'receipts.json'), JSON.stringify({ checks, page_errors: errors, physical_lab: false }, null, 2));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
