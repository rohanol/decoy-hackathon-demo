const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');
const API = process.env.API_BASE || 'http://127.0.0.1:18011';
const UI = process.env.UI_BASE || 'http://127.0.0.1:15173';
const CONTROL = process.env.CONTROL_BASE || 'http://127.0.0.1:18182';
const SHOTS = process.env.SHOT_DIR || path.resolve('kali-four-shots');
const get = async route => (await fetch(API + route)).json();

(async () => {
  const status = await (await fetch(CONTROL)).json();
  const browser = await chromium.launch({ headless: true, channel: process.env.DG_BROWSER_CHANNEL || 'msedge' });
  const checks = [], errors = [], external = [];
  const check = name => { checks.push(name); console.log('PASS', name); };
  fs.mkdirSync(SHOTS, { recursive: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
    page.on('pageerror', error => errors.push(String(error)));
    page.on('request', request => {
      if (!['127.0.0.1', 'localhost'].includes(new URL(request.url()).hostname)) external.push(request.url());
    });
    await page.goto(UI + '/sensors?dev=1', { waitUntil: 'networkidle' });
    await page.waitForSelector('.collector');
    assert.equal(await page.locator('.sensorcard').count(), 4);
    assert.equal(await page.locator('.collector .healthdim__val').filter({ hasText: /^running$/ }).count(), 4);
    assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), 'rgb(5, 5, 5)');
    assert.equal(await page.getByRole('heading', { name: 'Telemetry sources · not honeypots' }).count(), 0);
    check('original dark SOC shows four real collector paths without the new app/gateway');
    await page.screenshot({ path: path.join(SHOTS, '01-four-sensors.png'), fullPage: true });
    await page.goto(`${UI}/incidents/${status.db_case}?dev=1`, { waitUntil: 'networkidle' });
    await page.getByText('Case score', { exact: true }).waitFor();
    assert.ok(await page.getByText('mysql_native_password', { exact: false }).count() > 0);
    assert.equal(await page.getByRole('button', { name: 'Block source', exact: true }).isDisabled(), true);
    assert.equal(await page.locator('.v12scope[data-unsupported="true"]').count(), 1);
    check('MySQL proof/command evidence is visible and web-only response stays disabled');
    await page.goto(`${UI}/incidents/${status.file_case}?dev=1`, { waitUntil: 'networkidle' });
    await page.getByText('Case score', { exact: true }).waitFor();
    assert.ok(await page.getByText(/stored inert/i).count() > 0);
    assert.equal(await page.getByRole('button', { name: 'Block source', exact: true }).isDisabled(), true);
    check('actual SMB upload and inert-storage evidence reaches the incident screen');
    await page.screenshot({ path: path.join(SHOTS, '02-file-evidence.png'), fullPage: true });
    await page.goto(`${UI}/incidents/${status.web_case}?dev=1`, { waitUntil: 'networkidle' });
    await page.locator('.v12claims').first().waitFor();
    assert.ok(await page.getByText('unknown', { exact: false }).count() > 0);
    assert.equal(await page.getByRole('heading', { name: 'Gateway routing' }).count(), 0);
    check('ZIP evidence reports response facts and unknown transfer completion');
    const relation = page.locator(`[data-relation-id="${status.db_link}"]`);
    if ((await get('/api/links')).items.find(link => link.link_id === status.db_link).status !== 'confirmed') {
      await relation.getByRole('button', { name: /Confirm or reject|Change decision/ }).click();
      const decision = page.getByRole('dialog', { name: 'Cross-decoy link decision' });
      await decision.getByRole('textbox').fill('Synthetic loopback archive and database proof reviewed; identity is not established.');
      await decision.getByRole('button', { name: /^Confirm link/ }).click();
      await decision.waitFor({ state: 'hidden' });
    }
    assert.ok((await get('/api/incidents')).items.some(item => item.case_kind === 'investigation'));
    check('analyst confirmation creates a backend investigation from actual producer evidence');
    await page.getByRole('button', { name: 'Block source', exact: true }).click();
    const block = page.getByRole('dialog', { name: 'Block flow' });
    await block.getByRole('button', { name: 'Continue', exact: true }).click();
    await block.getByRole('textbox').fill('Synthetic direct-Kali lab response acceptance');
    await block.getByRole('checkbox').check();
    await block.getByRole('button', { name: /Apply block/ }).click();
    await block.locator('.action--applied').waitFor();
    assert.doesNotMatch(await block.innerText(), /NaN|Invalid Date|undefined/);
    check('preview/apply remains pending until a real denied request is collected');
    const denied = await (await fetch(CONTROL + '/probe', { method: 'POST' })).json();
    assert.equal(denied.portal_status, 403);
    await block.locator('.action--verified').waitFor({ timeout: 10000 });
    check('denial traverses actual web mapper, sender and trusted backend verification');
    await page.screenshot({ path: path.join(SHOTS, '03-verified-response.png'), fullPage: true });
    await block.getByRole('button', { name: /Undo|Revoke/ }).click();
    await block.locator('.action--revoked').waitFor();
    assert.equal((await (await fetch(CONTROL + '/probe', { method: 'POST' })).json()).portal_status, 200);
    check('revoke restores the synthetic web response');
    await block.getByRole('button', { name: 'Done', exact: true }).click();
    await page.goto(UI + '/graph?view=network&dev=1', { waitUntil: 'networkidle' });
    await page.locator('.graph__svg').waitFor();
    assert.equal(await page.locator('.gnode--sensor').count(), 4);
    const network = await page.locator('.graph__svg').textContent();
    for (const id of ['ssh-decoy-01', 'web-decoy-01', 'db-decoy-01', 'file-decoy-01']) assert.ok(network.includes(id));
    check('network graph represents all four sensors and backend-reported links');
    await page.screenshot({ path: path.join(SHOTS, '04-four-sensor-graph.png'), fullPage: true });
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    check('no browser page errors or external requests');
    fs.writeFileSync(path.join(SHOTS, 'browser-receipt.json'), JSON.stringify({ checks, errors, external,
      scope: 'synthetic SSH/web peers, actual loopback MySQL/SMB, actual adapter/backend/UI; not physical Kali' }, null, 2) + '\n');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
