// Disposable loopback acceptance, not physical Kali. Start kali_four_stack.py
// --trip-web-port 18080, then fixture-free Vite on 15173 with VITE_AUTH_LOCAL=1.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { chromium } = require('playwright');
const UI = process.env.UI_BASE || 'http://127.0.0.1:15173';
const SHOTS = process.env.SHOT_DIR || path.resolve('trip-shots');
const BASH = process.env.DG_TEST_BASH || 'bash';

(async () => {
  const browser = await chromium.launch({ headless: true, channel: process.env.DG_BROWSER_CHANNEL || 'msedge' });
  const checks = [], errors = [], external = [];
  const check = name => { checks.push(name); console.log('PASS', name); };
  fs.mkdirSync(SHOTS, { recursive: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
    page.on('pageerror', error => errors.push(String(error)));
    page.on('request', request => {
      if (!['127.0.0.1', 'localhost'].includes(new URL(request.url()).hostname)) external.push(request.url());
    });
    await page.goto(UI + '/sensors?local=1', { waitUntil: 'networkidle' });
    const panel = page.getByRole('region', { name: 'Controlled trip test' });
    await panel.getByRole('button', { name: 'Start web trip', exact: true }).click();
    await panel.getByRole('textbox', { name: 'Attacker trip command' }).waitFor();
    const runCommand = async (peer = '192.168.77.10') => {
      const command = await panel.getByRole('textbox', { name: 'Attacker trip command' }).inputValue();
      assert.match(command, /dg_trip=trip_[a-f0-9]{32}/);
      assert.ok(command.includes('http://192.168.77.20:8080/search'));
      const local = command.replace('http://192.168.77.20:8080/search', 'http://127.0.0.1:18080/search');
      const output = execFileSync(BASH, ['-c', local + ` -H 'X-DG-Test-Peer: ${peer}'`], { encoding: 'utf8', timeout: 15000 });
      assert.match(output, /Trip HTTP status: 500/);
    };
    assert.match(await panel.innerText(), /Waiting for evidence/);
    check('new trip starts unverified and displays a bounded attacker command');
    await runCommand();
    await panel.getByRole('status').filter({ hasText: 'Last web trip passed' }).waitFor({ timeout: 15000 });
    assert.match(await panel.innerText(), /Finding fnd_|Finding find_|Finding finding_|Finding f_/);
    assert.equal(await panel.locator('.trip__steps [data-passed="true"]').count(), 3);
    check('actual curl → local decoy → adapter → backend R07 → dashboard passed with evidence IDs');
    await panel.screenshot({ path: path.join(SHOTS, 'controlled-trip-passed.png') });
    await panel.getByRole('button', { name: 'Start a new web trip' }).click();
    await page.waitForTimeout(300);
    await runCommand('192.168.77.20');
    await page.waitForTimeout(2500);
    assert.match(await panel.innerText(), /Waiting for evidence/);
    assert.equal(await panel.locator('.trip__steps [data-passed="true"]').count() < 3, true);
    check('a defender-source request cannot pass the attacker-source check');
    await panel.getByRole('button', { name: 'Start a new web trip' }).click();
    await page.waitForTimeout(300);
    await page.route('**/api/incidents/*', async route => {
      const response = await route.fetch();
      const body = await response.json();
      if (Array.isArray(body.findings)) body.findings = body.findings.filter(f => f.rule_id !== 'R07');
      await route.fulfill({ response, json: body });
    });
    await runCommand();
    await page.waitForTimeout(2500);
    assert.equal(await panel.locator('.trip__steps [data-passed="true"]').count(), 2);
    assert.match(await panel.innerText(), /Waiting for evidence/);
    check('stored HTTP response without its R07 alert does not pass');
    await page.unroute('**/api/incidents/*');
    await page.route('**/api/events?**', route => route.abort());
    await panel.getByRole('button', { name: 'Start a new web trip' }).click();
    await panel.getByRole('alert').waitFor({ timeout: 10000 });
    assert.match(await panel.getByRole('status').innerText(), /Read unavailable/);
    check('backend read failure is shown as unavailable without a false pass');
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    check('no browser page errors or external requests');
    fs.writeFileSync(path.join(SHOTS, 'receipt.json'), JSON.stringify({ checks, errors, external,
      physical_capture: false, scope: 'real local curl/Flask/adapter/backend/browser with explicitly synthetic source IP' }, null, 2));
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
