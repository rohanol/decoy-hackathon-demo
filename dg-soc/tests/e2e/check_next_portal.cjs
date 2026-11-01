// Browser review of actual loopback portal/decoy, no synthetic SOC UI claims.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const [normal, decoy, shots] = process.argv.slice(2);
  for (const url of [normal, decoy]) {
    if (new URL(url).hostname !== '127.0.0.1') throw new Error('Loopback only');
  }
  fs.mkdirSync(shots, { recursive: true });
  const browser = await chromium.launch({ headless: true, channel: process.env.DG_BROWSER_CHANNEL || 'msedge' });
  const context = await browser.newContext({ viewport: { width: 1280, height: 850 }, acceptDownloads: true });
  const page = await context.newPage();
  const errors = [], external = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => {
    const url = new URL(request.url());
    if (!['127.0.0.1', 'localhost'].includes(url.hostname)) external.push(request.url());
  });
  try {
    await page.goto(normal);
    await page.getByRole('heading', { level: 1 }).waitFor();
    const theme = () => page.evaluate(() => ({
      background: getComputedStyle(document.body).backgroundColor,
      text: getComputedStyle(document.body).color,
      card: getComputedStyle(document.querySelector('.hero__card, .card')).backgroundColor,
    }));
    const expected = { background: 'rgb(5, 5, 5)', text: 'rgb(244, 244, 242)', card: 'rgb(12, 12, 12)' };
    assert.deepEqual(await theme(), expected);
    await page.screenshot({ path: path.join(shots, 'normal-portal.png'), fullPage: true });
    await page.goto(decoy);
    await page.getByRole('heading', { name: 'Research that connects people and ideas.' }).waitFor();
    assert.deepEqual(await theme(), expected);
    await page.screenshot({ path: path.join(shots, 'decoy-portal.png'), fullPage: true });
    await page.goto(decoy + '/login');
    await page.getByRole('heading', { name: 'Sign in', exact: true }).waitFor();
    await page.screenshot({ path: path.join(shots, 'decoy-login.png'), fullPage: true });
    await page.goto(decoy + '/resources');
    const downloadReady = page.waitForEvent('download');
    await page.getByRole('link', { name: 'Backup archive' }).click();
    const download = await downloadReady;
    assert.equal(download.suggestedFilename(), 'backup.zip');
    assert.equal(await download.failure(), null);
    await page.goto(decoy + '/search?q=' + encodeURIComponent('<script>window.attackerExecuted=true</script>'));
    assert.equal(await page.evaluate(() => window.attackerExecuted), undefined);
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(decoy);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.screenshot({ path: path.join(shots, 'decoy-mobile.png'), fullPage: true });
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    const receipt = { checks: 7, browser: 'installed ' + (process.env.DG_BROWSER_CHANNEL || 'msedge'),
      darkTheme: expected,
      normalAndDecoyRendered: true, actualArchiveDownload: 'backup.zip', scriptExecuted: false,
      mobileOverflow: false, pageErrors: errors, externalRequests: external };
    fs.writeFileSync(path.join(shots, 'browser-receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
    console.log(JSON.stringify(receipt));
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
