/**
 * Offline lab entry: with every non-loopback request blocked (the lab link has
 * no internet), the console must load, sign in through the local lab-analyst
 * entry, and render, without attempting any external fetch (fonts ship locally).
 *
 * Prerequisite: cd dg-soc/frontend && VITE_AUTH_DEV_BYPASS=1 npm run dev
 * Run:          node tests/e2e/offline-entry.e2e.cjs
 */
const { chromium } = require('playwright');
const UI = process.env.UI_BASE || 'http://127.0.0.1:5173';

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const external = [];
  await page.route('**/*', (route) => {
    const url = new URL(route.request().url());
    if (url.hostname === '127.0.0.1' || url.hostname === 'localhost') return route.continue();
    external.push(url.href);
    return route.abort();
  });
  await page.goto(`${UI}/login`, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: /Continue as lab analyst/ }).click();
  await page.waitForSelector('.sidebar', { timeout: 10000 });
  await page.goto(`${UI}/sensors`, { waitUntil: 'networkidle' });
  const signedIn = (await page.locator('.sidebar__team-user').innerText()).includes('dev');
  console.log(JSON.stringify({ signed_in_offline: signedIn, external_requests_attempted: external }));
  await browser.close();
  const ok = signedIn && external.length === 0;
  console.log(ok ? 'PASS' : 'FAIL');
  process.exit(ok ? 0 : 1);
})().catch((error) => { console.error(error); process.exit(2); });
