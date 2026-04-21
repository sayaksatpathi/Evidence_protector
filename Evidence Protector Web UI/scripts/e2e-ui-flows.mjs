import { chromium } from 'playwright';

const BASE_URL = process.env.EVIDENCE_PROTECTOR_BASE_URL || 'http://127.0.0.1:8080';

function nowIso() {
  return new Date().toISOString();
}

function makeLog(name = 'sample') {
  return [
    `2026-01-15T14:00:00Z ${name}-start`,
    `2026-01-15T14:00:01Z ${name}-ok`,
    `2026-01-15T14:00:02Z ${name}-ok`,
  ].join('\n') + '\n';
}

async function waitForTerminalText(page, text, timeout = 45_000) {
  await page.getByText(text, { exact: false }).waitFor({ state: 'visible', timeout });
}

async function setPrimaryLog(page, fileName, contents) {
  const input = page.locator('input[type="file"]').first();
  await input.setInputFiles({
    name: fileName,
    mimeType: 'text/plain',
    buffer: Buffer.from(contents, 'utf-8'),
  });
}

async function clickMode(page, modeLabel) {
  await page.getByRole('button', { name: modeLabel, exact: true }).click();
}

async function clickRun(page) {
  await page.getByRole('button', { name: 'Run', exact: true }).click();
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1600 }, colorScheme: 'dark' });
  const page = await context.newPage();

  // Fast fail if stack is unavailable.
  const health = await page.request.get(`${BASE_URL}/api/health`);
  if (!health.ok()) {
    throw new Error(`API health check failed at ${BASE_URL}/api/health`);
  }

  await page.goto(`${BASE_URL}/`, { waitUntil: 'networkidle' });
  await page.waitForLoadState('networkidle');
  await page.getByRole('link', { name: /scan/i }).first().click();
  await page.waitForLoadState('networkidle');

  const runLog = makeLog('ui-e2e');

  // SCAN
  await clickMode(page, 'SCAN');
  await setPrimaryLog(page, 'e2e.log', runLog);
  await clickRun(page);
  await waitForTerminalText(page, 'Evidence Protector Report');

  // SIGN
  await clickMode(page, 'SIGN');
  await setPrimaryLog(page, 'e2e.log', runLog);
  await clickRun(page);
  await waitForTerminalText(page, 'Log Signed');

  // Prepare manifest through API for verify UI flow.
  const signApi = await page.request.post(`${BASE_URL}/api/sign`, {
    multipart: {
      file: {
        name: 'e2e.log',
        mimeType: 'text/plain',
        buffer: Buffer.from(runLog, 'utf-8'),
      },
      manifest_mode: 'full',
      checkpoint_every: '1000',
      chain_scheme: 'v1-line+prev',
    },
  });

  if (!signApi.ok()) {
    throw new Error(`API sign setup failed: HTTP ${signApi.status()}`);
  }

  const signPayload = await signApi.json();
  const manifest = signPayload?.manifest;
  if (!manifest || typeof manifest !== 'object') {
    throw new Error('API sign setup did not return manifest JSON.');
  }

  // VERIFY
  await clickMode(page, 'VERIFY');
  const fileInputs = page.locator('input[type="file"]');
  await fileInputs.first().setInputFiles({
    name: 'e2e.log',
    mimeType: 'text/plain',
    buffer: Buffer.from(runLog, 'utf-8'),
  });
  await fileInputs.nth(1).setInputFiles({
    name: 'e2e.manifest.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(manifest, null, 2) + '\n', 'utf-8'),
  });
  await clickRun(page);
  await waitForTerminalText(page, 'Integrity verified. No tampering detected.');

  // GHOST ANALYZE
  await clickMode(page, 'GHOST');
  await page.getByRole('button', { name: 'ANALYZE', exact: true }).click();
  await setPrimaryLog(page, 'e2e.log', runLog);
  await clickRun(page);
  await waitForTerminalText(page, 'Ghost Protocol Analysis');

  // eslint-disable-next-line no-console
  console.log(`[${nowIso()}] UI E2E flows passed: scan/sign/verify/ghost`);
  await browser.close();
}

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error?.stack || error?.message || String(error));
  process.exit(1);
});
