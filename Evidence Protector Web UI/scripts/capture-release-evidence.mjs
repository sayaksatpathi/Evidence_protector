import { chromium } from 'playwright';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const DEFAULT_BASE_URL = process.env.EVIDENCE_PROTECTOR_BASE_URL || 'http://127.0.0.1:8080';
const DEFAULT_OUT_DIR = process.env.EVIDENCE_PROTECTOR_EVIDENCE_OUT_DIR || path.resolve(process.cwd(), '..', 'artifacts', 'release-evidence');

function nowIso() {
  return new Date().toISOString();
}

function sha256FileFromBuffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function stringify(obj) {
  return JSON.stringify(obj, null, 2) + '\n';
}

function seedHistory() {
  const scanId = 'auto-scan-1';
  const verifyId = 'auto-verify-1';
  const signId = 'auto-sign-1';
  const ghostAnalyzeId = 'auto-ghost-analyze-1';
  const ghostBaselineId = 'auto-ghost-baseline-1';
  const ghostReceiptsId = 'auto-ghost-receipts-1';

  const scanDetails = {
    scan: {
      request_id: 'req-scan-auto-1',
      gapThreshold: 300,
      outputFormat: 'terminal',
      stats: {
        file: 'sample.log',
        total_lines: 8,
        malformed_lines: 1,
        timestamps_found: 7,
        threshold_seconds: 300,
        gaps_found: 2,
        timestamp_anomalies: 1,
        first_timestamp: '2026-01-15T14:23:01+00:00',
        last_timestamp: '2026-01-15T14:31:40+00:00',
        max_gap_seconds: 301,
        max_anomaly_seconds: 60,
      },
      gaps: [
        {
          gap_index: 1,
          gap_start: '2026-01-15T14:24:01+00:00',
          gap_end: '2026-01-15T14:25:30+00:00',
          duration_seconds: 89,
          line_start: 2,
          line_end: 4,
          note: null,
        },
        {
          gap_index: 2,
          gap_start: '2026-01-15T14:31:40+00:00',
          gap_end: '2026-01-15T14:30:40+00:00',
          duration_seconds: 60,
          line_start: 7,
          line_end: 8,
          note: 'TIMESTAMP_ANOMALY',
        },
      ],
      outputText: 'Evidence Protector Report\n...\n',
    },
  };

  const signManifest = {
    file: 'sample.log',
    signed_at: '2026-04-20T00:00:00Z',
    hash_algorithm: 'sha256',
    chain_scheme: 'v1-line+prev',
    manifest_mode: 'full',
    checkpoint_every: undefined,
    checkpoint_count: 0,
    entry_count: 8,
    total_lines: 8,
    root_hash: 'eebc919b43417b64e1076104bcb97a1582c0f091d85b185e418f6e42db970476',
    signature: {
      scheme: 'ed25519',
      key_id: 'auto-release-key',
      value: 'QXV0b1NpZ25hdHVyZQ==',
    },
  };

  const verifyReport = {
    file: 'sample.log',
    manifest: 'sample.log.manifest.json',
    signed_at: signManifest.signed_at,
    verified_at: '2026-04-20T00:05:00Z',
    clean: false,
    issues_found: 1,
    issues: [
      {
        line_number: 8,
        expected_chain_hash: 'eebc919b43417b64e1076104bcb97a1582c0f091d85b185e418f6e42db970476',
        actual_chain_hash: 'f8a6bf6d6d2d6d2d6d2d6d2d6d2d6d2d6d2d6d2d6d2d6d2d6d2d6d2d6d2d6d2',
        status: 'TAMPERED',
        note: 'Synthetic capture record',
      },
    ],
    manifest_total_lines: 8,
    current_total_lines: 9,
    manifest_root_hash: signManifest.root_hash,
    current_root_hash: 'f8a6bf6d6d2d6d2d6d2d6d2d6d2d6d2d6d2d6d2d6d2d6d2d6d2d6d2d6d2d6d2',
    manifest_signature: { present: true, scheme: 'ed25519', key_id: 'auto-release-key', valid: false, reason: 'invalid' },
    manifest_mode: 'full',
    chain_scheme: 'v1-line+prev',
    hash_algorithm: 'sha256',
  };

  const ghostAnalyzeReport = {
    version: 1,
    generated_at: nowIso(),
    file: 'sample.log',
    config: {
      window_lines: 20,
      max_lines: 250000,
      gap_threshold_seconds: 300,
      dna_jsd_threshold: 0.12,
      dna_min_window_chars: 800,
      entropy_z_threshold: 3.5,
      entropy_min_window_chars: 800,
      regularity_cv_threshold: 0.01,
      min_intervals_for_regularity: 40,
      fs_mtime_vs_last_log_seconds: 3600,
    },
    summary: {
      total_lines: 8,
      timestamps_found: 7,
      malformed_lines: 1,
      big_gaps: 1,
      max_gap_seconds: 301,
      time_reversals: 1,
      first_timestamp: '2026-01-15T14:23:01+00:00',
      last_timestamp: '2026-01-15T14:31:40+00:00',
      event_counts: { total: 3, critical: 0, high: 2, medium: 1, low: 0 },
      risk_score: 145,
    },
    events: [
      {
        signal_type: 'TIME_GAP',
        severity: 'HIGH',
        confidence: 0.91,
        time_range: ['2026-01-15T14:24:01+00:00', '2026-01-15T14:25:30+00:00'],
        line_range: [2, 4],
        evidence: [{ kind: 'delta_seconds', detail: { delta: 89, threshold: 300 } }],
      },
      {
        signal_type: 'TIME_REVERSAL',
        severity: 'HIGH',
        confidence: 0.92,
        time_range: ['2026-01-15T14:31:40+00:00', '2026-01-15T14:30:40+00:00'],
        line_range: [7, 8],
        evidence: [{ kind: 'delta_seconds', detail: { delta: -60 } }],
      },
      {
        signal_type: 'FS_TIME_MISMATCH',
        severity: 'MEDIUM',
        confidence: 0.6,
        time_range: null,
        line_range: null,
        evidence: [{ kind: 'mtime_vs_last_log', detail: { delta_seconds: 4312, threshold_seconds: 3600 } }],
      },
    ],
  };

  const ghostBaseline = {
    version: 1,
    created_at: '2026-04-20T00:00:00Z',
    source_hint: 'prod/nginx',
    total_lines: 240,
    timestamps_found: 240,
    malformed_lines: 0,
    entropy_mean: 3.9123,
    entropy_stdev: 0.2211,
    interval_mean: 1.03,
    interval_stdev: 0.14,
    char_prob: Array.from({ length: 257 }, (_, i) => (i === 101 ? 0.2 : 0.0)),
  };

  const ghostReceipts = [
    {
      version: 1,
      created_at: '2026-04-20T00:01:00Z',
      kind: 'FILE',
      host: { hostname: 'release-host', user: 'runner' },
      data: {
        path: 'sample.log',
        size_bytes: 2048,
        mtime_epoch: 1768867260,
        ctime_epoch: 1768867260,
        inode: 12345,
        head_sha256: 'abcd',
        tail_sha256: 'efgh',
      },
    },
    {
      version: 1,
      created_at: '2026-04-20T00:02:00Z',
      kind: 'FILE',
      host: { hostname: 'release-host', user: 'runner' },
      data: {
        path: 'sample.log',
        size_bytes: 1024,
        mtime_epoch: 1768867160,
        ctime_epoch: 1768867160,
        inode: 12345,
        head_sha256: 'zzzz',
        tail_sha256: 'yyyy',
      },
    },
  ];

  const records = [
    {
      id: ghostAnalyzeId,
      timestamp: '2026-04-20 09:40:00',
      file: 'sample.log',
      mode: 'ghost',
      status: 'GHOST_SIGNALS',
      gaps: 3,
      lines: 8,
      request_id: 'req-ghost-analyze-auto-1',
      details: {
        ghost: {
          request_id: 'req-ghost-analyze-auto-1',
          status: 'GHOST_SIGNALS',
          action: 'analyze',
          report: ghostAnalyzeReport,
        },
      },
    },
    {
      id: ghostBaselineId,
      timestamp: '2026-04-20 09:30:00',
      file: 'sample.log',
      mode: 'ghost',
      status: 'GHOST_BASELINE',
      gaps: 0,
      lines: 240,
      request_id: 'req-ghost-baseline-auto-1',
      details: {
        ghost: {
          request_id: 'req-ghost-baseline-auto-1',
          status: 'GHOST_BASELINE',
          action: 'baseline',
          baseline: ghostBaseline,
        },
      },
    },
    {
      id: ghostReceiptsId,
      timestamp: '2026-04-20 09:20:00',
      file: 'sample.log',
      mode: 'ghost',
      status: 'GHOST_RECEIPTS',
      gaps: 0,
      lines: 8,
      request_id: 'req-ghost-receipts-auto-1',
      details: {
        ghost: {
          request_id: 'req-ghost-receipts-auto-1',
          status: 'GHOST_RECEIPTS',
          action: 'receipts',
          receipts: ghostReceipts,
        },
      },
    },
    {
      id: verifyId,
      timestamp: '2026-04-20 09:10:00',
      file: 'sample.log',
      mode: 'verify',
      status: 'TAMPERED',
      gaps: 0,
      lines: 9,
      request_id: 'req-verify-auto-1',
      details: {
        verify: {
          request_id: 'req-verify-auto-1',
          status: 'TAMPERED',
          report: verifyReport,
        },
      },
    },
    {
      id: signId,
      timestamp: '2026-04-20 09:00:00',
      file: 'sample.log',
      mode: 'sign',
      status: 'SIGNED',
      gaps: 0,
      lines: 8,
      request_id: 'req-sign-auto-1',
      details: {
        sign: {
          request_id: 'req-sign-auto-1',
          rootHash: signManifest.root_hash,
          manifest: signManifest,
        },
      },
    },
    {
      id: scanId,
      timestamp: '2026-04-20 08:50:00',
      file: 'sample.log',
      mode: 'scan',
      status: 'GAPS_FOUND',
      gaps: 2,
      lines: 8,
      request_id: 'req-scan-auto-1',
      details: scanDetails,
    },
  ];

  const baselineCollections = [
    {
      id: 'collection-prod-nginx',
      name: 'Prod nginx',
      description: 'Auto-generated collection for the release capture proof pack.',
      createdAt: '2026-04-20T00:00:00Z',
      updatedAt: '2026-04-20T00:10:00Z',
      baselineIds: [ghostBaselineId],
    },
  ];

  return { records, baselineCollections };
}

async function main() {
  const outDir = path.resolve(DEFAULT_OUT_DIR);
  const screenshotsDir = path.join(outDir, 'screenshots');
  await mkdir(screenshotsDir, { recursive: true });

  const health = await fetch(`${DEFAULT_BASE_URL}/api/health`).catch(() => null);
  if (!health || !health.ok) {
    throw new Error(`Backend/proxy not reachable at ${DEFAULT_BASE_URL}`);
  }

  const { records, baselineCollections } = seedHistory();
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1600 }, colorScheme: 'dark' });

  await context.addInitScript(({ records: seededRecords, baselineCollections: seededCollections }) => {
    localStorage.setItem('evidenceProtector.history.v1', JSON.stringify(seededRecords));
    localStorage.setItem('evidenceProtector.baselineCollections.v1', JSON.stringify(seededCollections));
    localStorage.setItem('evidenceProtector.guide.dismissed.v1', '0');
    localStorage.setItem('evidenceProtector.releaseEvidence.captured.v1', JSON.stringify({}));
  }, { records, baselineCollections });

  const page = await context.newPage();

  const screenshots = [
    { name: 'dashboard', route: '/' },
    { name: 'history', route: '/history' },
    { name: 'latest-report', route: `/results/${records[0].id}` },
    { name: 'baselines', route: '/baselines' },
    { name: 'compare', route: '/compare' },
    { name: 'guide', route: '/guide' },
    { name: 'release-evidence', route: '/release-evidence' },
  ];

  const manifest = {
    createdAt: nowIso(),
    baseUrl: DEFAULT_BASE_URL,
    outDir,
    screenshots: [],
  };

  for (const shot of screenshots) {
    await page.goto(`${DEFAULT_BASE_URL}${shot.route}`, { waitUntil: 'networkidle' });
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(750);
    await page.evaluate(() => window.scrollTo(0, 0));

    const filePath = path.join(screenshotsDir, `${shot.name}.png`);
    await page.screenshot({ path: filePath, fullPage: true });
    const buffer = await readFile(filePath);
    manifest.screenshots.push({
      name: shot.name,
      route: shot.route,
      file: path.relative(outDir, filePath),
      sha256: sha256FileFromBuffer(buffer),
      bytes: buffer.length,
    });
  }

  const checklist = [
    '# Automated Release Evidence Capture',
    '',
    `- Created at: ${manifest.createdAt}`,
    `- Base URL: ${manifest.baseUrl}`,
    '',
    '## Screenshots',
    ...manifest.screenshots.map((item) => `- [x] ${item.name} (${item.route}) -> ${item.file}`),
    '',
    '## Seeded records',
    ...records.map((record) => `- ${record.timestamp} | ${record.mode} | ${record.status} | ${record.file}`),
    '',
    '## Baseline collections',
    ...baselineCollections.map((collection) => `- ${collection.name} (${collection.baselineIds.length} baseline(s))`),
    '',
  ].join('\n');

  await writeFile(path.join(outDir, 'release-evidence-manifest.json'), stringify(manifest), 'utf-8');
  await writeFile(path.join(outDir, 'release-evidence-checklist.md'), `${checklist}\n`, 'utf-8');

  await browser.close();

  // eslint-disable-next-line no-console
  console.log(`Wrote screenshots and evidence pack to ${outDir}`);
}

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error?.stack || error?.message || String(error));
  process.exit(1);
});
