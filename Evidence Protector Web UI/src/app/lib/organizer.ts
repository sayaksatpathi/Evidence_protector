import { formatTimestamp, getHistoryRecords, type HistoryRecord } from './history';

export type BaselineRecord = {
  id: string;
  file: string;
  timestamp: string;
  sourceLabel: string;
  lines: number;
  totalLines: number;
  timestampsFound: number;
  malformedLines: number;
  entropyMean?: number;
  entropyStdev?: number;
  intervalMean?: number;
  intervalStdev?: number;
};

export type BaselineCollection = {
  id: string;
  name: string;
  description: string;
  createdAt: string;
  updatedAt: string;
  baselineIds: string[];
};

export type ReleaseEvidencePack = {
  createdAt: string;
  appVersion: string;
  currentPath: string;
  historyCount: number;
  baselineCount: number;
  collectionsCount: number;
  recentHistory: Array<{
    id: string;
    timestamp: string;
    file: string;
    mode: string;
    status: string;
  }>;
  baselineCollections: BaselineCollection[];
  requiredScreenshots: Array<{
    name: string;
    description: string;
    captured: boolean;
  }>;
};

const BASELINE_COLLECTIONS_KEY = 'evidenceProtector.baselineCollections.v1';
const GUIDE_DISMISSED_KEY = 'evidenceProtector.guide.dismissed.v1';

export function getGhostBaselineRecords(records: HistoryRecord[] = getHistoryRecords()): BaselineRecord[] {
  return records
    .filter((record) => record.mode === 'ghost' && record.details?.ghost?.action === 'baseline' && record.details?.ghost?.baseline)
    .map((record) => {
      const baseline = record.details?.ghost?.baseline ?? {};
      const sourceLabel = String(baseline?.source_hint ?? record.file ?? 'baseline');
      const lines = Number(record.lines ?? baseline?.total_lines ?? 0);
      return {
        id: record.id,
        file: record.file,
        timestamp: record.timestamp,
        sourceLabel,
        lines,
        totalLines: Number(baseline?.total_lines ?? lines),
        timestampsFound: Number(baseline?.timestamps_found ?? 0),
        malformedLines: Number(baseline?.malformed_lines ?? 0),
        entropyMean: typeof baseline?.entropy_mean === 'number' ? Number(baseline.entropy_mean) : undefined,
        entropyStdev: typeof baseline?.entropy_stdev === 'number' ? Number(baseline.entropy_stdev) : undefined,
        intervalMean: typeof baseline?.interval_mean === 'number' ? Number(baseline.interval_mean) : undefined,
        intervalStdev: typeof baseline?.interval_stdev === 'number' ? Number(baseline.interval_stdev) : undefined,
      };
    });
}

function safeParseCollections(raw: string | null): BaselineCollection[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item) => item && typeof item === 'object') as BaselineCollection[];
  } catch {
    return [];
  }
}

function readCollections(): BaselineCollection[] {
  try {
    return safeParseCollections(localStorage.getItem(BASELINE_COLLECTIONS_KEY));
  } catch {
    return [];
  }
}

function saveCollections(collections: BaselineCollection[]) {
  try {
    localStorage.setItem(BASELINE_COLLECTIONS_KEY, JSON.stringify(collections.slice(0, 100)));
  } catch {
    // Best effort only.
  }
}

export function getBaselineCollections(): BaselineCollection[] {
  return readCollections();
}

export function getBaselineCollectionById(id: string): BaselineCollection | undefined {
  return readCollections().find((collection) => collection.id === id);
}

export function upsertBaselineCollection(input: {
  id?: string;
  name: string;
  description?: string;
  baselineIds?: string[];
}): BaselineCollection[] {
  const now = new Date().toISOString();
  const existing = readCollections();
  const id = input.id || `baseline-collection-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const nextItem: BaselineCollection = {
    id,
    name: input.name.trim() || 'Untitled collection',
    description: input.description?.trim() || '',
    createdAt: existing.find((item) => item.id === id)?.createdAt || now,
    updatedAt: now,
    baselineIds: Array.from(new Set(input.baselineIds ?? existing.find((item) => item.id === id)?.baselineIds ?? [])),
  };
  const next = [nextItem, ...existing.filter((item) => item.id !== id)];
  saveCollections(next);
  return next;
}

export function deleteBaselineCollection(id: string): BaselineCollection[] {
  const next = readCollections().filter((collection) => collection.id !== id);
  saveCollections(next);
  return next;
}

export function toggleBaselineInCollection(collectionId: string, baselineId: string): BaselineCollection[] {
  const existing = readCollections();
  const next = existing.map((collection) => {
    if (collection.id !== collectionId) return collection;
    const has = collection.baselineIds.includes(baselineId);
    return {
      ...collection,
      updatedAt: new Date().toISOString(),
      baselineIds: has
        ? collection.baselineIds.filter((id) => id !== baselineId)
        : [baselineId, ...collection.baselineIds],
    };
  });
  saveCollections(next);
  return next;
}

export function addBaselineCollection(baselineId: string, name?: string) {
  const now = new Date().toISOString();
  const next = [
    {
      id: `baseline-collection-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      name: name || `Collection ${formatTimestamp(new Date()).replace(' ', ' ')}`,
      description: '',
      createdAt: now,
      updatedAt: now,
      baselineIds: [baselineId],
    },
    ...readCollections(),
  ];
  saveCollections(next);
  return next;
}

export function createBaselineCollection(input: {
  name: string;
  description?: string;
  baselineIds: string[];
}) {
  return upsertBaselineCollection({
    name: input.name,
    description: input.description,
    baselineIds: input.baselineIds,
  });
}

export function getGuideDismissed(): boolean {
  try {
    return localStorage.getItem(GUIDE_DISMISSED_KEY) === '1';
  } catch {
    return false;
  }
}

export function setGuideDismissed(dismissed: boolean) {
  try {
    localStorage.setItem(GUIDE_DISMISSED_KEY, dismissed ? '1' : '0');
  } catch {
    // Best effort only.
  }
}

export function buildReleaseEvidencePack(): ReleaseEvidencePack {
  const records = getHistoryRecords();
  const collections = getBaselineCollections();
  return {
    createdAt: new Date().toISOString(),
    appVersion: 'v2.4.1',
    currentPath: typeof window !== 'undefined' ? window.location.pathname : '/',
    historyCount: records.length,
    baselineCount: getGhostBaselineRecords(records).length,
    collectionsCount: collections.length,
    recentHistory: records.slice(0, 8).map((record) => ({
      id: record.id,
      timestamp: record.timestamp,
      file: record.file,
      mode: record.mode,
      status: record.status,
    })),
    baselineCollections: collections,
    requiredScreenshots: [
      {
        name: 'dashboard-health',
        description: 'Dashboard showing API settings and recent activity',
        captured: false,
      },
      {
        name: 'scan-results',
        description: 'Scan or verify report page showing a real result',
        captured: false,
      },
      {
        name: 'baseline-organizer',
        description: 'Baseline organizer page with a named collection',
        captured: false,
      },
      {
        name: 'compare-view',
        description: 'Report comparison view with two selected records',
        captured: false,
      },
    ],
  };
}

export function buildReleaseEvidenceMarkdown(pack: ReleaseEvidencePack): string {
  const lines: string[] = [];
  lines.push('# Evidence Protector Release Evidence Pack');
  lines.push('');
  lines.push(`- Created at: ${pack.createdAt}`);
  lines.push(`- App version: ${pack.appVersion}`);
  lines.push(`- Current path: ${pack.currentPath}`);
  lines.push(`- History records: ${pack.historyCount}`);
  lines.push(`- Baseline records: ${pack.baselineCount}`);
  lines.push(`- Baseline collections: ${pack.collectionsCount}`);
  lines.push('');
  lines.push('## Required screenshots');
  for (const shot of pack.requiredScreenshots) {
    lines.push(`- [ ] ${shot.name}: ${shot.description}`);
  }
  lines.push('');
  lines.push('## Recent history');
  for (const item of pack.recentHistory) {
    lines.push(`- ${item.timestamp} | ${item.mode} | ${item.status} | ${item.file}`);
  }
  lines.push('');
  lines.push('## Baseline collections');
  if (!pack.baselineCollections.length) {
    lines.push('- None yet');
  } else {
    for (const c of pack.baselineCollections) {
      lines.push(`- ${c.name} (${c.baselineIds.length} baseline(s))`);
    }
  }
  lines.push('');
  lines.push('## Capture guidance');
  lines.push('- Capture the dashboard after health checks are green.');
  lines.push('- Capture a report page with a real result.');
  lines.push('- Capture the baseline organizer after naming a collection.');
  lines.push('- Capture the compare view after selecting two reports.');
  lines.push('- Keep the JSON pack together with the screenshots in the release folder.');
  return `${lines.join('\n')}\n`;
}
