export type HistoryMode = 'scan' | 'sign' | 'verify' | 'ghost';

export type HistoryStatus =
  | 'CLEAN'
  | 'SIGNED'
  | 'TAMPERED'
  | 'GAPS_FOUND'
  | 'NO_TIMESTAMPS'
  | 'GHOST_CLEAN'
  | 'GHOST_SIGNALS'
  | 'GHOST_BASELINE'
  | 'GHOST_RECEIPTS'
  | 'ERROR';

export type GhostEvent = {
  signal_type?: string;
  severity?: string;
  message?: string;
  at?: string;
  line_start?: number;
  line_end?: number;
  evidence?: unknown;
};

export type GhostReport = {
  version?: number;
  source_file_name?: string;
  created_at?: string;
  baseline_used?: boolean;
  summary?: Record<string, unknown>;
  events?: GhostEvent[];
  config?: Record<string, unknown>;
};

export type GhostBaseline = {
  version?: number;
  created_at?: string;
  source_hint?: string;
  total_lines?: number;
  timestamps_found?: number;
  malformed_lines?: number;
  entropy_mean?: number;
  entropy_stdev?: number;
  interval_mean?: number;
  interval_stdev?: number;
  char_prob?: number[];
  source_file_name?: string;
};

export type GhostReceiptEnvelope = {
  version?: number;
  created_at?: string;
  kind?: string;
  host?: Record<string, unknown>;
  data?: Record<string, unknown>;
};

export type ScanGap = {
  gap_index?: number;
  gap_start?: string;
  gap_end?: string;
  duration_seconds?: number;
  line_start?: number;
  line_end?: number;
  note?: string | null;
};

export type ScanStats = {
  file?: string;
  total_lines?: number;
  malformed_lines?: number;
  timestamps_found?: number;
  threshold_seconds?: number;
  gaps_found?: number;
};

export type VerifyIssue = {
  line_number?: number;
  expected_chain_hash?: string;
  actual_chain_hash?: string;
  status?: string;
  note?: string;
};

export type ManifestSignature = {
  scheme?: string;
  key_id?: string;
  value?: string;
};

export type ManifestSignatureStatus = {
  present?: boolean;
  scheme?: string;
  key_id?: string;
  valid?: boolean;
  reason?: string;
};

export type VerifyReport = {
  file?: string;
  manifest?: string;
  signed_at?: string;
  verified_at?: string;
  clean?: boolean;
  issues_found?: number;
  issues?: VerifyIssue[];
  manifest_total_lines?: number;
  current_total_lines?: number;
  manifest_root_hash?: string;
  current_root_hash?: string;
  manifest_signature?: ManifestSignatureStatus;
  manifest_mode?: string;
  chain_scheme?: string;
  hash_algorithm?: string;
};

export type SignManifestSummary = {
  file?: string;
  signed_at?: string;
  hash_algorithm?: string;
  chain_scheme?: string;
  manifest_mode?: string;
  checkpoint_every?: number;
  checkpoint_count?: number;
  entry_count?: number;
  total_lines?: number;
  root_hash?: string;
  signature?: ManifestSignature;
};

export type HistoryRecord = {
  id: string;
  timestamp: string; // Display timestamp, e.g. "2026-04-11 14:32:18"
  file: string;
  mode: HistoryMode;
  status: HistoryStatus;
  gaps: number;
  lines: number;
  request_id?: string;
  details?: {
    scan?: {
      request_id?: string;
      gapThreshold?: number;
      outputFormat?: string;
      stats?: ScanStats;
      gaps?: ScanGap[];
      outputText?: string;
    };
    sign?: {
      request_id?: string;
      rootHash?: string;
      manifest?: SignManifestSummary;
      outputText?: string;
    };
    verify?: {
      request_id?: string;
      status?: HistoryStatus;
      report?: VerifyReport;
      outputText?: string;
    };
    ghost?: {
      request_id?: string;
      status?: HistoryStatus;
      action?: 'analyze' | 'baseline' | 'receipts' | 'correlate';
      report?: GhostReport;
      baseline?: GhostBaseline;
      receipts?: GhostReceiptEnvelope[];
      outputText?: string;
    };
  };
};

export const HISTORY_UPDATED_EVENT = 'evidenceProtector:historyUpdated';

export type HistoryUpdatedDetail = {
  records: HistoryRecord[];
  updatedAt: string;
};

const STORAGE_KEY = 'evidenceProtector.history.v1';
const MAX_RECORDS = 200;

function emitHistoryUpdated(records: HistoryRecord[]) {
  try {
    if (typeof window === 'undefined') return;
    const detail: HistoryUpdatedDetail = { records, updatedAt: new Date().toISOString() };
    window.dispatchEvent(new CustomEvent<HistoryUpdatedDetail>(HISTORY_UPDATED_EVENT, { detail }));
  } catch {
    // Best-effort only.
  }
}

export function formatTimestamp(date: Date): string {
  const pad2 = (value: number) => String(value).padStart(2, '0');
  const yyyy = date.getFullYear();
  const mm = pad2(date.getMonth() + 1);
  const dd = pad2(date.getDate());
  const hh = pad2(date.getHours());
  const min = pad2(date.getMinutes());
  const ss = pad2(date.getSeconds());
  return `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;
}

export function newHistoryId(): string {
  try {
    // Most modern browsers.
    return crypto.randomUUID();
  } catch {
    return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }
}

function safeParseRecords(raw: string | null): HistoryRecord[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((r) => r && typeof r === 'object') as HistoryRecord[];
  } catch {
    return [];
  }
}

export function getHistoryRecords(): HistoryRecord[] {
  try {
    return safeParseRecords(localStorage.getItem(STORAGE_KEY));
  } catch {
    return [];
  }
}

function saveHistoryRecords(records: HistoryRecord[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(records.slice(0, MAX_RECORDS)));
  } catch {
    // Best-effort only.
  }
}

export function addHistoryRecord(record: HistoryRecord): HistoryRecord[] {
  const existing = getHistoryRecords();
  const next = [record, ...existing].slice(0, MAX_RECORDS);
  saveHistoryRecords(next);
  emitHistoryUpdated(next);
  return next;
}

export function deleteHistoryRecord(id: string): HistoryRecord[] {
  const existing = getHistoryRecords();
  const next = existing.filter((r) => r.id !== id);
  saveHistoryRecords(next);
  emitHistoryUpdated(next);
  return next;
}

export function getHistoryRecordById(id: string): HistoryRecord | undefined {
  const existing = getHistoryRecords();
  return existing.find((r) => r.id === id);
}
