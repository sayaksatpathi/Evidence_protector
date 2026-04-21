import { useEffect, useState } from 'react';
import { FileDropzone } from '../components/FileDropzone';
import { TerminalOutput } from '../components/TerminalOutput';
import { Play, FileText, Download, Binary, Fingerprint, Search, Shield } from 'lucide-react';
import { sha256 } from '@noble/hashes/sha256';
import { sha1 } from '@noble/hashes/sha1';
import { md5 } from '@noble/hashes/legacy';
import { addHistoryRecord, formatTimestamp, newHistoryId, type HistoryStatus } from '../lib/history';
import {
  type ApiMode,
  fetchApiJson,
  formatApiErrorMessage,
  getApiHeaders,
  isApiOkWithMode,
  isHealthResponse,
} from '../lib/apiClient';

const PREF_KEY_MODE = 'evidenceProtector.ui.scan.mode.v1';
const PREF_KEY_GAP = 'evidenceProtector.ui.scan.gapThreshold.v1';
const PREF_KEY_OUTPUT = 'evidenceProtector.ui.scan.outputFormat.v1';
const PREF_KEY_SIGN_MANIFEST_MODE = 'evidenceProtector.ui.sign.manifestMode.v1';
const PREF_KEY_SIGN_CHECKPOINT_EVERY = 'evidenceProtector.ui.sign.checkpointEvery.v1';
const PREF_KEY_SIGN_CHAIN_SCHEME = 'evidenceProtector.ui.sign.chainScheme.v1';
const PREF_KEY_LOCAL_RULES = 'evidenceProtector.ui.localRules.v1';

const MAX_LOG_BYTES = 50 * 1024 * 1024; // 50 MB
const MAX_MANIFEST_BYTES = 5 * 1024 * 1024; // 5 MB
const MAX_GHOST_BASELINE_BYTES = 5 * 1024 * 1024; // 5 MB
const MAX_GHOST_CORRELATE_BYTES = 5 * 1024 * 1024; // 5 MB
const MAX_TERMINAL_LINES = 1000;

const LOCAL_FORENSICS_SAMPLE_BYTES = 1024 * 1024; // 1 MB
const LOCAL_FORENSICS_HEX_BYTES = 256;
const LOCAL_FORENSICS_MAX_TEXT_BYTES = 256 * 1024; // 256 KB
const ENTROPY_WINDOW_BYTES = 4096;
const ENTROPY_STEP_BYTES = 2048;
const ENTROPY_MAX_WINDOWS = 140;

const FULL_ANALYSIS_DEBOUNCE_MS = 700;
const FULL_STREAM_CHUNK_BYTES = 256 * 1024;
const FULL_ENTROPY_MAX_BINS = 240;
const FULL_ENTROPY_MIN_BIN_BYTES = 4096;
const FULL_ENTROPY_MAX_BIN_BYTES = 256 * 1024;
const TIMELINE_BUCKET_MS = 60 * 1000; // 1 minute
const TIMELINE_MAX_BUCKETS = 5000;
const FULL_TEXT_MAX_LINES = 250_000;
const FULL_RULES_UI_TOP_N = 8;
const ASYNC_SCAN_THRESHOLD_BYTES = 5 * 1024 * 1024; // 5 MB
const ASYNC_SCAN_POLL_MS = 750;
const ASYNC_SCAN_TIMEOUT_MS = 2 * 60 * 1000;

const DEFAULT_LOCAL_RULES = `# One rule per line: [SEVERITY:] keyword OR [SEVERITY:] /regex/flags
# Examples:
# HIGH: failed login
# MEDIUM: /unauthori[sz]ed/i
# /token\s*[:=]\s*[^\s"']+/i

HIGH: failed login
MEDIUM: unauthorized
MEDIUM: forbidden
MEDIUM: exception
HIGH: traceback
HIGH: token
HIGH: api key
CRITICAL: password
CRITICAL: secret
CRITICAL: /\b(mimikatz|powershell\s+-enc|certutil\s+-urlcache|whoami|net\s+user)\b/i
CRITICAL: /\b(ssh-rsa|BEGIN\s+RSA\s+PRIVATE\s+KEY|BEGIN\s+OPENSSH\s+PRIVATE\s+KEY)\b/i
`;

type LocalForensicsStatus = 'idle' | 'running' | 'ready' | 'error';

type RuleSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

type LocalForensics = {
  status: LocalForensicsStatus;
  error?: string;
  sampleBytes: number;
  totalBytes: number;
  sampleText?: string;
  sampleTextTruncated?: boolean;
  entropyBitsPerByte?: number;
  entropyWindows?: number[];
  printableRatio?: number;
  likelyType?: string;
  signature?: string;
  sha256Hex?: string;
  sha256Scope?: 'sample' | 'full';
  lineEndings?: { crlf: number; lf: number; cr: number };
  linesInSample?: number;
  timestampHits?: number;
  iocs?: {
    ipv4: { count: number; examples: string[] };
    urls: { count: number; examples: string[] };
    emails: { count: number; examples: string[] };
    sha256: { count: number; examples: string[] };
    md5: { count: number; examples: string[] };
  };
  hexPreview?: string;
  suspicion?: {
    score: number;
    level: 'LOW' | 'MEDIUM' | 'HIGH';
    reasons: string[];
  };
};

type RuleDef = {
  id: string;
  label: string;
  regex: RegExp;
  severity: RuleSeverity;
};

type RuleMatch = {
  id: string;
  label: string;
  severity: RuleSeverity;
  count: number;
  examples: string[];
  hits?: Array<{ line: number; text: string }>;
};

type FullAnalysisStatus = 'idle' | 'running' | 'ready' | 'error';

type FullAnalysis = {
  status: FullAnalysisStatus;
  error?: string;
  bytesRead: number;
  totalBytes: number;
  progressPct: number;
  sha256Hex?: string;
  sha1Hex?: string;
  md5Hex?: string;
  entropyBinBytes?: number;
  entropyBins?: number[];
  rules?: {
    errors: string[];
    scannedLines: number;
    truncated: boolean;
    matches: RuleMatch[];
    severityCounts: Record<RuleSeverity, number>;
  };
  timeline?: {
    bucketMs: number;
    buckets: Array<{ t: number; count: number }>;
    parsedEvents: number;
    parsedLines: number;
    gapCount: number;
    maxGapSeconds: number;
    burstBuckets: number;
    gapBuckets: number;
  };
};

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  const mb = bytes / (1024 * 1024);
  if (mb >= 1) return `${mb.toFixed(2)} MB`;
  const kb = bytes / 1024;
  return `${kb.toFixed(2)} KB`;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

function computeEntropyBitsPerByte(bytes: Uint8Array): number {
  if (!bytes.length) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
  let entropy = 0;
  const n = bytes.length;
  for (let b = 0; b < 256; b++) {
    const c = counts[b];
    if (!c) continue;
    const p = c / n;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function computeEntropyWindows(bytes: Uint8Array): number[] {
  if (!bytes.length) return [];
  const windowSize = Math.max(256, ENTROPY_WINDOW_BYTES);
  let step = Math.max(128, ENTROPY_STEP_BYTES);

  const maxStart = Math.max(0, bytes.length - Math.min(bytes.length, windowSize));
  let windows = Math.floor(maxStart / step) + 1;
  if (windows > ENTROPY_MAX_WINDOWS) {
    step = Math.max(128, Math.ceil(maxStart / ENTROPY_MAX_WINDOWS));
    windows = Math.floor(maxStart / step) + 1;
  }

  const out: number[] = [];
  for (let offset = 0; offset <= maxStart && out.length < ENTROPY_MAX_WINDOWS; offset += step) {
    const end = Math.min(bytes.length, offset + windowSize);
    const slice = bytes.slice(offset, end);
    out.push(computeEntropyBitsPerByte(slice));
  }
  return out;
}

function computePrintableRatio(bytes: Uint8Array): number {
  if (!bytes.length) return 0;
  let printable = 0;
  for (let i = 0; i < bytes.length; i++) {
    const v = bytes[i];
    // ASCII printable + whitespace (tab/lf/cr)
    if ((v >= 0x20 && v <= 0x7e) || v === 0x09 || v === 0x0a || v === 0x0d) printable++;
  }
  return printable / bytes.length;
}

function detectSignature(bytes: Uint8Array): string {
  const b = bytes;
  const hex8 = (i: number) => (b[i] ?? 0).toString(16).padStart(2, '0');
  const startsWith = (arr: number[]) => arr.every((v, i) => b[i] === v);
  if (startsWith([0x1f, 0x8b])) return 'GZIP (1F 8B)';
  if (startsWith([0x50, 0x4b, 0x03, 0x04])) return 'ZIP (PK\\x03\\x04)';
  if (startsWith([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'PNG';
  if (startsWith([0x25, 0x50, 0x44, 0x46])) return 'PDF';
  if (startsWith([0xef, 0xbb, 0xbf])) return 'UTF-8 BOM';
  if (startsWith([0xff, 0xfe])) return 'UTF-16 LE BOM';
  if (startsWith([0xfe, 0xff])) return 'UTF-16 BE BOM';
  if (b.length >= 4 && hex8(0) === '7b' && hex8(1) === '22') return 'JSON-like ({")';
  if (b.length >= 5 && bytesToHex(b.slice(0, 5)) === '3c3f786d6c') return 'XML (<?xml)';
  return 'Unknown / Plaintext';
}

function inferLikelyType(extLower: string, printableRatio: number, entropyBitsPerByte: number): string {
  if (extLower === '.log' || extLower === '.txt') {
    if (printableRatio >= 0.85 && entropyBitsPerByte < 6.6) return 'Text log (likely)';
    if (entropyBitsPerByte >= 7.5) return 'High-entropy data (compressed/encrypted?)';
    return 'Mixed/structured text';
  }
  if (printableRatio >= 0.9) return 'Plaintext';
  if (entropyBitsPerByte >= 7.5) return 'Compressed/encrypted binary (likely)';
  return 'Binary/unknown';
}

function makeHexPreview(bytes: Uint8Array, maxBytes: number): string {
  const n = Math.min(bytes.length, maxBytes);
  const width = 16;
  const lines: string[] = [];
  for (let offset = 0; offset < n; offset += width) {
    const chunk = bytes.slice(offset, Math.min(offset + width, n));
    const hex = Array.from(chunk)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(' ');
    const pad = '   '.repeat(width - chunk.length);
    const ascii = Array.from(chunk)
      .map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.'))
      .join('');
    lines.push(`${offset.toString(16).padStart(8, '0')}  ${hex}${pad}  |${ascii.padEnd(width, ' ')}|`);
  }
  return lines.join('\n');
}

function countLineEndings(text: string): { crlf: number; lf: number; cr: number } {
  let crlf = 0;
  let lf = 0;
  let cr = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 13) {
      if (text.charCodeAt(i + 1) === 10) {
        crlf++;
        i++;
      } else {
        cr++;
      }
      continue;
    }
    if (c === 10) lf++;
  }
  return { crlf, lf, cr };
}

function uniqExamples(matches: Iterable<string>, max: number): { count: number; examples: string[] } {
  const set = new Set<string>();
  for (const m of matches) {
    if (!m) continue;

    if (set.size < max) set.add(m);
    else set.add(m);
  }
  const examples = Array.from(set).slice(0, max);
  return { count: set.size, examples };
}

function extractIocs(text: string) {
  const ipv4Re = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
  const urlRe = /\bhttps?:\/\/[^\s'"<>]+/g;
  const emailRe = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
  const sha256Re = /\b[a-f0-9]{64}\b/gi;
  const md5Re = /\b[a-f0-9]{32}\b/gi;

  return {
    ipv4: uniqExamples(text.match(ipv4Re) ?? [], 5),
    urls: uniqExamples(text.match(urlRe) ?? [], 5),
    emails: uniqExamples(text.match(emailRe) ?? [], 5),
    sha256: uniqExamples(text.match(sha256Re) ?? [], 5),
    md5: uniqExamples(text.match(md5Re) ?? [], 5),
  };
}

function clamp(n: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, n));
}

function computeSuspicionScore(input: {
  entropyBitsPerByte: number;
  printableRatio: number;
  signature: string;
  timestampHits: number;
  lines: number;
  iocCounts: { ips: number; urls: number; emails: number; sha256: number; md5: number };
}): { score: number; level: 'LOW' | 'MEDIUM' | 'HIGH'; reasons: string[] } {
  const reasons: string[] = [];
  let score = 0;

  if (input.entropyBitsPerByte >= 7.6) {
    score += 35;
    reasons.push('High entropy (packed/encrypted-looking sample)');
  } else if (input.entropyBitsPerByte >= 7.0) {
    score += 20;
    reasons.push('Moderate-high entropy');
  } else if (input.entropyBitsPerByte < 5.0) {
    score += 5;
    reasons.push('Low entropy (highly repetitive content)');
  }

  if (input.printableRatio < 0.6) {
    score += 18;
    reasons.push('Low printable ratio (binary-ish content)');
  } else if (input.printableRatio < 0.8) {
    score += 8;
    reasons.push('Mixed printable content');
  }

  if (/ZIP|GZIP/i.test(input.signature)) {
    score += 10;
    reasons.push('Archive/compression signature detected');
  }

  const lines = Math.max(1, input.lines);
  const tsPer100Lines = (input.timestampHits / lines) * 100;
  if (lines >= 50 && tsPer100Lines < 5) {
    score += 12;
    reasons.push('Low timestamp density for a log-like file');
  } else if (tsPer100Lines >= 60) {
    score += 6;
    reasons.push('Very high timestamp density');
  }

  const { ips, urls, emails, sha256, md5 } = input.iocCounts;
  const iocScore = clamp(ips, 0, 10) * 1.5 + clamp(urls, 0, 10) * 2 + clamp(sha256 + md5, 0, 10) * 2;
  if (iocScore >= 18) {
    score += 20;
    reasons.push('High IOC volume in sample');
  } else if (iocScore >= 8) {
    score += 10;
    reasons.push('Some IOCs present in sample');
  }
  if (emails >= 5) {
    score += 4;
    reasons.push('Many email addresses in sample');
  }

  score = clamp(Math.round(score), 0, 100);
  const level = score >= 70 ? 'HIGH' : score >= 35 ? 'MEDIUM' : 'LOW';
  return { score, level, reasons: reasons.length ? reasons : ['No strong heuristics triggered'] };
}

function parseRules(text: string): { rules: RuleDef[]; errors: string[] } {
  const rules: RuleDef[] = [];
  const errors: string[] = [];

  const parseSeverity = (raw: string): { severity: RuleSeverity; rest: string } => {
    const m = /^\s*(LOW|MEDIUM|HIGH|CRITICAL)\s*:\s*(.+)$/i.exec(raw);
    if (!m) return { severity: 'MEDIUM', rest: raw };
    const sev = m[1].toUpperCase() as RuleSeverity;
    return { severity: sev, rest: m[2].trim() };
  };

  const lines = text.split(/\r\n|\n|\r/);
  for (let idx = 0; idx < lines.length; idx++) {
    let line = lines[idx].trim();
    if (!line) continue;
    if (line.startsWith('#')) continue;

    const hashPos = line.indexOf(' #');
    if (hashPos !== -1) line = line.slice(0, hashPos).trim();
    if (!line) continue;

    try {
      const { severity, rest } = parseSeverity(line);
      line = rest;
      if (!line) continue;

      let label = line;
      let regex: RegExp;

      if (line.startsWith('/') && line.lastIndexOf('/') > 0) {
        const lastSlash = line.lastIndexOf('/');
        const pattern = line.slice(1, lastSlash);
        const flagsRaw = line.slice(lastSlash + 1).trim();
        const flags = flagsRaw.replace(/[^gimsuy]/g, '');
        const normalizedFlags = flags.includes('i') ? flags : flags + 'i';
        regex = new RegExp(pattern, normalizedFlags);
        label = `/${pattern}/${normalizedFlags}`;
      } else {
        const escaped = line.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        regex = new RegExp(escaped, 'i');
      }

      const id = `${idx + 1}:${label}`;
      rules.push({ id, label, regex, severity });
    } catch (e: any) {
      errors.push(`Line ${idx + 1}: ${e?.message ?? String(e)}`);
    }
  }

  return { rules, errors };
}

function scanRules(sampleText: string, defs: RuleDef[]): RuleMatch[] {
  const maxLinesToScan = 6000;
  const lines = sampleText.split(/\r\n|\n|\r/).slice(0, maxLinesToScan);
  const results: RuleMatch[] = [];

  for (const def of defs) {
    let count = 0;
    const examples: string[] = [];
    const hits: Array<{ line: number; text: string }> = [];

    const flags = def.regex.flags.replace('g', '');
    const lineRegex = new RegExp(def.regex.source, flags);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line) continue;
      if (lineRegex.test(line)) {
        count++;
        if (examples.length < 3) {
          examples.push(line.length > 220 ? line.slice(0, 220) + '…' : line);
        }
        if (hits.length < 3) {
          hits.push({ line: i + 1, text: line.length > 220 ? line.slice(0, 220) + '…' : line });
        }
      }
    }

    results.push({ id: def.id, label: def.label, severity: def.severity, count, examples, hits });
  }

  results.sort((a, b) => b.count - a.count);
  return results;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return bytesToHex(new Uint8Array(digest));
}

function getFileExtensionLower(name: string): string {
  const idx = name.lastIndexOf('.');
  if (idx === -1) return '';
  return name.slice(idx).toLowerCase();
}

function validateUpload(file: File, opts: { label: string; allowedExts: string[]; maxBytes: number }): string | null {
  const ext = getFileExtensionLower(file.name);
  if (!opts.allowedExts.includes(ext)) {
    return `${opts.label} must be one of: ${opts.allowedExts.join(', ')}`;
  }
  if (file.size > opts.maxBytes) {
    return `${opts.label} is too large (${formatBytes(file.size)}). Max allowed is ${formatBytes(opts.maxBytes)}.`;
  }
  return null;
}

function lastLines(text: string, maxLines: number): { lines: string[]; truncated: boolean } {
  if (!text) return { lines: [], truncated: false };

  const lines: string[] = [];
  let end = text.length;
  let i = text.length - 1;
  let count = 0;

  while (i >= 0 && count < maxLines) {
    if (text[i] === '\n') {
      let line = text.slice(i + 1, end);
      if (line.endsWith('\r')) line = line.slice(0, -1);
      lines.push(line);
      end = i;
      count++;
    }
    i--;
  }

  if (count < maxLines && end > 0) {
    let line = text.slice(0, end);
    if (line.endsWith('\r')) line = line.slice(0, -1);
    lines.push(line);
  }

  lines.reverse();
  return { lines, truncated: i >= 0 };
}

function toTerminalLines(text: string): string[] {
  const { lines, truncated } = lastLines(text.replace(/\r\n/g, '\n'), MAX_TERMINAL_LINES);
  if (!lines.length) return ['(No output)'];
  if (!truncated) return lines;
  return [`[Output truncated: showing last ${MAX_TERMINAL_LINES.toLocaleString()} lines]`, ...lines];
}

function formatGhostTerminalReport(args: {
  fileName: string;
  report: any;
  requestId?: string;
}): string {
  const summary = args?.report?.summary ?? {};
  const riskScore = Number(summary?.risk_score ?? 0);
  const totalEvents =
    Number(summary?.event_counts?.total ?? summary?.event_count ?? 0) ||
    (Array.isArray(args?.report?.events) ? args.report.events.length : 0);
  const baselineUsed = Boolean(args?.report?.baseline_used);
  const analyzedLines = Number(summary?.lines_analyzed ?? summary?.lines_total ?? summary?.total_lines ?? 0);

  const lines: string[] = [];
  lines.push('Ghost Protocol Analysis');
  lines.push('='.repeat(80));
  lines.push(`File: ${args.fileName}`);
  if (args.requestId) lines.push(`Request ID: ${args.requestId}`);
  lines.push(`Baseline used: ${baselineUsed ? 'yes' : 'no'}`);
  if (Number.isFinite(analyzedLines) && analyzedLines > 0) lines.push(`Lines analyzed: ${analyzedLines.toLocaleString()}`);
  lines.push(`Events: ${Number.isFinite(totalEvents) ? totalEvents.toLocaleString() : String(totalEvents)}`);
  lines.push(`Risk score: ${Number.isFinite(riskScore) ? riskScore : 0}`);
  lines.push('');

  const events: any[] = Array.isArray(args?.report?.events) ? args.report.events : [];
  if (events.length) {
    const counts = new Map<string, number>();
    for (const e of events) {
      const k = String(e?.signal_type ?? 'UNKNOWN');
      counts.set(k, (counts.get(k) ?? 0) + 1);
    }
    const top = Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 12);
    lines.push('Top signals:');
    for (const [k, c] of top) lines.push(`- ${k}: ${c}`);
  } else {
    lines.push('No signals emitted.');
  }

  return lines.join('\n') + '\n';
}

function formatGhostBaselineTerminal(args: {
  fileName: string;
  baseline: any;
  requestId?: string;
}): string {
  const b = args?.baseline ?? {};
  const totalLines = Number(b?.total_lines ?? 0);
  const timestampsFound = Number(b?.timestamps_found ?? 0);
  const malformed = Number(b?.malformed_lines ?? 0);

  const lines: string[] = [];
  lines.push('Ghost Protocol Baseline');
  lines.push('='.repeat(80));
  lines.push(`File: ${args.fileName}`);
  if (args.requestId) lines.push(`Request ID: ${args.requestId}`);
  if (b?.created_at) lines.push(`Created at: ${String(b.created_at)}`);
  lines.push(`Total lines: ${Number.isFinite(totalLines) ? totalLines.toLocaleString() : 0}`);
  lines.push(`Timestamps found: ${Number.isFinite(timestampsFound) ? timestampsFound.toLocaleString() : 0}`);
  lines.push(`Malformed lines: ${Number.isFinite(malformed) ? malformed.toLocaleString() : 0}`);
  lines.push('');
  if (typeof b?.entropy_mean === 'number' || typeof b?.entropy_stdev === 'number') {
    lines.push(`Entropy mean/stdev: ${Number(b?.entropy_mean ?? 0).toFixed(4)} / ${Number(b?.entropy_stdev ?? 0).toFixed(4)}`);
  }
  if (typeof b?.interval_mean === 'number' || typeof b?.interval_stdev === 'number') {
    lines.push(`Interval mean/stdev: ${Number(b?.interval_mean ?? 0).toFixed(4)} / ${Number(b?.interval_stdev ?? 0).toFixed(4)}`);
  }
  return lines.join('\n') + '\n';
}

function formatGhostReceiptsTerminal(args: {
  fileName: string;
  receipts: any[];
  requestId?: string;
}): string {
  const receipts: any[] = Array.isArray(args?.receipts) ? args.receipts : [];
  const counts = new Map<string, number>();
  for (const r of receipts) {
    const k = String(r?.kind ?? 'UNKNOWN');
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }

  const lines: string[] = [];
  lines.push('Ghost Protocol Receipts');
  lines.push('='.repeat(80));
  lines.push(`File: ${args.fileName}`);
  if (args.requestId) lines.push(`Request ID: ${args.requestId}`);
  lines.push(`Receipt items: ${receipts.length.toLocaleString()}`);
  lines.push('');

  const kinds = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  if (kinds.length) {
    lines.push('Kinds:');
    for (const [k, c] of kinds) lines.push(`- ${k}: ${c}`);
  } else {
    lines.push('No receipt items.');
  }

  const file = receipts.find((r) => String(r?.kind ?? '') === 'FILE');
  const data = file?.data;
  if (data && typeof data === 'object') {
    const size = Number((data as any)?.size_bytes ?? 0);
    lines.push('');
    lines.push('File snapshot:');
    if ((data as any)?.path) lines.push(`- path: ${String((data as any).path)}`);
    if (Number.isFinite(size) && size > 0) lines.push(`- size_bytes: ${size.toLocaleString()}`);
    if ((data as any)?.mtime_epoch) lines.push(`- mtime_epoch: ${String((data as any).mtime_epoch)}`);
    if ((data as any)?.head_sha256) lines.push(`- head_sha256: ${String((data as any).head_sha256).slice(0, 16)}…`);
    if ((data as any)?.tail_sha256) lines.push(`- tail_sha256: ${String((data as any).tail_sha256).slice(0, 16)}…`);
  }

  return lines.join('\n') + '\n';
}

function serializeLocalForensics(input: LocalForensics) {
  return {
    status: input.status,
    sampleBytes: input.sampleBytes,
    totalBytes: input.totalBytes,
    signature: input.signature,
    likelyType: input.likelyType,
    entropyBitsPerByte: input.entropyBitsPerByte,
    entropyWindows: input.entropyWindows,
    printableRatio: input.printableRatio,
    sha256: input.sha256Hex ? { hex: input.sha256Hex, scope: input.sha256Scope } : undefined,
    linesInSample: input.linesInSample,
    timestampHits: input.timestampHits,
    lineEndings: input.lineEndings,
    iocs: input.iocs,
    suspicion: input.suspicion,
  };
}

function serializeFullAnalysis(input: FullAnalysis) {
  if (!input || input.status === 'idle') return { status: 'idle' as const };
  if (input.status === 'error') return { status: 'error' as const, error: input.error };

  return {
    status: input.status,
    progressPct: input.progressPct,
    bytesRead: input.bytesRead,
    totalBytes: input.totalBytes,
    hashes: {
      sha256: input.sha256Hex,
      sha1: input.sha1Hex,
      md5: input.md5Hex,
    },
    entropy: {
      binBytes: input.entropyBinBytes,
      bins: input.entropyBins,
    },
    rules: input.rules
      ? {
          errors: input.rules.errors,
          scannedLines: input.rules.scannedLines,
          truncated: input.rules.truncated,
          severityCounts: input.rules.severityCounts,
          matches: input.rules.matches.slice(0, 50),
        }
      : undefined,
    timeline: input.timeline,
  };
}

export function Scan() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [manifestFile, setManifestFile] = useState<File | null>(null);
  const [ghostBaselineFile, setGhostBaselineFile] = useState<File | null>(null);
  const [ghostOperation, setGhostOperation] = useState<'analyze' | 'baseline' | 'receipts' | 'correlate'>('analyze');
  const [ghostReceiptsIncludeProcesses, setGhostReceiptsIncludeProcesses] = useState(false);
  const [ghostReceiptsIncludeNetstat, setGhostReceiptsIncludeNetstat] = useState(false);
  const [ghostReceiptsIncludeSamples, setGhostReceiptsIncludeSamples] = useState(true);
  const [ghostLastReport, setGhostLastReport] = useState<any | null>(null);
  const [ghostLastReceipts, setGhostLastReceipts] = useState<any[] | null>(null);
  const [ghostCorrelateReportFile, setGhostCorrelateReportFile] = useState<File | null>(null);
  const [ghostCorrelateReceiptsFile, setGhostCorrelateReceiptsFile] = useState<File | null>(null);
  const [gapThreshold, setGapThreshold] = useState('300');
  const [outputFormat, setOutputFormat] = useState<'terminal' | 'csv' | 'json'>('terminal');
  const [mode, setMode] = useState<'scan' | 'sign' | 'verify' | 'ghost'>('scan');
  const [signManifestMode, setSignManifestMode] = useState<'full' | 'compact'>('full');
  const [signCheckpointEvery, setSignCheckpointEvery] = useState('1000');
  const [signChainScheme, setSignChainScheme] = useState<'v1-line+prev' | 'v2-prev+lineno+line'>('v1-line+prev');
  const [isRunning, setIsRunning] = useState(false);
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
  const [download, setDownload] = useState<{ filename: string; text: string; mime: string } | null>(null);
  const [apiDown, setApiDown] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);
  const [manifestError, setManifestError] = useState<string | null>(null);
  const [ghostBaselineError, setGhostBaselineError] = useState<string | null>(null);
  const [ghostCorrelateReportError, setGhostCorrelateReportError] = useState<string | null>(null);
  const [ghostCorrelateReceiptsError, setGhostCorrelateReceiptsError] = useState<string | null>(null);
  const [gapError, setGapError] = useState<string | null>(null);
  const [localForensics, setLocalForensics] = useState<LocalForensics>({
    status: 'idle',
    sampleBytes: 0,
    totalBytes: 0,
  });
  const [localRulesText, setLocalRulesText] = useState(DEFAULT_LOCAL_RULES);
  const [localRulesErrors, setLocalRulesErrors] = useState<string[]>([]);
  const [localRuleMatches, setLocalRuleMatches] = useState<RuleMatch[]>([]);
  const [fullAnalysis, setFullAnalysis] = useState<FullAnalysis>({
    status: 'idle',
    bytesRead: 0,
    totalBytes: 0,
    progressPct: 0,
  });
  const [lastScanSummary, setLastScanSummary] = useState<{ gapsFound: number; totalLines: number } | null>(null);

  const topFullRuleMatches = (fullAnalysis.status === 'ready' ? (fullAnalysis.rules?.matches ?? []) : [])
    .filter((m) => m.count > 0)
    .slice(0, FULL_RULES_UI_TOP_N);

  const checkApiHealth = async (): Promise<boolean> => {
    try {
      const { res, json } = await fetchApiJson('/api/health', { headers: getApiHeaders() });
      if (!res.ok) {
        setApiDown(true);
        return false;
      }
      const ok = isHealthResponse(json);
      setApiDown(!ok);
      return Boolean(ok);
    } catch {
      setApiDown(true);
      return false;
    }
  };

  useEffect(() => {
    try {
      const savedMode = localStorage.getItem(PREF_KEY_MODE);
      const savedGap = localStorage.getItem(PREF_KEY_GAP);
      const savedOutput = localStorage.getItem(PREF_KEY_OUTPUT);
      const savedSignManifestMode = localStorage.getItem(PREF_KEY_SIGN_MANIFEST_MODE);
      const savedSignCheckpointEvery = localStorage.getItem(PREF_KEY_SIGN_CHECKPOINT_EVERY);
      const savedSignChainScheme = localStorage.getItem(PREF_KEY_SIGN_CHAIN_SCHEME);
      const savedLocalRules = localStorage.getItem(PREF_KEY_LOCAL_RULES);

      const nextMode =
        savedMode === 'scan' || savedMode === 'sign' || savedMode === 'verify' || savedMode === 'ghost'
          ? savedMode
          : null;

      if (nextMode) setMode(nextMode);
      if (savedGap && /^\d+$/.test(savedGap)) setGapThreshold(savedGap);

      if (savedOutput === 'terminal' || savedOutput === 'csv' || savedOutput === 'json') {
        const normalized = nextMode && nextMode !== 'scan' && savedOutput === 'csv' ? 'terminal' : savedOutput;
        setOutputFormat(normalized);
      }

      if (savedSignManifestMode === 'full' || savedSignManifestMode === 'compact') {
        setSignManifestMode(savedSignManifestMode);
      }

      if (savedSignCheckpointEvery && /^\d+$/.test(savedSignCheckpointEvery)) {
        setSignCheckpointEvery(savedSignCheckpointEvery);
      }

      if (savedSignChainScheme === 'v1-line+prev' || savedSignChainScheme === 'v2-prev+lineno+line') {
        setSignChainScheme(savedSignChainScheme);
      }

      if (typeof savedLocalRules === 'string' && savedLocalRules.trim()) {
        setLocalRulesText(savedLocalRules);
      }
    } catch {
      // Best-effort only.
    }

    void checkApiHealth();
  }, []);

  useEffect(() => {
    if (!apiDown) return;
    const id = window.setInterval(() => {
      void checkApiHealth();
    }, 3000);
    return () => window.clearInterval(id);
  }, [apiDown]);

  useEffect(() => {
    try {
      localStorage.setItem(PREF_KEY_MODE, mode);
    } catch {
      // Best-effort only.
    }

    if (mode !== 'scan' && mode !== 'ghost' && outputFormat === 'csv') {
      setOutputFormat('terminal');
    }

    if (mode !== 'verify') {
      setManifestError(null);
    }

    if (mode !== 'scan' && mode !== 'ghost') {
      setGapError(null);
    }

    if (mode !== 'ghost') {
      setGhostBaselineError(null);
      setGhostCorrelateReportError(null);
      setGhostCorrelateReceiptsError(null);
    }
  }, [mode]);

  useEffect(() => {
    try {
      localStorage.setItem(PREF_KEY_GAP, gapThreshold);
    } catch {
      // Best-effort only.
    }
  }, [gapThreshold]);

  useEffect(() => {
    try {
      localStorage.setItem(PREF_KEY_OUTPUT, outputFormat);
    } catch {
      // Best-effort only.
    }
  }, [outputFormat]);

  useEffect(() => {
    try {
      localStorage.setItem(PREF_KEY_SIGN_MANIFEST_MODE, signManifestMode);
    } catch {
      // Best-effort only.
    }

    if (signManifestMode !== 'compact') {
      // Keep a valid checkpoint value around but avoid showing validation errors.
      // (Backend ignores checkpoint_every for full mode.)
    }
  }, [signManifestMode]);

  useEffect(() => {
    try {
      localStorage.setItem(PREF_KEY_SIGN_CHECKPOINT_EVERY, signCheckpointEvery);
    } catch {
      // Best-effort only.
    }
  }, [signCheckpointEvery]);

  useEffect(() => {
    try {
      localStorage.setItem(PREF_KEY_SIGN_CHAIN_SCHEME, signChainScheme);
    } catch {
      // Best-effort only.
    }
  }, [signChainScheme]);

  useEffect(() => {
    try {
      localStorage.setItem(PREF_KEY_LOCAL_RULES, localRulesText);
    } catch {
      // Best-effort only.
    }
  }, [localRulesText]);

  useEffect(() => {
    let cancelled = false;

    const runLocalForensics = async () => {
      if (!selectedFile) {
        setLocalForensics({ status: 'idle', sampleBytes: 0, totalBytes: 0 });
        return;
      }

      setLocalForensics({ status: 'running', sampleBytes: 0, totalBytes: selectedFile.size });

      try {
        const sampleSize = Math.min(selectedFile.size, LOCAL_FORENSICS_SAMPLE_BYTES);
        const sampleBuf = await selectedFile.slice(0, sampleSize).arrayBuffer();
        if (cancelled) return;
        const sample = new Uint8Array(sampleBuf);

        const entropy = computeEntropyBitsPerByte(sample);
        const printable = computePrintableRatio(sample);
        const signature = detectSignature(sample);
        const likelyType = inferLikelyType(getFileExtensionLower(selectedFile.name), printable, entropy);

        // Decode (lossy) for IOC extraction + rule scanning + timestamp stats.
        const decodedText = new TextDecoder('utf-8', { fatal: false }).decode(sample);
        const sampleText = decodedText.length > LOCAL_FORENSICS_MAX_TEXT_BYTES
          ? decodedText.slice(0, LOCAL_FORENSICS_MAX_TEXT_BYTES)
          : decodedText;
        const sampleTextTruncated = decodedText.length > LOCAL_FORENSICS_MAX_TEXT_BYTES;

        const endings = countLineEndings(sampleText);
        const lines = sampleText.length ? sampleText.split(/\r\n|\n|\r/).length : 0;
        const tsRe = /\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?\b/g;
        const timestampHits = (sampleText.match(tsRe) ?? []).length;
        const iocs = extractIocs(sampleText);
        const hexPreview = makeHexPreview(sample, LOCAL_FORENSICS_HEX_BYTES);
        const entropyWindows = computeEntropyWindows(sample);
        const suspicion = computeSuspicionScore({
          entropyBitsPerByte: entropy,
          printableRatio: printable,
          signature,
          timestampHits,
          lines,
          iocCounts: {
            ips: iocs.ipv4.count,
            urls: iocs.urls.count,
            emails: iocs.emails.count,
            sha256: iocs.sha256.count,
            md5: iocs.md5.count,
          },
        });

        // Hash either the full file (if small) or just the sample (always available).
        let shaHex = '';
        let scope: 'sample' | 'full' = 'sample';
        if (selectedFile.size <= LOCAL_FORENSICS_SAMPLE_BYTES) {
          shaHex = await sha256Hex(sample);
          scope = 'full';
        } else {
          shaHex = await sha256Hex(sample);
          scope = 'sample';
        }

        if (cancelled) return;
        setLocalForensics({
          status: 'ready',
          sampleBytes: sampleSize,
          totalBytes: selectedFile.size,
          sampleText,
          sampleTextTruncated,
          entropyBitsPerByte: entropy,
          entropyWindows,
          printableRatio: printable,
          signature,
          likelyType,
          sha256Hex: shaHex,
          sha256Scope: scope,
          lineEndings: endings,
          linesInSample: lines,
          timestampHits,
          iocs,
          hexPreview,
          suspicion,
        });
      } catch (e: any) {
        if (cancelled) return;
        setLocalForensics({
          status: 'error',
          error: e?.message ?? String(e),
          sampleBytes: 0,
          totalBytes: selectedFile.size,
        });
      }
    };

    void runLocalForensics();
    return () => {
      cancelled = true;
    };
  }, [selectedFile]);

  useEffect(() => {
    const text = localForensics.sampleText ?? '';
    if (!text) {
      setLocalRulesErrors([]);
      setLocalRuleMatches([]);
      return;
    }
    const { rules, errors } = parseRules(localRulesText);
    setLocalRulesErrors(errors);
    setLocalRuleMatches(scanRules(text, rules));
  }, [localForensics.sampleText, localRulesText]);

  useEffect(() => {
    let cancelled = false;
    let timeoutId: number | undefined;

    const run = async () => {
      if (!selectedFile) {
        setFullAnalysis({ status: 'idle', bytesRead: 0, totalBytes: 0, progressPct: 0 });
        return;
      }

      const totalBytes = selectedFile.size;
      const entropyBinBytes = clamp(
        Math.ceil(totalBytes / FULL_ENTROPY_MAX_BINS),
        FULL_ENTROPY_MIN_BIN_BYTES,
        FULL_ENTROPY_MAX_BIN_BYTES,
      );

      const gapSeconds = (() => {
        const n = Number.parseInt(gapThreshold, 10);
        return Number.isFinite(n) && n >= 0 ? n : 300;
      })();

      const { rules, errors } = parseRules(localRulesText);

      setFullAnalysis({
        status: 'running',
        bytesRead: 0,
        totalBytes,
        progressPct: 0,
        entropyBinBytes,
        rules: {
          errors,
          scannedLines: 0,
          truncated: false,
          matches: [],
          severityCounts: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
        },
      });

      try {
        // Incremental hashes
        const sha256h = sha256.create();
        const sha1h = sha1.create();
        const md5h = md5.create();

        // Entropy binning across full file (stream-friendly, non-overlapping)
        let entropyCarry = new Uint8Array(0);
        const entropyBins: number[] = [];

        // Full-text scanning + timeline
        const decoder = new TextDecoder('utf-8', { fatal: false });
        let leftover = '';
        let scannedLines = 0;
        let truncated = false;

        const isoRe = /(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(?:\s*(Z|[+-]\d{2}:?\d{2}))?/;
        const apacheRe = /(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s*([+-]\d{4}))?/;
        const syslogRe = /\b([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b/;

        const monthIndex = (mon: string): number => {
          const m = mon.slice(0, 3).toLowerCase();
          const map: Record<string, number> = {
            jan: 0,
            feb: 1,
            mar: 2,
            apr: 3,
            may: 4,
            jun: 5,
            jul: 6,
            aug: 7,
            sep: 8,
            oct: 9,
            nov: 10,
            dec: 11,
          };
          return map[m] ?? -1;
        };

        const parseTimestampMs = (line: string): number | null => {
          // ISO-ish: 2024-01-15T14:23:01Z, 2024-01-15 14:23:01.123+05:30
          {
            const m = isoRe.exec(line);
            if (m) {
              const year = Number(m[1]);
              const month = Number(m[2]);
              const day = Number(m[3]);
              const hour = Number(m[4]);
              const minute = Number(m[5]);
              const second = Number(m[6]);
              const frac = m[7] ? m[7].padEnd(3, '0').slice(0, 3) : '0';
              const ms = Number(frac);
              const tz = m[8] ? String(m[8]) : '';
              if (
                !Number.isFinite(year) || !Number.isFinite(month) || !Number.isFinite(day) ||
                !Number.isFinite(hour) || !Number.isFinite(minute) || !Number.isFinite(second) || !Number.isFinite(ms)
              ) return null;

              if (tz) {
                const baseUtc = Date.UTC(year, month - 1, day, hour, minute, second, ms);
                if (tz === 'Z') return Number.isFinite(baseUtc) ? baseUtc : null;
                const tzNorm = tz.includes(':') ? tz : `${tz.slice(0, 3)}:${tz.slice(3)}`;
                const sign = tzNorm.startsWith('-') ? -1 : 1;
                const hh = Number(tzNorm.slice(1, 3));
                const mm = Number(tzNorm.slice(4, 6));
                if (!Number.isFinite(hh) || !Number.isFinite(mm)) return Number.isFinite(baseUtc) ? baseUtc : null;
                const offsetMs = sign * (hh * 60 + mm) * 60 * 1000;
                return baseUtc - offsetMs;
              }

              // No timezone given: treat as local time.
              const dt = new Date(year, month - 1, day, hour, minute, second, ms);
              const t = dt.getTime();
              return Number.isFinite(t) ? t : null;
            }
          }

          // Apache: [15/Jan/2024:14:23:01 +0000]
          {
            const m = apacheRe.exec(line);
            if (m) {
              const day = Number(m[1]);
              const mon = monthIndex(String(m[2]));
              const year = Number(m[3]);
              const hour = Number(m[4]);
              const minute = Number(m[5]);
              const second = Number(m[6]);
              const tz = m[7] ? String(m[7]) : '';
              if (mon < 0) return null;
              if (
                !Number.isFinite(year) || !Number.isFinite(day) || !Number.isFinite(hour) ||
                !Number.isFinite(minute) || !Number.isFinite(second)
              ) return null;
              const baseUtc = Date.UTC(year, mon, day, hour, minute, second, 0);
              if (!tz) return Number.isFinite(baseUtc) ? baseUtc : null;
              const sign = tz.startsWith('-') ? -1 : 1;
              const hh = Number(tz.slice(1, 3));
              const mm = Number(tz.slice(3, 5));
              if (!Number.isFinite(hh) || !Number.isFinite(mm)) return Number.isFinite(baseUtc) ? baseUtc : null;
              const offsetMs = sign * (hh * 60 + mm) * 60 * 1000;
              return baseUtc - offsetMs;
            }
          }

          // Syslog: Jan 15 14:23:01 (assume current year, local time)
          {
            const m = syslogRe.exec(line);
            if (m) {
              const mon = monthIndex(String(m[1]));
              const day = Number(m[2]);
              const hour = Number(m[3]);
              const minute = Number(m[4]);
              const second = Number(m[5]);
              if (mon < 0) return null;
              const year = new Date().getFullYear();
              const dt = new Date(year, mon, day, hour, minute, second, 0);
              const t = dt.getTime();
              return Number.isFinite(t) ? t : null;
            }
          }

          return null;
        };

        let bucketMs = TIMELINE_BUCKET_MS;
        let bucketMap = new Map<number, number>();
        let parsedEvents = 0;
        let prevTs: number | null = null;
        let gapCount = 0;
        let maxGapSeconds = 0;

        // Rule match aggregation
        const ruleAgg = new Map<string, { def: RuleDef; count: number; hits: Array<{ line: number; text: string }> }>();
        const compiledRules = rules.map((def) => {
          const flags = def.regex.flags.replace('g', '');
          const lineRegex = new RegExp(def.regex.source, flags);
          ruleAgg.set(def.id, { def, count: 0, hits: [] });
          return { def, lineRegex };
        });

        let bytesRead = 0;
        let lastUiUpdate = 0;
        let lastYield = 0;

        const reader = selectedFile.stream().getReader();
        try {
          while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            if (!value) continue;
            if (cancelled) return;

            const chunk = value as Uint8Array;
            bytesRead += chunk.length;

            sha256h.update(chunk);
            sha1h.update(chunk);
            md5h.update(chunk);

            // Entropy bins
            if (entropyCarry.length) {
              const merged = new Uint8Array(entropyCarry.length + chunk.length);
              merged.set(entropyCarry, 0);
              merged.set(chunk, entropyCarry.length);
              let offset = 0;
              while (offset + entropyBinBytes <= merged.length) {
                entropyBins.push(computeEntropyBitsPerByte(merged.subarray(offset, offset + entropyBinBytes)));
                offset += entropyBinBytes;
                if (entropyBins.length >= FULL_ENTROPY_MAX_BINS) break;
              }
              entropyCarry = merged.slice(offset);
            } else {
              let offset = 0;
              while (offset + entropyBinBytes <= chunk.length) {
                entropyBins.push(computeEntropyBitsPerByte(chunk.subarray(offset, offset + entropyBinBytes)));
                offset += entropyBinBytes;
                if (entropyBins.length >= FULL_ENTROPY_MAX_BINS) break;
              }
              entropyCarry = chunk.slice(offset);
            }

            // Full text scan + timeline (bounded by line limit)
            if (!truncated) {
              const decoded = decoder.decode(chunk, { stream: true });
              let text = leftover + decoded;

              // Normalize to '\n' splits; handle CRLF by removing '\r'
              text = text.replace(/\r\n/g, '\n');
              const parts = text.split('\n');
              leftover = parts.pop() ?? '';

              for (const rawLine of parts) {
                if (cancelled) return;
                scannedLines++;
                const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;

                // Rule scan
                for (const r of compiledRules) {
                  if (r.lineRegex.test(line)) {
                    const agg = ruleAgg.get(r.def.id);
                    if (!agg) continue;
                    agg.count++;
                    if (agg.hits.length < 3) {
                      agg.hits.push({
                        line: scannedLines,
                        text: line.length > 220 ? line.slice(0, 220) + '…' : line,
                      });
                    }
                  }
                }

                // Timeline
                const t = parseTimestampMs(line);
                if (t != null) {
                  parsedEvents++;
                  const bucket = Math.floor(t / TIMELINE_BUCKET_MS) * TIMELINE_BUCKET_MS;
                  bucketMap.set(bucket, (bucketMap.get(bucket) ?? 0) + 1);

                  if (prevTs != null) {
                    const deltaSec = (t - prevTs) / 1000;
                    if (deltaSec > gapSeconds) {
                      gapCount++;
                      if (deltaSec > maxGapSeconds) maxGapSeconds = Math.floor(deltaSec);
                    }
                  }
                  prevTs = t;
                }

                if (scannedLines >= FULL_TEXT_MAX_LINES) {
                  truncated = true;
                  break;
                }
              }
            }

            const now = performance.now();
            if (now - lastUiUpdate > 120) {
              lastUiUpdate = now;
              setFullAnalysis((prev) => ({
                ...prev,
                status: 'running',
                bytesRead,
                totalBytes,
                progressPct: totalBytes ? Math.round((bytesRead / totalBytes) * 100) : 0,
              }));
            }

            if (now - lastYield > 250) {
              lastYield = now;
              await new Promise((r) => requestAnimationFrame(() => r(null)));
            }
          }
        } finally {
          try { reader.releaseLock(); } catch { /* ignore */ }
        }

        // Flush decoder tail
        if (!truncated) {
          const tail = decoder.decode();
          let text = leftover + tail;
          text = text.replace(/\r\n/g, '\n');
          const parts = text.split('\n');
          for (const rawLine of parts) {
            scannedLines++;
            const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;

            for (const r of compiledRules) {
              if (r.lineRegex.test(line)) {
                const agg = ruleAgg.get(r.def.id);
                if (!agg) continue;
                agg.count++;
                if (agg.hits.length < 3) {
                  agg.hits.push({ line: scannedLines, text: line.length > 220 ? line.slice(0, 220) + '…' : line });
                }
              }
            }

            const t = parseTimestampMs(line);
            if (t != null) {
              parsedEvents++;
              const bucket = Math.floor(t / TIMELINE_BUCKET_MS) * TIMELINE_BUCKET_MS;
              bucketMap.set(bucket, (bucketMap.get(bucket) ?? 0) + 1);
              if (prevTs != null) {
                const deltaSec = (t - prevTs) / 1000;
                if (deltaSec > gapSeconds) {
                  gapCount++;
                  if (deltaSec > maxGapSeconds) maxGapSeconds = Math.floor(deltaSec);
                }
              }
              prevTs = t;
            }

            if (scannedLines >= FULL_TEXT_MAX_LINES) {
              truncated = true;
              break;
            }
          }
        }

        // Final entropy bin
        if (entropyCarry.length && entropyBins.length < FULL_ENTROPY_MAX_BINS) {
          entropyBins.push(computeEntropyBitsPerByte(entropyCarry));
        }

        const sha256HexFull = bytesToHex(sha256h.digest());
        const sha1HexFull = bytesToHex(sha1h.digest());
        const md5HexFull = bytesToHex(md5h.digest());

        // Rules -> array + severity counts
        const matches: RuleMatch[] = [];
        const severityCounts: Record<RuleSeverity, number> = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
        for (const agg of ruleAgg.values()) {
          matches.push({
            id: agg.def.id,
            label: agg.def.label,
            severity: agg.def.severity,
            count: agg.count,
            examples: agg.hits.map((h) => h.text),
            hits: agg.hits,
          });
          severityCounts[agg.def.severity] += agg.count;
        }
        matches.sort((a, b) => b.count - a.count);

        // Timeline buckets (filled). Coarsen if the span is too large.
        let keys = Array.from(bucketMap.keys()).sort((a, b) => a - b);
        if (keys.length) {
          const start0 = keys[0];
          const end0 = keys[keys.length - 1];
          const spanBuckets = Math.floor((end0 - start0) / TIMELINE_BUCKET_MS) + 1;
          if (spanBuckets > TIMELINE_MAX_BUCKETS) {
            const factor = Math.ceil(spanBuckets / TIMELINE_MAX_BUCKETS);
            bucketMs = TIMELINE_BUCKET_MS * factor;
            const merged = new Map<number, number>();
            for (const [t, c] of bucketMap.entries()) {
              const bt = Math.floor(t / bucketMs) * bucketMs;
              merged.set(bt, (merged.get(bt) ?? 0) + c);
            }
            bucketMap = merged;
            keys = Array.from(bucketMap.keys()).sort((a, b) => a - b);
          }
        }
        const buckets: Array<{ t: number; count: number }> = [];
        if (keys.length) {
          const start = keys[0];
          const end = keys[keys.length - 1];
          for (let t = start; t <= end; t += bucketMs) {
            buckets.push({ t, count: bucketMap.get(t) ?? 0 });
          }
        }

        // Simple anomaly detection
        const counts = buckets.map((b) => b.count);
        const mean = counts.length ? counts.reduce((a, b) => a + b, 0) / counts.length : 0;
        const variance = counts.length ? counts.reduce((a, b) => a + (b - mean) * (b - mean), 0) / counts.length : 0;
        const std = Math.sqrt(variance);
        const burstThreshold = Math.max(10, mean + 3 * std);
        const burstBuckets = counts.filter((c) => c >= burstThreshold).length;

        let gapBuckets = 0;
        let inZero = false;
        let zeroLen = 0;
        for (const c of counts) {
          if (c === 0) {
            inZero = true;
            zeroLen++;
          } else {
            if (inZero && zeroLen >= 2) gapBuckets++;
            inZero = false;
            zeroLen = 0;
          }
        }
        if (inZero && zeroLen >= 2) gapBuckets++;

        if (cancelled) return;
        setFullAnalysis({
          status: 'ready',
          bytesRead: totalBytes,
          totalBytes,
          progressPct: 100,
          sha256Hex: sha256HexFull,
          sha1Hex: sha1HexFull,
          md5Hex: md5HexFull,
          entropyBinBytes,
          entropyBins,
          rules: {
            errors,
            scannedLines,
            truncated,
            matches,
            severityCounts,
          },
          timeline: {
            bucketMs,
            buckets,
            parsedEvents,
            parsedLines: scannedLines,
            gapCount,
            maxGapSeconds,
            burstBuckets,
            gapBuckets,
          },
        });
      } catch (e: any) {
        if (cancelled) return;
        setFullAnalysis({
          status: 'error',
          error: e?.message ?? String(e),
          bytesRead: 0,
          totalBytes,
          progressPct: 0,
        });
      }
    };

    timeoutId = window.setTimeout(() => {
      void run();
    }, FULL_ANALYSIS_DEBOUNCE_MS);

    return () => {
      cancelled = true;
      if (timeoutId) window.clearTimeout(timeoutId);
    };
  }, [selectedFile, localRulesText, gapThreshold]);

  const handleSelectLogFile = (file: File) => {
    const err = validateUpload(file, { label: 'Log file', allowedExts: ['.log', '.txt'], maxBytes: MAX_LOG_BYTES });
    if (err) {
      setSelectedFile(null);
      setFileError(err);
      return;
    }
    setFileError(null);
    setSelectedFile(file);
  };

  const handleSelectManifestFile = (file: File) => {
    const err = validateUpload(file, { label: 'Manifest file', allowedExts: ['.json'], maxBytes: MAX_MANIFEST_BYTES });
    if (err) {
      setManifestFile(null);
      setManifestError(err);
      return;
    }
    setManifestError(null);
    setManifestFile(file);
  };

  const handleSelectGhostBaselineFile = (file: File) => {
    const err = validateUpload(file, { label: 'Baseline file', allowedExts: ['.json'], maxBytes: MAX_GHOST_BASELINE_BYTES });
    if (err) {
      setGhostBaselineFile(null);
      setGhostBaselineError(err);
      return;
    }
    setGhostBaselineError(null);
    setGhostBaselineFile(file);
  };

  const handleSelectGhostCorrelateReportFile = (file: File) => {
    const err = validateUpload(file, { label: 'Report file', allowedExts: ['.json'], maxBytes: MAX_GHOST_CORRELATE_BYTES });
    if (err) {
      setGhostCorrelateReportFile(null);
      setGhostCorrelateReportError(err);
      return;
    }
    setGhostCorrelateReportError(null);
    setGhostCorrelateReportFile(file);
  };

  const handleSelectGhostCorrelateReceiptsFile = (file: File) => {
    const err = validateUpload(file, { label: 'Receipts file', allowedExts: ['.jsonl', '.txt'], maxBytes: MAX_GHOST_CORRELATE_BYTES });
    if (err) {
      setGhostCorrelateReceiptsFile(null);
      setGhostCorrelateReceiptsError(err);
      return;
    }
    setGhostCorrelateReceiptsError(null);
    setGhostCorrelateReceiptsFile(file);
  };

  const downloadText = (filename: string, text: string, mime: string) => {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const handleRunAnalysis = async () => {
    if (mode !== 'ghost' || ghostOperation !== 'correlate') {
      if (!selectedFile) return;
    }

    if (mode === 'verify' && !manifestFile) {
      setManifestError('Verify mode requires a manifest JSON file.');
      return;
    }

    if (mode === 'scan' || (mode === 'ghost' && ghostOperation === 'analyze')) {
      const gapSeconds = Number.parseInt(gapThreshold, 10);
      if (!Number.isFinite(gapSeconds) || gapSeconds < 0) {
        setGapError('Gap threshold must be a non-negative integer (seconds).');
        return;
      }
      setGapError(null);
    }

    const apiOk = await checkApiHealth();
    if (!apiOk) {
      setTerminalOutput(['ERROR: Backend API not reachable. Start the Python API on http://127.0.0.1:8000.']);
      return;
    }

    setIsRunning(true);
    setDownload(null);
    setTerminalOutput([
      `[${new Date().toLocaleTimeString()}] Starting ${mode === 'ghost' ? `ghost (${ghostOperation})` : mode}...`,
      selectedFile ? `[${new Date().toLocaleTimeString()}] File: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(2)} KB)` : '',
      mode === 'scan' ? `[${new Date().toLocaleTimeString()}] Gap threshold: ${gapThreshold}s` : '',
      `[${new Date().toLocaleTimeString()}] Output format: ${outputFormat}`,
      '',
    ].filter(Boolean));

    try {
      let endpoint = '/api/scan';
      let form = new FormData();
      let expectedMode: ApiMode = mode === 'ghost' ? 'ghost-analyze' : mode;
      let data: any = null;

      if (mode === 'scan') {
        endpoint = '/api/scan';
        form.append('file', selectedFile!);
        const gapSeconds = Number.parseInt(gapThreshold, 10);
        form.append('gap', String(gapSeconds));
        form.append('output_format', outputFormat);
        expectedMode = 'scan';
      } else if (mode === 'sign') {
        endpoint = '/api/sign';
        form.append('file', selectedFile!);

        const checkpointEveryIsValid = /^\d+$/.test(signCheckpointEvery);
        if (signManifestMode === 'compact' && !checkpointEveryIsValid) {
          setTerminalOutput((prev) => [...prev, 'ERROR: Checkpoint Every must be a non-negative integer for compact manifests.']);
          return;
        }

        form.append('manifest_mode', signManifestMode);
        form.append('checkpoint_every', checkpointEveryIsValid ? signCheckpointEvery : '1000');
        form.append('chain_scheme', signChainScheme);
        expectedMode = 'sign';
      } else if (mode === 'verify') {
        endpoint = '/api/verify';
        form.append('file', selectedFile!);
        if (manifestFile) form.append('manifest', manifestFile);
        expectedMode = 'verify';
      } else {
        // Ghost operations
        if (ghostOperation === 'analyze') {
          endpoint = '/api/ghost/analyze';
          form.append('file', selectedFile!);
          const gapSeconds = Number.parseInt(gapThreshold, 10);
          form.append('gap', String(gapSeconds));
          if (ghostBaselineFile) form.append('baseline', ghostBaselineFile);
          expectedMode = 'ghost-analyze';
        } else if (ghostOperation === 'baseline') {
          endpoint = '/api/ghost/baseline';
          form.append('file', selectedFile!);
          form.append('max_lines', String(FULL_TEXT_MAX_LINES));
          expectedMode = 'ghost-baseline';
        } else if (ghostOperation === 'receipts') {
          endpoint = '/api/ghost/receipts';
          form.append('file', selectedFile!);
          form.append('processes', String(Boolean(ghostReceiptsIncludeProcesses)));
          form.append('netstat', String(Boolean(ghostReceiptsIncludeNetstat)));
          form.append('samples', String(Boolean(ghostReceiptsIncludeSamples)));
          expectedMode = 'ghost-receipts';
        } else {
          endpoint = '/api/ghost/correlate';
          form = new FormData();
          expectedMode = 'ghost-correlate';

          const reportFile = ghostCorrelateReportFile
            ? ghostCorrelateReportFile
            : ghostLastReport
              ? new File([JSON.stringify(ghostLastReport, null, 2) + '\n'], 'ghost_report.json', { type: 'application/json' })
              : null;

          const receiptsFile = ghostCorrelateReceiptsFile
            ? ghostCorrelateReceiptsFile
            : ghostLastReceipts && ghostLastReceipts.length
              ? new File([
                  ghostLastReceipts.map((r) => JSON.stringify(r)).join('\n') + '\n',
                ], 'ghost_receipts.jsonl', { type: 'text/plain' })
              : null;

          if (!reportFile || !receiptsFile) {
            setTerminalOutput((prev) => [
              ...prev,
              'ERROR: Correlate requires both a ghost report (.json) and receipts (.jsonl).',
              'Tip: Run Ghost Analyze + Ghost Receipts first, or upload files below.',
            ]);
            return;
          }

          form.append('report', reportFile);
          form.append('receipts', receiptsFile);
        }
      }

      if (mode === 'scan' && selectedFile && selectedFile.size >= ASYNC_SCAN_THRESHOLD_BYTES) {
        setTerminalOutput((prev) => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] Large file detected. Switching to async scan job mode...`,
        ]);

        const enqueue = await fetchApiJson('/api/jobs/scan', { method: 'POST', body: form, headers: getApiHeaders() });
        if (!enqueue.res.ok || !isApiOkWithMode(enqueue.json, 'jobs-scan')) {
          const msg = formatApiErrorMessage({
            res: enqueue.res,
            json: enqueue.json,
            fallback: `Async scan enqueue failed (${enqueue.res.status})`,
          });
          setTerminalOutput((prev) => [...prev, `ERROR: ${msg}`]);
          return;
        }

        const jobId = String((enqueue.json as any)?.job_id ?? '');
        if (!jobId) {
          setTerminalOutput((prev) => [...prev, 'ERROR: Async scan did not return a job ID.']);
          return;
        }

        setTerminalOutput((prev) => [...prev, `[${new Date().toLocaleTimeString()}] Job queued: ${jobId}`]);

        const startedAt = Date.now();
        let lastStatus = '';
        while (Date.now() - startedAt < ASYNC_SCAN_TIMEOUT_MS) {
          await new Promise((resolve) => window.setTimeout(resolve, ASYNC_SCAN_POLL_MS));
          const statusRes = await fetchApiJson(`/api/jobs/${jobId}`, { headers: getApiHeaders() });
          if (!statusRes.res.ok || !isApiOkWithMode(statusRes.json, 'jobs-status')) {
            const msg = formatApiErrorMessage({
              res: statusRes.res,
              json: statusRes.json,
              fallback: `Async scan status failed (${statusRes.res.status})`,
            });
            setTerminalOutput((prev) => [...prev, `ERROR: ${msg}`]);
            return;
          }

          const statusPayload: any = statusRes.json;
          const status = String(statusPayload?.status ?? '');
          if (status && status !== lastStatus) {
            lastStatus = status;
            setTerminalOutput((prev) => [...prev, `[${new Date().toLocaleTimeString()}] Job status: ${status}`]);
          }

          if (status === 'failed') {
            const err = String(statusPayload?.error ?? 'Async scan job failed.');
            setTerminalOutput((prev) => [...prev, `ERROR: ${err}`]);
            return;
          }

          if (status === 'succeeded') {
            data = statusPayload?.result;
            break;
          }
        }

        if (!data) {
          setTerminalOutput((prev) => [...prev, 'ERROR: Async scan timed out while waiting for completion.']);
          return;
        }

        if (!isApiOkWithMode(data, expectedMode)) {
          setTerminalOutput((prev) => [...prev, 'ERROR: Async scan result payload is invalid.']);
          return;
        }
      } else {
        const { res, json } = await fetchApiJson(endpoint, { method: 'POST', body: form, headers: getApiHeaders() });
        if (!res.ok || !isApiOkWithMode(json, expectedMode)) {
          const msg = formatApiErrorMessage({ res, json, fallback: `Request failed (${res.status})` });
          setTerminalOutput((prev) => [...prev, `ERROR: ${msg}`]);
          return;
        }
        data = json;
      }

      const requestId = data?.request_id ? String(data.request_id) : '';

      const outputText: string =
        mode === 'ghost'
          ? ghostOperation === 'baseline'
            ? formatGhostBaselineTerminal({ fileName: selectedFile?.name ?? '—', baseline: data?.baseline, requestId })
            : ghostOperation === 'receipts'
              ? formatGhostReceiptsTerminal({ fileName: selectedFile?.name ?? '—', receipts: data?.receipts, requestId })
              : formatGhostTerminalReport({ fileName: selectedFile?.name ?? '—', report: data?.report, requestId })
          : String(data?.output?.text ?? '');

      if (mode === 'scan') {
        const gapsFound = Array.isArray(data?.gaps) ? data.gaps.length : Number(data?.stats?.gaps_found ?? 0);
        const totalLines = Number(data?.stats?.total_lines ?? 0);
        setLastScanSummary({
          gapsFound: Number.isFinite(gapsFound) ? gapsFound : 0,
          totalLines: Number.isFinite(totalLines) ? totalLines : 0,
        });
      }

      // Persist a summary record for the History / Results pages.
      try {
        const now = new Date();
        const baseStatus: HistoryStatus =
          mode === 'sign'
            ? 'SIGNED'
            : mode === 'ghost'
              ? ghostOperation === 'baseline'
                ? 'GHOST_BASELINE'
                : ghostOperation === 'receipts'
                  ? 'GHOST_RECEIPTS'
                  : (() => {
                      const report = data?.report;
                      const summary = report?.summary ?? {};
                      const risk = Number(summary?.risk_score ?? 0);
                      const eventsCount =
                        Number(summary?.event_counts?.total ?? summary?.event_count ?? 0) ||
                        (Array.isArray(report?.events) ? report.events.length : 0);
                      return risk > 0 || eventsCount > 0 ? 'GHOST_SIGNALS' : 'GHOST_CLEAN';
                    })()
              : (String(data?.status ?? 'ERROR') as HistoryStatus);

        const gapsCount =
          mode === 'scan'
            ? Array.isArray(data?.gaps)
              ? data.gaps.length
              : Number(data?.stats?.gaps_found ?? 0)
            : mode === 'ghost'
              ? ghostOperation === 'baseline'
                ? Number(data?.baseline?.timestamps_found ?? 0)
                : ghostOperation === 'receipts'
                  ? (Array.isArray(data?.receipts) ? data.receipts.length : 0)
                  : (() => {
                      const report = data?.report;
                      const summary = report?.summary ?? {};
                      return (
                        Number(summary?.event_counts?.total ?? summary?.event_count ?? 0) ||
                        (Array.isArray(report?.events) ? report.events.length : 0)
                      );
                    })()
            : 0;

        const linesCount =
          mode === 'scan'
            ? Number(data?.stats?.total_lines ?? 0)
            : mode === 'sign'
              ? Number(data?.manifest?.total_lines ?? 0)
              : mode === 'ghost'
                ? ghostOperation === 'baseline'
                  ? Number(data?.baseline?.total_lines ?? 0)
                  : ghostOperation === 'receipts'
                    ? 0
                    : (() => {
                        const report = data?.report;
                        const summary = report?.summary ?? {};
                        return Number(summary?.lines_analyzed ?? summary?.lines_total ?? summary?.total_lines ?? 0);
                      })()
              : Number(data?.report?.current_total_lines ?? 0);

        const historyFileName =
          selectedFile?.name ??
          (mode === 'ghost' && ghostOperation === 'correlate'
            ? ghostCorrelateReportFile?.name ?? 'ghost_correlate.json'
            : 'uploaded.log');

        addHistoryRecord({
          id: newHistoryId(),
          timestamp: formatTimestamp(now),
          file: historyFileName,
          mode,
          status: baseStatus,
          gaps: gapsCount,
          lines: Number.isFinite(linesCount) ? linesCount : 0,
          request_id: data?.request_id ? String(data.request_id) : undefined,
          details: {
            scan:
              mode === 'scan'
                ? {
                    request_id: data?.request_id ? String(data.request_id) : undefined,
                    gapThreshold: Number.parseInt(gapThreshold, 10),
                    outputFormat,
                    stats: data?.stats,
                    gaps: data?.gaps,
                    outputText: String(data?.output?.text ?? ''),
                  }
                : undefined,
            sign:
              mode === 'sign'
                ? {
                    request_id: data?.request_id ? String(data.request_id) : undefined,
                    rootHash: String(data?.root_hash ?? ''),
                    manifest: data?.manifest
                      ? {
                          file: String(data?.manifest?.file ?? ''),
                          signed_at: String(data?.manifest?.signed_at ?? ''),
                          hash_algorithm: String(data?.manifest?.hash_algorithm ?? ''),
                          chain_scheme: String(data?.manifest?.chain_scheme ?? ''),
                          manifest_mode: String(data?.manifest?.manifest_mode ?? ''),
                          checkpoint_every:
                            typeof data?.manifest?.checkpoint_every === 'number'
                              ? Number(data.manifest.checkpoint_every)
                              : undefined,
                          checkpoint_count: Array.isArray(data?.manifest?.checkpoints)
                            ? Number((data.manifest.checkpoints as any[]).length)
                            : undefined,
                          entry_count: Array.isArray(data?.manifest?.entries)
                            ? Number((data.manifest.entries as any[]).length)
                            : undefined,
                          total_lines: Number(data?.manifest?.total_lines ?? 0),
                          root_hash: String(data?.manifest?.root_hash ?? ''),
                          signature: data?.manifest?.signature
                            ? {
                                scheme: String(data?.manifest?.signature?.scheme ?? ''),
                                key_id: String(data?.manifest?.signature?.key_id ?? ''),
                                value: String(data?.manifest?.signature?.value ?? ''),
                              }
                            : undefined,
                        }
                      : undefined,
                    outputText: String(data?.output?.text ?? ''),
                  }
                : undefined,
            verify:
              mode === 'verify'
                ? {
                    request_id: data?.request_id ? String(data.request_id) : undefined,
                    status: baseStatus,
                    report: data?.report,
                    outputText: String(data?.output?.text ?? ''),
                  }
                : undefined,
            ghost:
              mode === 'ghost'
                ? {
                    request_id: data?.request_id ? String(data.request_id) : undefined,
                    status: baseStatus,
                    action: ghostOperation,
                    report: ghostOperation === 'baseline' || ghostOperation === 'receipts' ? undefined : data?.report,
                    baseline: ghostOperation === 'baseline' ? data?.baseline : undefined,
                    receipts: ghostOperation === 'receipts' ? data?.receipts : undefined,
                    outputText,
                  }
                : undefined,
          },
        });
      } catch {
        // Best-effort only; do not block UI on storage failures.
      }

      // Display output in the terminal pane.
      {
        const baseLines = toTerminalLines(outputText);
        const prefix = requestId ? [`[Request ID: ${requestId}]`] : [];
        setTerminalOutput([...prefix, ...baseLines]);
      }

      // Prepare a download blob for the selected output.
      if (mode === 'scan') {
        const ext = outputFormat === 'terminal' ? 'txt' : outputFormat;
        const mime = outputFormat === 'csv' ? 'text/csv' : outputFormat === 'json' ? 'application/json' : 'text/plain';

        if (outputFormat === 'json') {
          const gapsFound = Array.isArray(data?.gaps) ? data.gaps.length : Number(data?.stats?.gaps_found ?? 0);
          const totalLines = Number(data?.stats?.total_lines ?? 0);
          const augmented = {
            ...data,
            local_analysis: {
              sample: serializeLocalForensics(localForensics),
              full: serializeFullAnalysis(fullAnalysis),
              correlation: {
                backend: {
                  gaps_found: Number.isFinite(gapsFound) ? gapsFound : 0,
                  total_lines: Number.isFinite(totalLines) ? totalLines : 0,
                  request_id: data?.request_id ? String(data.request_id) : undefined,
                },
                local: {
                  gap_threshold_seconds: Number.parseInt(gapThreshold, 10),
                  timeline_gaps: fullAnalysis.status === 'ready' ? fullAnalysis.timeline?.gapCount : undefined,
                },
              },
            },
          };
          const jsonText = JSON.stringify(augmented, null, 2) + '\n';
          setDownload({
            filename: `${selectedFile.name}.scan.${ext}`,
            text: jsonText,
            mime,
          });
        } else {
          setDownload({
            filename: `${selectedFile.name}.scan.${ext}`,
            text: outputText,
            mime,
          });
        }
      } else if (mode === 'sign') {
        const jsonText = JSON.stringify(data.manifest, null, 2) + '\n';
        setDownload({
          filename: `${selectedFile.name}.manifest.json`,
          text: jsonText,
          mime: 'application/json',
        });
        if (outputFormat === 'json') {
          const baseLines = toTerminalLines(jsonText);
          const prefix = requestId ? [`[Request ID: ${requestId}]`] : [];
          setTerminalOutput([...prefix, ...baseLines]);
        }
      } else if (mode === 'ghost') {
        if (ghostOperation === 'baseline') {
          const jsonText = JSON.stringify(data.baseline, null, 2) + '\n';
          const baselineName = `${selectedFile?.name ?? 'log'}.ghost-baseline.json`;
          setDownload({ filename: baselineName, text: jsonText, mime: 'application/json' });
          setGhostLastReport(null);

          // Also keep it loaded for quick Analyze runs.
          try {
            const baselineFile = new File([jsonText], baselineName, { type: 'application/json' });
            setGhostBaselineError(null);
            setGhostBaselineFile(baselineFile);
          } catch {
            // Best-effort only.
          }

          if (outputFormat === 'json') {
            const baseLines = toTerminalLines(jsonText);
            const prefix = requestId ? [`[Request ID: ${requestId}]`] : [];
            setTerminalOutput([...prefix, ...baseLines]);
          }
        } else if (ghostOperation === 'receipts') {
          const receipts = Array.isArray(data?.receipts) ? (data.receipts as any[]) : [];
          setGhostLastReceipts(receipts);

          const jsonText = JSON.stringify(receipts, null, 2) + '\n';
          const jsonlText = receipts.map((r) => JSON.stringify(r)).join('\n') + (receipts.length ? '\n' : '');
          setDownload({
            filename: `${selectedFile?.name ?? 'log'}.ghost_receipts.jsonl`,
            text: jsonlText,
            mime: 'text/plain',
          });
          if (outputFormat === 'json') {
            const baseLines = toTerminalLines(jsonText);
            const prefix = requestId ? [`[Request ID: ${requestId}]`] : [];
            setTerminalOutput([...prefix, ...baseLines]);
          }
        } else {
          const report = data.report;
          setGhostLastReport(report);

          const jsonText = JSON.stringify(report, null, 2) + '\n';
          setDownload({
            filename: `${selectedFile?.name ?? 'log'}.ghost_report.json`,
            text: jsonText,
            mime: 'application/json',
          });
          if (outputFormat === 'json') {
            const baseLines = toTerminalLines(jsonText);
            const prefix = requestId ? [`[Request ID: ${requestId}]`] : [];
            setTerminalOutput([...prefix, ...baseLines]);
          }
        }
      } else {
        const jsonText = JSON.stringify(data.report, null, 2) + '\n';
        setDownload({
          filename: `${selectedFile.name}.verify_report.json`,
          text: jsonText,
          mime: 'application/json',
        });
        if (outputFormat === 'json') {
          const baseLines = toTerminalLines(jsonText);
          const prefix = requestId ? [`[Request ID: ${requestId}]`] : [];
          setTerminalOutput([...prefix, ...baseLines]);
        }
      }
    } catch (e: any) {
      setApiDown(true);
      setTerminalOutput((prev) => [...prev, `ERROR: ${e?.message ?? String(e)}`]);
    } finally {
      setIsRunning(false);
    }
  };

  const canRun =
    mode === 'ghost' && ghostOperation === 'correlate'
      ? Boolean(
          (ghostCorrelateReportFile && ghostCorrelateReceiptsFile) ||
            (ghostLastReport && ghostLastReceipts && ghostLastReceipts.length)
        )
      : Boolean(selectedFile);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 lg:h-[calc(100vh-12rem)]">
      <div className="space-y-8 lg:overflow-y-auto lg:pr-2">
        <div>
          <h1 className="text-2xl font-semibold text-foreground mb-2">Scan & Analysis</h1>
          <p className="text-muted-foreground">Upload log files for integrity analysis</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <div className="px-2.5 py-1 rounded-md border bg-secondary/60 border-border text-[11px] font-mono text-muted-foreground tracking-wider">
              MODE: {mode.toUpperCase()}
            </div>
            <div className="px-2.5 py-1 rounded-md border bg-secondary/60 border-border text-[11px] font-mono text-muted-foreground tracking-wider">
              OUTPUT: {outputFormat.toUpperCase()}
            </div>
            {selectedFile ? (
              <div className="px-2.5 py-1 rounded-md border bg-secondary/60 border-border text-[11px] font-mono text-muted-foreground tracking-wider">
                FILE: {selectedFile.name}
              </div>
            ) : null}
          </div>
        </div>

        {apiDown && (
          <div className="p-4 bg-destructive/10 border border-destructive/30 rounded text-destructive">
            Backend API not reachable. Start the Python API on http://127.0.0.1:8000.
          </div>
        )}

        <div className="space-y-4">
          <FileDropzone
            onFileSelect={handleSelectLogFile}
            accept=".log,.txt"
          />

          {fileError && (
            <div className="text-sm text-destructive">{fileError}</div>
          )}

          {selectedFile && (
            <div className="flex items-center gap-3 p-4 bg-card border border-border rounded">
              <FileText className="w-5 h-5 text-primary" />
              <div className="flex-1">
                <div className="text-sm text-foreground">{selectedFile.name}</div>
                <div className="text-xs text-muted-foreground">{(selectedFile.size / 1024).toFixed(2)} KB</div>
              </div>
            </div>
          )}

          {selectedFile && (
            <div className="p-4 bg-card border border-border rounded space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div className="text-sm text-foreground">Local Forensics Modules</div>
                <div
                  className={
                    localForensics.status === 'running'
                      ? 'text-xs px-2 py-1 rounded border bg-primary/10 text-primary border-primary/30'
                      : localForensics.status === 'ready'
                        ? 'text-xs px-2 py-1 rounded border bg-success/10 text-success border-success/30'
                        : localForensics.status === 'error'
                          ? 'text-xs px-2 py-1 rounded border bg-destructive/10 text-destructive border-destructive/30'
                          : 'text-xs px-2 py-1 rounded border bg-secondary text-muted-foreground border-border'
                  }
                >
                  {localForensics.status === 'running'
                    ? 'ANALYZING'
                    : localForensics.status === 'ready'
                      ? 'READY'
                      : localForensics.status === 'error'
                        ? 'FAILED'
                        : 'IDLE'}
                </div>
              </div>

              {localForensics.status === 'error' && (
                <div className="text-sm text-destructive">Local analysis error: {localForensics.error ?? 'Unknown error'}</div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="flex items-start gap-3 p-3 bg-background border border-border rounded">
                  <Fingerprint className="w-4 h-4 text-primary mt-0.5" />
                  <div className="flex-1">
                    <div className="text-xs text-muted-foreground">Signature / Type</div>
                    <div className="text-sm text-foreground">
                      {localForensics.signature ?? '—'}
                      {localForensics.likelyType ? ` • ${localForensics.likelyType}` : ''}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Sample: {formatBytes(localForensics.sampleBytes)} / Total: {formatBytes(localForensics.totalBytes)}
                    </div>
                  </div>
                </div>

                <div className="flex items-start gap-3 p-3 bg-background border border-border rounded">
                  <Binary className="w-4 h-4 text-primary mt-0.5" />
                  <div className="flex-1">
                    <div className="text-xs text-muted-foreground">Entropy / Printable</div>
                    <div className="text-sm text-foreground">
                      {typeof localForensics.entropyBitsPerByte === 'number'
                        ? `${localForensics.entropyBitsPerByte.toFixed(2)} bits/byte`
                        : '—'}
                      {typeof localForensics.printableRatio === 'number'
                        ? ` • ${(localForensics.printableRatio * 100).toFixed(1)}% printable`
                        : ''}
                    </div>
                    <div className="text-xs text-muted-foreground">Higher entropy ≈ more compressed/encrypted.</div>
                  </div>
                </div>

                <div className="flex items-start gap-3 p-3 bg-background border border-border rounded">
                  <Search className="w-4 h-4 text-primary mt-0.5" />
                  <div className="flex-1">
                    <div className="text-xs text-muted-foreground">IOC Extractor (sample)</div>
                    <div className="text-sm text-foreground">
                      IPs: {localForensics.iocs?.ipv4.count ?? 0} • URLs: {localForensics.iocs?.urls.count ?? 0}
                    </div>
                    <div className="text-sm text-foreground">
                      SHA-256: {localForensics.iocs?.sha256.count ?? 0} • Emails: {localForensics.iocs?.emails.count ?? 0}
                    </div>
                  </div>
                </div>

                <div className="flex items-start gap-3 p-3 bg-background border border-border rounded">
                  <Shield className="w-4 h-4 text-primary mt-0.5" />
                  <div className="flex-1">
                    <div className="text-xs text-muted-foreground">Timestamps / Line Endings (sample)</div>
                    <div className="text-sm text-foreground">
                      TS hits: {localForensics.timestampHits ?? 0} • Lines: {localForensics.linesInSample ?? 0}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      CRLF: {localForensics.lineEndings?.crlf ?? 0} • LF: {localForensics.lineEndings?.lf ?? 0} • CR: {localForensics.lineEndings?.cr ?? 0}
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="text-xs text-muted-foreground">SLIDING-WINDOW ENTROPY MAP</div>
                    <div className="text-xs text-muted-foreground">
                      {Array.isArray(localForensics.entropyWindows) ? `${localForensics.entropyWindows.length} windows` : '—'}
                    </div>
                  </div>
                  <div className="p-3 bg-background border border-border rounded">
                    {Array.isArray(localForensics.entropyWindows) && localForensics.entropyWindows.length ? (
                      <div className="space-y-2">
                        <div className="flex items-end gap-[2px] h-16 overflow-hidden">
                          {localForensics.entropyWindows.map((v, i) => {
                            const h = Math.round(clamp((v / 8) * 64, 2, 64));
                            const isPeak = v >= 7.6;
                            return (
                              <div
                                key={i}
                                title={`Window ${i + 1}: ${v.toFixed(2)} bits/byte`}
                                className={isPeak ? 'bg-primary' : 'bg-primary/60'}
                                style={{ width: '3px', height: `${h}px` }}
                              />
                            );
                          })}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          Scale: 0 → 8 bits/byte. Peaks (≥7.6) often indicate packed/encrypted segments.
                        </div>
                      </div>
                    ) : (
                      <div className="text-xs text-muted-foreground">—</div>
                    )}
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="text-xs text-muted-foreground">SUSPICION SCORE</div>
                    <div
                      className={
                        localForensics.suspicion?.level === 'HIGH'
                          ? 'text-xs px-2 py-1 rounded border bg-destructive/10 text-destructive border-destructive/30'
                          : localForensics.suspicion?.level === 'MEDIUM'
                            ? 'text-xs px-2 py-1 rounded border bg-warning/10 text-warning border-warning/30'
                            : 'text-xs px-2 py-1 rounded border bg-success/10 text-success border-success/30'
                      }
                    >
                      {localForensics.suspicion?.level ?? '—'}
                    </div>
                  </div>
                  <div className="p-3 bg-background border border-border rounded space-y-2">
                    <div className="text-3xl font-semibold text-foreground">
                      {typeof localForensics.suspicion?.score === 'number' ? localForensics.suspicion.score : '—'}
                      <span className="text-sm text-muted-foreground">/100</span>
                    </div>
                    <div className="text-xs text-muted-foreground">Heuristic score from entropy, timestamp density, and IOC volume (sample-based).</div>
                    <div className="text-xs text-foreground space-y-1">
                      {(localForensics.suspicion?.reasons ?? []).slice(0, 6).map((r) => (
                        <div key={r} className="flex items-start gap-2">
                          <span className="text-primary">▸</span>
                          <span>{r}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <div className="text-xs text-muted-foreground">SHA-256 ({localForensics.sha256Scope === 'full' ? 'full file' : 'sample'})</div>
                <div className="px-3 py-2 bg-background border border-border rounded font-mono text-xs text-foreground break-all">
                  {localForensics.sha256Hex ?? '—'}
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                <div className="space-y-2">
                  <div className="text-xs text-muted-foreground">HEX DUMP (first {LOCAL_FORENSICS_HEX_BYTES} bytes)</div>
                  <pre className="p-3 bg-background border border-border rounded font-mono text-[11px] leading-5 text-foreground overflow-auto max-h-48 scrollbar-thin scrollbar-track-transparent">
                    {localForensics.hexPreview ?? '—'}
                  </pre>
                </div>

                <div className="space-y-2">
                  <div className="text-xs text-muted-foreground">IOC SAMPLES (unique, from sample)</div>
                  <div className="p-3 bg-background border border-border rounded text-xs text-foreground space-y-2 max-h-48 overflow-auto scrollbar-thin scrollbar-track-transparent">
                    <div>
                      <div className="text-muted-foreground">IPv4</div>
                      <div className="font-mono break-all">{(localForensics.iocs?.ipv4.examples ?? []).join('  ') || '—'}</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">URLs</div>
                      <div className="font-mono break-all">{(localForensics.iocs?.urls.examples ?? []).join('  ') || '—'}</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Hashes</div>
                      <div className="font-mono break-all">
                        {(localForensics.iocs?.sha256.examples ?? []).concat(localForensics.iocs?.md5.examples ?? []).join('  ') || '—'}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="text-xs text-muted-foreground">RULE SCANNER (YARA-LIKE)</div>
                  <div className="text-xs text-muted-foreground">
                    {localForensics.sampleTextTruncated ? 'sample text truncated' : 'sample text'}
                  </div>
                </div>

                <textarea
                  value={localRulesText}
                  onChange={(e) => setLocalRulesText(e.target.value)}
                  className="w-full min-h-[140px] px-3 py-2 bg-background border border-border rounded text-foreground focus:border-primary focus:outline-none transition-colors font-mono text-xs"
                  spellCheck={false}
                />

                {localRulesErrors.length ? (
                  <div className="text-xs text-warning bg-warning/10 border border-warning/30 rounded p-2">
                    {localRulesErrors.slice(0, 4).map((e) => (
                      <div key={e}>{e}</div>
                    ))}
                  </div>
                ) : null}

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                  <div className="p-3 bg-background border border-border rounded">
                    <div className="text-xs text-muted-foreground mb-2">Top rule hits (sample)</div>
                    <div className="space-y-2 max-h-44 overflow-auto scrollbar-thin scrollbar-track-transparent">
                      {localRuleMatches.length ? (
                        localRuleMatches.slice(0, 10).map((m) => (
                          <div key={m.id} className="flex items-start justify-between gap-3">
                            <div className="text-xs text-foreground break-all">{m.label}</div>
                            <div className={m.count > 0 ? 'text-xs text-primary' : 'text-xs text-muted-foreground'}>
                              {m.count}
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="text-xs text-muted-foreground">—</div>
                      )}
                    </div>
                  </div>

                  <div className="p-3 bg-background border border-border rounded">
                    <div className="text-xs text-muted-foreground mb-2">Example matches</div>
                    <div className="space-y-3 max-h-44 overflow-auto scrollbar-thin scrollbar-track-transparent">
                      {(localRuleMatches.find((m) => m.count > 0)?.examples ?? []).length ? (
                        <>
                          <div className="text-xs text-foreground break-all">
                            <span className="text-muted-foreground">Rule: </span>
                            {localRuleMatches.find((m) => m.count > 0)?.label}
                          </div>
                          {(localRuleMatches.find((m) => m.count > 0)?.examples ?? []).map((ex, i) => (
                            <pre key={i} className="p-2 bg-card border border-border rounded font-mono text-[11px] text-foreground whitespace-pre-wrap">
                              {ex}
                            </pre>
                          ))}
                        </>
                      ) : (
                        <div className="text-xs text-muted-foreground">No rule hits in sample.</div>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="text-xs text-muted-foreground">FULL-FILE STREAMING ANALYSIS</div>
                  <div
                    className={
                      fullAnalysis.status === 'running'
                        ? 'text-xs px-2 py-1 rounded border bg-primary/10 text-primary border-primary/30'
                        : fullAnalysis.status === 'ready'
                          ? 'text-xs px-2 py-1 rounded border bg-success/10 text-success border-success/30'
                          : fullAnalysis.status === 'error'
                            ? 'text-xs px-2 py-1 rounded border bg-destructive/10 text-destructive border-destructive/30'
                            : 'text-xs px-2 py-1 rounded border bg-secondary text-muted-foreground border-border'
                    }
                  >
                    {fullAnalysis.status === 'running'
                      ? `RUNNING ${clamp(fullAnalysis.progressPct, 0, 100)}%`
                      : fullAnalysis.status === 'ready'
                        ? 'READY'
                        : fullAnalysis.status === 'error'
                          ? 'ERROR'
                          : 'IDLE'}
                  </div>
                </div>

                <div className="p-3 bg-background border border-border rounded space-y-3">
                  {fullAnalysis.status === 'error' ? (
                    <div className="text-xs text-destructive">{fullAnalysis.error}</div>
                  ) : fullAnalysis.status === 'idle' ? (
                    <div className="text-xs text-muted-foreground">Select a file to start streaming analysis.</div>
                  ) : (
                    <>
                      <div className="space-y-2">
                        <div className="w-full h-2 bg-secondary rounded overflow-hidden">
                          <div
                            className="h-2 bg-primary"
                            style={{ width: `${clamp(fullAnalysis.progressPct, 0, 100)}%` }}
                          />
                        </div>
                        <div className="flex items-center justify-between text-xs text-muted-foreground">
                          <div>
                            {(fullAnalysis.bytesRead / (1024 * 1024)).toFixed(2)} MB / {(fullAnalysis.totalBytes / (1024 * 1024)).toFixed(2)} MB
                          </div>
                          {typeof fullAnalysis.entropyBinBytes === 'number' ? (
                            <div>bin {fullAnalysis.entropyBinBytes.toLocaleString()} B</div>
                          ) : null}
                        </div>
                      </div>

                      {fullAnalysis.status === 'ready' ? (
                        <>
                          <div className="space-y-2">
                            <div className="text-xs text-muted-foreground">FULL HASHES</div>
                            <div className="grid grid-cols-1 gap-2">
                              <div className="px-3 py-2 bg-card border border-border rounded font-mono text-[11px] text-foreground break-all">
                                <span className="text-muted-foreground">SHA-256: </span>
                                {fullAnalysis.sha256Hex}
                              </div>
                              <div className="px-3 py-2 bg-card border border-border rounded font-mono text-[11px] text-foreground break-all">
                                <span className="text-muted-foreground">SHA-1: </span>
                                {fullAnalysis.sha1Hex}
                              </div>
                              <div className="px-3 py-2 bg-card border border-border rounded font-mono text-[11px] text-foreground break-all">
                                <span className="text-muted-foreground">MD5: </span>
                                {fullAnalysis.md5Hex}
                              </div>
                            </div>
                          </div>

                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
                              <div className="text-xs text-muted-foreground">FULL ENTROPY MAP</div>
                              <div className="text-xs text-muted-foreground">
                                {fullAnalysis.entropyBins?.length ? `${fullAnalysis.entropyBins.length} bins` : '—'}
                              </div>
                            </div>
                            {fullAnalysis.entropyBins?.length ? (
                              <div className="flex items-end gap-[1px] h-14 overflow-hidden">
                                {(fullAnalysis.entropyBins ?? []).map((v, i) => {
                                  const h = Math.round(clamp((v / 8) * 56, 2, 56));
                                  const isPeak = v >= 7.6;
                                  return (
                                    <div
                                      key={i}
                                      title={`Bin ${i + 1}: ${v.toFixed(2)} bits/byte`}
                                      className={isPeak ? 'bg-primary' : 'bg-primary/60'}
                                      style={{ width: '2px', height: `${h}px` }}
                                    />
                                  );
                                })}
                              </div>
                            ) : (
                              <div className="text-xs text-muted-foreground">—</div>
                            )}
                          </div>

                          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                            <div className="p-3 bg-card border border-border rounded space-y-2">
                              <div className="text-xs text-muted-foreground">RULE ENGINE v2 (full file)</div>
                              <div className="text-xs text-foreground">
                                <div className="flex items-center justify-between"><span className="text-muted-foreground">CRITICAL</span><span className="text-primary">{fullAnalysis.rules?.severityCounts.CRITICAL ?? 0}</span></div>
                                <div className="flex items-center justify-between"><span className="text-muted-foreground">HIGH</span><span className="text-primary">{fullAnalysis.rules?.severityCounts.HIGH ?? 0}</span></div>
                                <div className="flex items-center justify-between"><span className="text-muted-foreground">MEDIUM</span><span className="text-primary">{fullAnalysis.rules?.severityCounts.MEDIUM ?? 0}</span></div>
                                <div className="flex items-center justify-between"><span className="text-muted-foreground">LOW</span><span className="text-primary">{fullAnalysis.rules?.severityCounts.LOW ?? 0}</span></div>
                              </div>
                              <div className="text-xs text-muted-foreground">
                                Scanned {fullAnalysis.rules?.scannedLines?.toLocaleString() ?? '—'} lines{fullAnalysis.rules?.truncated ? ' (truncated)' : ''}.
                              </div>

                              <div className="pt-2 border-t border-border space-y-2">
                                <div className="text-xs text-muted-foreground">Top matches (full file)</div>
                                {topFullRuleMatches.length ? (
                                  <div className="space-y-2 max-h-56 overflow-auto scrollbar-thin scrollbar-track-transparent">
                                    {topFullRuleMatches.map((m) => (
                                      <div key={m.id} className="p-2 bg-background border border-border rounded space-y-2">
                                        <div className="flex items-start justify-between gap-3">
                                          <div className="text-xs text-foreground break-all">
                                            {m.label}
                                          </div>
                                          <div className="flex items-center gap-2">
                                            <div
                                              className={
                                                m.severity === 'CRITICAL'
                                                  ? 'text-[10px] px-2 py-[2px] rounded border bg-destructive/10 text-destructive border-destructive/30'
                                                  : m.severity === 'HIGH'
                                                    ? 'text-[10px] px-2 py-[2px] rounded border bg-destructive/10 text-destructive border-destructive/30'
                                                    : m.severity === 'MEDIUM'
                                                      ? 'text-[10px] px-2 py-[2px] rounded border bg-warning/10 text-warning border-warning/30'
                                                      : 'text-[10px] px-2 py-[2px] rounded border bg-success/10 text-success border-success/30'
                                              }
                                            >
                                              {m.severity}
                                            </div>
                                            <div className="text-xs text-primary font-mono">{m.count}</div>
                                          </div>
                                        </div>

                                        {(m.hits ?? []).length ? (
                                          <div className="space-y-1">
                                            {(m.hits ?? []).slice(0, 3).map((h) => (
                                              <div key={`${m.id}:${h.line}`} className="text-[11px] font-mono text-foreground break-all">
                                                <span className="text-muted-foreground">L{h.line}:</span> {h.text}
                                              </div>
                                            ))}
                                          </div>
                                        ) : null}
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <div className="text-xs text-muted-foreground">No rule hits in full-file scan.</div>
                                )}
                              </div>
                            </div>

                            <div className="p-3 bg-card border border-border rounded space-y-2">
                              <div className="text-xs text-muted-foreground">TIMELINE + ANOMALIES (full file)</div>
                              <div className="text-xs text-foreground space-y-1">
                                <div className="flex items-center justify-between"><span className="text-muted-foreground">Parsed events</span><span className="text-primary">{fullAnalysis.timeline?.parsedEvents?.toLocaleString() ?? 0}</span></div>
                                <div className="flex items-center justify-between"><span className="text-muted-foreground">Local gaps</span><span className="text-primary">{fullAnalysis.timeline?.gapCount ?? 0}</span></div>
                                <div className="flex items-center justify-between"><span className="text-muted-foreground">Max gap</span><span className="text-primary">{fullAnalysis.timeline?.maxGapSeconds ?? 0}s</span></div>
                                <div className="flex items-center justify-between"><span className="text-muted-foreground">Burst buckets</span><span className="text-primary">{fullAnalysis.timeline?.burstBuckets ?? 0}</span></div>
                                <div className="flex items-center justify-between"><span className="text-muted-foreground">Gap buckets</span><span className="text-primary">{fullAnalysis.timeline?.gapBuckets ?? 0}</span></div>
                              </div>
                              {mode === 'scan' && lastScanSummary ? (
                                <div className="text-xs text-muted-foreground">
                                  Backend gaps: {lastScanSummary.gapsFound.toLocaleString()} (of {lastScanSummary.totalLines.toLocaleString()} lines)
                                </div>
                              ) : null}
                            </div>
                          </div>
                        </>
                      ) : (
                        <div className="text-xs text-muted-foreground">
                          Streaming in progress. Hashing + entropy + rules + timeline update automatically.
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            </div>
          )}

          <div className="pt-4 border-t border-border">
            <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Controls</div>
          </div>

          <div className="space-y-2">
            <label className="text-sm text-foreground">Suspicious gap threshold (seconds)</label>
            <input
              type="number"
              value={gapThreshold}
              onChange={(e) => setGapThreshold(e.target.value)}
              disabled={mode !== 'scan' && mode !== 'ghost'}
              className="w-full px-4 py-2 bg-background border border-border rounded text-foreground focus:border-primary focus:outline-none transition-colors"
            />
            {gapError && <div className="text-sm text-destructive">{gapError}</div>}
          </div>

          <div className="space-y-2">
            <label className="text-sm text-foreground">Output Format</label>
            <div className="flex flex-wrap gap-2">
              {(mode === 'scan' ? (['terminal', 'csv', 'json'] as const) : (['terminal', 'json'] as const)).map((format) => (
                <button
                  key={format}
                  onClick={() => setOutputFormat(format)}
                  className={
                    `
                    px-3 py-2 rounded-md text-xs font-semibold uppercase tracking-wider transition-colors border
                    ${outputFormat === format
                      ? 'bg-primary text-primary-foreground border-primary/40'
                      : 'bg-secondary text-muted-foreground hover:bg-secondary/80 hover:text-foreground border-transparent hover:border-border'
                    }
                  `
                  }
                >
                  {format.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-sm text-foreground">Mode</label>
            <div className="flex flex-wrap gap-2">
              {(['scan', 'sign', 'verify', 'ghost'] as const).map((m) => (
                <button
                  key={m}
                  onClick={() => {
                    setMode(m);
                    if (m !== 'scan' && outputFormat === 'csv') setOutputFormat('terminal');
                  }}
                  className={
                    `
                    px-3 py-2 rounded-md text-xs font-semibold uppercase tracking-wider transition-colors border
                    ${mode === m
                      ? 'bg-primary text-primary-foreground border-primary/40'
                      : 'bg-secondary text-muted-foreground hover:bg-secondary/80 hover:text-foreground border-transparent hover:border-border'
                    }
                  `
                  }
                >
                  {m.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {mode === 'sign' && (
            <div className="space-y-4">
              <div>
                <div className="text-sm text-foreground mb-2">Sign Options</div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="space-y-2">
                    <label className="text-sm text-foreground">Manifest Mode</label>
                    <select
                      value={signManifestMode}
                      onChange={(e) => setSignManifestMode(e.target.value as any)}
                      className="w-full px-4 py-2 bg-background border border-border rounded text-foreground focus:border-primary focus:outline-none transition-colors"
                    >
                      <option value="full">Full</option>
                      <option value="compact">Compact</option>
                    </select>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm text-foreground">Checkpoint Every</label>
                    <input
                      type="number"
                      min={0}
                      value={signCheckpointEvery}
                      onChange={(e) => setSignCheckpointEvery(e.target.value)}
                      disabled={signManifestMode !== 'compact'}
                      className="w-full px-4 py-2 bg-background border border-border rounded text-foreground focus:border-primary focus:outline-none transition-colors disabled:opacity-50"
                    />
                    {signManifestMode !== 'compact' ? (
                      <div className="text-xs text-muted-foreground">Used only for compact manifests.</div>
                    ) : null}
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm text-foreground">Chain Scheme</label>
                    <select
                      value={signChainScheme}
                      onChange={(e) => setSignChainScheme(e.target.value as any)}
                      className="w-full px-4 py-2 bg-background border border-border rounded text-foreground focus:border-primary focus:outline-none transition-colors"
                    >
                      <option value="v1-line+prev">v1 (line + prev)</option>
                      <option value="v2-prev+lineno+line">v2 (prev + line# + line)</option>
                    </select>
                  </div>
                </div>
              </div>
            </div>
          )}

          {mode === 'verify' && (
            <div className="space-y-2">
              <label className="text-sm text-foreground">Manifest File (required for verify)</label>
              <FileDropzone
                onFileSelect={handleSelectManifestFile}
                accept=".json"
                label="Drop manifest.json here or click to browse"
              />

              {manifestError && (
                <div className="text-sm text-destructive">{manifestError}</div>
              )}

              {manifestFile && (
                <div className="flex items-center gap-3 p-4 bg-card border border-border rounded">
                  <FileText className="w-5 h-5 text-primary" />
                  <div className="flex-1">
                    <div className="text-sm text-foreground">{manifestFile.name}</div>
                    <div className="text-xs text-muted-foreground">{(manifestFile.size / 1024).toFixed(2)} KB</div>
                  </div>
                </div>
              )}
            </div>
          )}

          {mode === 'ghost' && (
            <div className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm text-foreground">Ghost Operation</label>
                <div className="flex flex-wrap gap-2">
                  {(['analyze', 'baseline', 'receipts', 'correlate'] as const).map((op) => (
                    <button
                      key={op}
                      onClick={() => setGhostOperation(op)}
                      className={
                        `
                        px-3 py-2 rounded-md text-xs font-semibold uppercase tracking-wider transition-colors border
                        ${ghostOperation === op
                          ? 'bg-primary text-primary-foreground border-primary/40'
                          : 'bg-secondary text-muted-foreground hover:bg-secondary/80 hover:text-foreground border-transparent hover:border-border'
                        }
                      `
                      }
                    >
                      {op.toUpperCase()}
                    </button>
                  ))}
                </div>
                <div className="text-xs text-muted-foreground">
                  Analyze: detect log signals. Baseline: generate a reusable baseline JSON. Receipts: capture host/file snapshots. Correlate: compare report vs receipts for FS rewrites/truncation.
                </div>
              </div>

              {ghostOperation === 'analyze' ? (
                <div className="space-y-2">
                  <label className="text-sm text-foreground">Baseline File (optional)</label>
                  <FileDropzone
                    onFileSelect={handleSelectGhostBaselineFile}
                    accept=".json"
                    label="Drop .ghost-baseline.json here or click to browse"
                  />

                  {ghostBaselineError && (
                    <div className="text-sm text-destructive">{ghostBaselineError}</div>
                  )}

                  {ghostBaselineFile && (
                    <div className="flex items-center gap-3 p-4 bg-card border border-border rounded">
                      <FileText className="w-5 h-5 text-primary" />
                      <div className="flex-1">
                        <div className="text-sm text-foreground">{ghostBaselineFile.name}</div>
                        <div className="text-xs text-muted-foreground">{(ghostBaselineFile.size / 1024).toFixed(2)} KB</div>
                      </div>
                    </div>
                  )}
                </div>
              ) : null}

              {ghostOperation === 'receipts' ? (
                <div className="space-y-2">
                  <label className="text-sm text-foreground">Receipts Options</label>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <label className="flex items-center gap-2 text-sm text-foreground">
                      <input
                        type="checkbox"
                        checked={ghostReceiptsIncludeSamples}
                        onChange={(e) => setGhostReceiptsIncludeSamples(e.target.checked)}
                        className="h-4 w-4"
                      />
                      Samples (head/tail hashes)
                    </label>
                    <label className="flex items-center gap-2 text-sm text-foreground">
                      <input
                        type="checkbox"
                        checked={ghostReceiptsIncludeProcesses}
                        onChange={(e) => setGhostReceiptsIncludeProcesses(e.target.checked)}
                        className="h-4 w-4"
                      />
                      Processes snapshot
                    </label>
                    <label className="flex items-center gap-2 text-sm text-foreground">
                      <input
                        type="checkbox"
                        checked={ghostReceiptsIncludeNetstat}
                        onChange={(e) => setGhostReceiptsIncludeNetstat(e.target.checked)}
                        className="h-4 w-4"
                      />
                      Netstat snapshot
                    </label>
                  </div>
                </div>
              ) : null}

              {ghostOperation === 'correlate' ? (
                <div className="space-y-3">
                  <div className="text-xs text-muted-foreground">
                    Uses the last in-app Ghost Analyze + Ghost Receipts if available, or upload a report + receipts file below.
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                    <div className="space-y-2">
                      <label className="text-sm text-foreground">Ghost Report (.json)</label>
                      <FileDropzone
                        onFileSelect={handleSelectGhostCorrelateReportFile}
                        accept=".json"
                        label="Drop ghost_report.json here or click to browse"
                      />
                      {ghostCorrelateReportError ? <div className="text-sm text-destructive">{ghostCorrelateReportError}</div> : null}
                      {ghostCorrelateReportFile ? (
                        <div className="text-xs text-muted-foreground font-mono">selected: {ghostCorrelateReportFile.name}</div>
                      ) : null}
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm text-foreground">Receipts (.jsonl)</label>
                      <FileDropzone
                        onFileSelect={handleSelectGhostCorrelateReceiptsFile}
                        accept=".jsonl,.txt"
                        label="Drop ghost_receipts.jsonl here or click to browse"
                      />
                      {ghostCorrelateReceiptsError ? <div className="text-sm text-destructive">{ghostCorrelateReceiptsError}</div> : null}
                      {ghostCorrelateReceiptsFile ? (
                        <div className="text-xs text-muted-foreground font-mono">selected: {ghostCorrelateReceiptsFile.name}</div>
                      ) : null}
                    </div>
                  </div>

                  {!ghostCorrelateReportFile && !ghostCorrelateReceiptsFile ? (
                    <div className="text-xs text-muted-foreground font-mono">
                      auto-ready: {ghostLastReport && ghostLastReceipts && ghostLastReceipts.length ? 'yes' : 'no'}
                    </div>
                  ) : null}
                </div>
              ) : null}
            </div>
          )}

          <div className="flex gap-2">
            <button
              onClick={handleRunAnalysis}
              disabled={!canRun || isRunning || Boolean(fileError)}
              className="flex-1 flex items-center justify-center gap-2 px-6 py-3 bg-primary hover:bg-primary/90 disabled:bg-secondary disabled:text-muted-foreground text-primary-foreground rounded transition-colors"
            >
              <Play className="w-4 h-4" />
              {isRunning ? 'Running...' : 'Run'}
            </button>

            <button
              onClick={() => download && downloadText(download.filename, download.text, download.mime)}
              disabled={!download || isRunning}
              className="px-4 py-3 bg-secondary hover:bg-secondary/80 disabled:bg-card disabled:text-muted-foreground text-foreground border border-border rounded transition-colors"
              title="Download output"
            >
              <Download className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <TerminalOutput output={terminalOutput} isRunning={isRunning} />
      </div>
    </div>
  );
}
