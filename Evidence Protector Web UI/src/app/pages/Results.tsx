import { useMemo } from 'react';
import { useParams, Link } from '../router';
import { StatusBadge } from '../components/StatusBadge';
import { HashDisplay } from '../components/HashDisplay';
import { ForensicFingerprint } from '../components/ForensicFingerprint';
import { Download, ArrowLeft, Copy, GitCompareArrows, Layers3, ClipboardList } from 'lucide-react';
import { getHistoryRecordById, type ScanGap } from '../lib/history';
import { ChartContainer, ChartTooltip, ChartTooltipContent } from '../components/ui/chart';
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from 'recharts';

function downloadText(filename: string, text: string, mime: string) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function formatIsoForDisplay(value?: string) {
  if (!value) return '';
  return value
    .replace('T', ' ')
    .replace('Z', '')
    .replace(/\.(\d+)/, '');
}

function csvEscape(value: unknown): string {
  const s = String(value ?? '');
  if (/[\n",]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function buildScanCsv(gaps: ScanGap[]): string {
  const header = ['gap_index', 'gap_start', 'gap_end', 'duration_seconds', 'line_start', 'line_end', 'note'];
  const rows = gaps.map((g, idx) => [
    csvEscape(g.gap_index ?? idx + 1),
    csvEscape(g.gap_start ?? ''),
    csvEscape(g.gap_end ?? ''),
    csvEscape(g.duration_seconds ?? 0),
    csvEscape(g.line_start ?? ''),
    csvEscape(g.line_end ?? ''),
    csvEscape(g.note ?? ''),
  ]);
  return [header.join(','), ...rows.map((r) => r.join(','))].join('\n') + '\n';
}

function buildGhostNarrativeMarkdown(report: any): string {
  const summary = report?.summary ?? {};
  const events: any[] = Array.isArray(report?.events) ? report.events : [];
  const lines: string[] = [];

  lines.push('# Ghost Protocol Narrative');
  lines.push('');
  lines.push(`- Generated at: \`${String(report?.generated_at ?? '')}\``);
  lines.push(`- File: \`${String(report?.source_file_name ?? report?.file ?? '')}\``);
  lines.push(`- Total lines: \`${String(summary?.total_lines ?? '')}\``);
  lines.push(`- Timestamps found: \`${String(summary?.timestamps_found ?? '')}\``);
  lines.push(`- Risk score: \`${String(summary?.risk_score ?? '')}\``);
  lines.push('');
  lines.push('## Signals');

  if (!events.length) {
    lines.push('No events emitted.');
  } else {
    for (const ev of events) {
      const signal = String(ev?.signal_type ?? 'UNKNOWN');
      const severity = String(ev?.severity ?? 'LOW');
      const lineStart = Number(ev?.line_range?.[0] ?? 0);
      const lineEnd = Number(ev?.line_range?.[1] ?? 0);
      const lineRange = lineStart > 0 && lineEnd >= lineStart ? `${lineStart}-${lineEnd}` : '?';
      lines.push(`- **${severity}** \`${signal}\` (lines \`${lineRange}\`)`);
    }
  }

  lines.push('');
  lines.push('## Raw Summary');
  lines.push('```json');
  lines.push(JSON.stringify(summary, null, 2));
  lines.push('```');
  lines.push('');

  return lines.join('\n');
}

function severityTone(severity: string): string {
  const s = severity.toLowerCase();
  if (s === 'high' || s === 'critical') return 'bg-destructive/10 text-destructive border-destructive/30';
  if (s === 'medium') return 'bg-warning/10 text-warning border-warning/30';
  return 'bg-secondary text-muted-foreground border-border';
}

export function Results() {
  const { id } = useParams();
  const record = useMemo(() => (id ? getHistoryRecordById(id) : undefined), [id]);

  if (!id || !record) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Link
            to="/history"
            className="p-2 hover:bg-secondary rounded transition-colors"
          >
            <ArrowLeft className="w-5 h-5 text-muted-foreground" />
          </Link>
          <div>
            <h1 className="text-2xl font-semibold text-foreground">Report Not Found</h1>
            <p className="text-muted-foreground">This report may have been deleted.</p>
          </div>
        </div>
      </div>
    );
  }

  const title =
    record.mode === 'scan'
      ? 'Scan Results'
      : record.mode === 'sign'
        ? 'Sign Results'
        : record.mode === 'ghost'
          ? 'Ghost Results'
          : 'Verify Results';

  const scanDetails = record.details?.scan;
  const verifyDetails = record.details?.verify;
  const signDetails = record.details?.sign;
  const ghostDetails = record.details?.ghost;

  const ghostAction = record.mode === 'ghost' ? (String((ghostDetails as any)?.action ?? 'analyze') as any) : undefined;
  const ghostBaseline = record.mode === 'ghost' ? ((ghostDetails as any)?.baseline as any) : undefined;
  const ghostReceipts: any[] = record.mode === 'ghost' && Array.isArray((ghostDetails as any)?.receipts) ? ((ghostDetails as any).receipts as any[]) : [];

  const requestId =
    String(
      record.request_id ??
        scanDetails?.request_id ??
        signDetails?.request_id ??
        verifyDetails?.request_id ??
        ghostDetails?.request_id ??
        ''
    ) || '';

  const scanGaps: ScanGap[] = Array.isArray(scanDetails?.gaps) ? scanDetails!.gaps! : [];
  const issues = Array.isArray(verifyDetails?.report?.issues) ? verifyDetails?.report?.issues ?? [] : [];

  const scanStats = record.mode === 'scan' ? (scanDetails?.stats as any) : undefined;
  const scanAnomalies = useMemo(() => {
    if (record.mode !== 'scan') return 0;
    return scanGaps.filter((g) => String(g.note ?? '') === 'TIMESTAMP_ANOMALY').length;
  }, [record.mode, scanGaps]);

  const verifyReport = record.mode === 'verify' ? ((verifyDetails as any)?.report as any) : undefined;
  const ghostReport = record.mode === 'ghost' ? ((ghostDetails as any)?.report as any) : undefined;
  const ghostSummary = ghostReport?.summary ?? {};
  const ghostEvents: any[] = Array.isArray(ghostReport?.events) ? ghostReport.events : [];
  const ghostRiskScore = Number(ghostSummary?.risk_score ?? 0);
  const ghostBaselineUsed = Boolean(ghostReport?.baseline_used);

  const ghostReceiptsSummary = useMemo(() => {
    if (record.mode !== 'ghost' || !ghostReceipts.length) {
      return { counts: [] as Array<{ kind: string; count: number }>, file: undefined as any };
    }
    const counts = new Map<string, number>();
    for (const r of ghostReceipts) {
      const k = String(r?.kind ?? 'UNKNOWN');
      counts.set(k, (counts.get(k) ?? 0) + 1);
    }
    const file = ghostReceipts.find((r) => String(r?.kind ?? '') === 'FILE');
    return {
      counts: Array.from(counts.entries())
        .map(([kind, count]) => ({ kind, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 12),
      file,
    };
  }, [record.mode, ghostReceipts]);

  const ghostSignalCounts = useMemo(() => {
    if (record.mode !== 'ghost') return [] as Array<{ signal: string; count: number }>;
    const counts = new Map<string, number>();
    for (const e of ghostEvents) {
      const k = String(e?.signal_type ?? 'UNKNOWN');
      counts.set(k, (counts.get(k) ?? 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([signal, count]) => ({ signal, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 16);
  }, [record.mode, ghostEvents]);

  const ghostExplainabilityCards = useMemo(() => {
    if (record.mode !== 'ghost') return [] as Array<{ id: string; signal: string; severity: string; lineRange: string; message: string; evidence: string }>;
    return ghostEvents.slice(0, 24).map((event: any, idx: number) => {
      const signal = String(event?.signal_type ?? 'UNKNOWN');
      const severity = String(event?.severity ?? 'low');
      const lineStart = Number(event?.line_range?.[0] ?? event?.line_start ?? 0);
      const lineEnd = Number(event?.line_range?.[1] ?? event?.line_end ?? lineStart);
      const lineRange = lineStart > 0 ? (lineEnd > lineStart ? `${lineStart}-${lineEnd}` : `${lineStart}`) : '—';
      const message = String(event?.message ?? event?.note ?? '').trim();

      let evidence = '';
      try {
        const ev = event?.evidence;
        evidence = ev === undefined ? '' : JSON.stringify(ev);
      } catch {
        evidence = '';
      }
      if (evidence.length > 180) evidence = `${evidence.slice(0, 180)}…`;

      return {
        id: `${signal}-${lineRange}-${idx}`,
        signal,
        severity,
        lineRange,
        message,
        evidence,
      };
    });
  }, [record.mode, ghostEvents]);

  const verifyIssueTypeData = useMemo(() => {
    if (record.mode !== 'verify') return [] as Array<{ status: string; count: number }>;
    const counts = new Map<string, number>();
    for (const issue of issues as any[]) {
      const status = String(issue?.status ?? 'MISMATCH');
      counts.set(status, (counts.get(status) ?? 0) + 1);
    }
    const out = Array.from(counts.entries()).map(([status, count]) => ({ status, count }));
    out.sort((a, b) => b.count - a.count);
    return out.slice(0, 12);
  }, [record.mode, issues]);

  const scanGapChartData = useMemo(() => {
    if (record.mode !== 'scan') return [] as Array<{ gap: string; duration: number }>;
    const limited = scanGaps.slice(0, 80);
    return limited.map((gap, idx) => ({
      gap: `#${String(gap.gap_index ?? idx + 1)}`,
      duration: Number(gap.duration_seconds ?? 0),
    }));
  }, [record.mode, scanGaps]);

  const verifyIssueHistogram = useMemo(() => {
    if (record.mode !== 'verify') return [] as Array<{ bucket: string; count: number }>;
    const lineNumbers = issues
      .map((i: any) => (typeof i?.line_number === 'number' ? Number(i.line_number) : Number.NaN))
      .filter((n: number) => Number.isFinite(n) && n > 0);
    if (!lineNumbers.length) return [] as Array<{ bucket: string; count: number }>;

    const maxLine = Math.max(...lineNumbers);
    const desiredBins = Math.min(24, Math.max(6, Math.ceil(Math.sqrt(lineNumbers.length))));
    const binSize = Math.max(1, Math.ceil(maxLine / desiredBins));

    const counts = new Map<number, number>();
    for (const ln of lineNumbers) {
      const idx = Math.floor((ln - 1) / binSize);
      counts.set(idx, (counts.get(idx) ?? 0) + 1);
    }

    const out: Array<{ bucket: string; count: number; start: number }> = [];
    for (const [idx, count] of counts.entries()) {
      const start = idx * binSize + 1;
      const end = start + binSize - 1;
      out.push({ bucket: `${start.toLocaleString()}–${end.toLocaleString()}`, count, start });
    }
    out.sort((a, b) => a.start - b.start);
    return out.map(({ bucket, count }) => ({ bucket, count }));
  }, [record.mode, issues]);

  const signCompositionData = useMemo(() => {
    if (record.mode !== 'sign') return [] as Array<{ kind: string; count: number }>;
    const entryCount = Number((signDetails as any)?.manifest?.entry_count ?? 0);
    const checkpointCount = Number((signDetails as any)?.manifest?.checkpoint_count ?? 0);
    const entries = Number.isFinite(entryCount) ? entryCount : 0;
    const checkpoints = Number.isFinite(checkpointCount) ? checkpointCount : 0;
    if (entries <= 0 && checkpoints <= 0) return [] as Array<{ kind: string; count: number }>;
    return [
      { kind: 'Entries', count: entries },
      { kind: 'Checkpoints', count: checkpoints },
    ];
  }, [record.mode, signDetails]);

  const jsonPayload =
    record.mode === 'scan'
      ? {
          file: record.file,
          status: record.status,
          timestamp: record.timestamp,
          request_id: requestId || undefined,
          gap_threshold: scanDetails?.gapThreshold,
          output_format: scanDetails?.outputFormat,
          stats: scanDetails?.stats,
          gaps: scanGaps,
        }
      : record.mode === 'sign'
        ? {
            file: record.file,
            status: record.status,
            timestamp: record.timestamp,
            request_id: requestId || undefined,
            root_hash: signDetails?.rootHash ?? signDetails?.manifest?.root_hash,
            manifest: signDetails?.manifest,
          }
        : record.mode === 'ghost'
          ? {
              file: record.file,
              status: record.status,
              timestamp: record.timestamp,
              request_id: requestId || undefined,
              action: (ghostDetails as any)?.action,
              baseline: (ghostDetails as any)?.baseline,
              receipts: (ghostDetails as any)?.receipts,
              report: ghostDetails?.report,
            }
          : {
            file: record.file,
            status: record.status,
            timestamp: record.timestamp,
            request_id: requestId || undefined,
            report: verifyDetails?.report,
          };

  const jsonText = JSON.stringify(jsonPayload, null, 2) + '\n';
  const csvText = record.mode === 'scan' ? buildScanCsv(scanGaps) : '';

  const canDownloadJson = true;
  const canDownloadCsv = record.mode === 'scan';
  const canCopy = true;

  const ghostReportJsonText =
    record.mode === 'ghost' && ghostReport
      ? JSON.stringify(ghostReport, null, 2) + '\n'
      : '';

  const ghostReceiptsJsonlText =
    record.mode === 'ghost' && ghostReceipts.length
      ? ghostReceipts.map((row) => JSON.stringify(row)).join('\n') + '\n'
      : '';

  const ghostCorrelatedJsonText =
    record.mode === 'ghost' && ghostAction === 'correlate' && ghostReport
      ? JSON.stringify(ghostReport, null, 2) + '\n'
      : '';

  const ghostNarrativeMarkdown =
    record.mode === 'ghost' && ghostReport
      ? buildGhostNarrativeMarkdown(ghostReport)
      : '';

  const copyText =
    record.mode === 'scan'
      ? String(scanDetails?.outputText ?? jsonText)
      : record.mode === 'sign'
        ? String(signDetails?.outputText ?? jsonText)
        : record.mode === 'ghost'
          ? String(ghostDetails?.outputText ?? jsonText)
          : String(verifyDetails?.outputText ?? jsonText);

  const rootHash =
    record.mode === 'sign'
      ? String(signDetails?.rootHash ?? signDetails?.manifest?.root_hash ?? '')
      : record.mode === 'verify'
        ? String(verifyDetails?.report?.current_root_hash ?? '')
        : '';

  const signSignatureValue =
    record.mode === 'sign'
      ? String((signDetails as any)?.manifest?.signature?.value ?? '')
      : '';

  const signSignatureScheme =
    record.mode === 'sign'
      ? String((signDetails as any)?.manifest?.signature?.scheme ?? '')
      : '';

  const signSignatureKeyId =
    record.mode === 'sign'
      ? String((signDetails as any)?.manifest?.signature?.key_id ?? '')
      : '';

  const verifySignature =
    record.mode === 'verify'
      ? (verifyDetails as any)?.report?.manifest_signature
      : undefined;

  const verifyManifestMode =
    record.mode === 'verify' ? String((verifyDetails as any)?.report?.manifest_mode ?? '') : '';

  const verifyChainScheme =
    record.mode === 'verify' ? String((verifyDetails as any)?.report?.chain_scheme ?? '') : '';

  const verifyHashAlgorithm =
    record.mode === 'verify' ? String((verifyDetails as any)?.report?.hash_algorithm ?? '') : '';

  const thirdMetricLabel =
    record.mode === 'scan'
      ? 'Gaps Detected'
      : record.mode === 'ghost'
        ? ghostAction === 'baseline'
          ? 'Timestamps'
          : ghostAction === 'receipts'
            ? 'Receipts'
            : 'Signals'
      : record.mode === 'verify'
        ? 'Issues Found'
        : 'Lines Signed';

  const thirdMetricValue =
    record.mode === 'scan'
      ? record.gaps
      : record.mode === 'ghost'
        ? record.gaps
      : record.mode === 'verify'
        ? Number(verifyDetails?.report?.issues_found ?? issues.length ?? 0)
        : record.lines;

  const thirdMetricColor =
    record.mode === 'scan'
      ? record.gaps > 0
        ? 'text-warning'
        : 'text-foreground'
      : record.mode === 'ghost'
        ? thirdMetricValue > 0 || (Number.isFinite(ghostRiskScore) && ghostRiskScore > 0)
          ? 'text-warning'
          : 'text-foreground'
      : record.mode === 'verify'
        ? thirdMetricValue > 0
          ? 'text-destructive'
          : 'text-foreground'
        : 'text-foreground';

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-4">
          <Link
            to="/history"
            className="p-2 hover:bg-secondary rounded transition-colors"
          >
            <ArrowLeft className="w-5 h-5 text-muted-foreground" />
          </Link>
          <div>
            <h1 className="text-2xl font-semibold text-foreground">{title}</h1>
            <p className="text-muted-foreground">Report #{id}</p>
            {requestId ? (
              <p className="text-xs text-muted-foreground font-mono mt-1">Request ID: {requestId}</p>
            ) : null}
          </div>
        </div>
        <div className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto">
          <Link
            to="/compare"
            className="flex items-center justify-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 text-foreground border border-border rounded-md transition-colors w-full sm:w-auto"
          >
            <GitCompareArrows className="w-4 h-4" />
            Compare
          </Link>
          <Link
            to="/baselines"
            className="flex items-center justify-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 text-foreground border border-border rounded-md transition-colors w-full sm:w-auto"
          >
            <Layers3 className="w-4 h-4" />
            Baselines
          </Link>
          <Link
            to="/release-evidence"
            className="flex items-center justify-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 text-foreground border border-border rounded-md transition-colors w-full sm:w-auto"
          >
            <ClipboardList className="w-4 h-4" />
            Evidence
          </Link>
          <button
            disabled={!canDownloadJson}
            onClick={() => downloadText(`${record.file}.${record.mode}.json`, jsonText, 'application/json')}
            className="flex items-center justify-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 disabled:opacity-50 text-foreground border border-border rounded-md transition-colors w-full sm:w-auto"
          >
            <Download className="w-4 h-4" />
            JSON
          </button>
          <button
            disabled={!canDownloadCsv}
            onClick={() => downloadText(`${record.file}.${record.mode}.csv`, csvText, 'text/csv')}
            className="flex items-center justify-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 disabled:opacity-50 text-foreground border border-border rounded-md transition-colors w-full sm:w-auto"
          >
            <Download className="w-4 h-4" />
            CSV
          </button>
          <button
            disabled={!canCopy}
            onClick={() => navigator.clipboard.writeText(copyText)}
            className="flex items-center justify-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 disabled:opacity-50 text-foreground border border-border rounded-md transition-colors w-full sm:w-auto"
          >
            <Copy className="w-4 h-4" />
            Copy
          </button>
          {record.mode === 'ghost' ? (
            <>
              <button
                disabled={!ghostReportJsonText}
                onClick={() => downloadText(`${record.file}.ghost-report.json`, ghostReportJsonText, 'application/json')}
                className="flex items-center justify-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 disabled:opacity-50 text-foreground border border-border rounded-md transition-colors w-full sm:w-auto"
              >
                <Download className="w-4 h-4" />
                Report
              </button>
              <button
                disabled={!ghostReceiptsJsonlText}
                onClick={() => downloadText(`${record.file}.ghost-receipts.jsonl`, ghostReceiptsJsonlText, 'application/x-ndjson')}
                className="flex items-center justify-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 disabled:opacity-50 text-foreground border border-border rounded-md transition-colors w-full sm:w-auto"
              >
                <Download className="w-4 h-4" />
                Receipts
              </button>
              <button
                disabled={!ghostCorrelatedJsonText}
                onClick={() => downloadText(`${record.file}.ghost-correlated.json`, ghostCorrelatedJsonText, 'application/json')}
                className="flex items-center justify-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 disabled:opacity-50 text-foreground border border-border rounded-md transition-colors w-full sm:w-auto"
              >
                <Download className="w-4 h-4" />
                Correlated
              </button>
              <button
                disabled={!ghostNarrativeMarkdown}
                onClick={() => downloadText(`${record.file}.ghost-narrative.md`, ghostNarrativeMarkdown, 'text/markdown')}
                className="flex items-center justify-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 disabled:opacity-50 text-foreground border border-border rounded-md transition-colors w-full sm:w-auto"
              >
                <Download className="w-4 h-4" />
                Narrative
              </button>
            </>
          ) : null}
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-6 space-y-4">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <h2 className="text-xl font-semibold text-foreground">{record.file}</h2>
            <p className="text-sm text-muted-foreground font-mono">{record.timestamp}</p>
          </div>
          <StatusBadge status={record.status as any} />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-4">
          <div>
            <div className="text-xs text-muted-foreground mb-1">Total Lines</div>
            <div className="text-2xl font-semibold text-foreground">{(record.lines ?? 0).toLocaleString()}</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground mb-1">Mode</div>
            <div className="text-2xl font-semibold text-foreground uppercase">{record.mode}</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground mb-1">{thirdMetricLabel}</div>
            <div className={`text-2xl font-semibold ${thirdMetricColor}`}>{thirdMetricValue}</div>
          </div>
        </div>
      </div>

      {rootHash ? <HashDisplay hash={rootHash} label="Root Hash" /> : null}

      {rootHash ? <ForensicFingerprint hash={rootHash} /> : null}

      {record.mode === 'sign' && signSignatureValue ? (
        <HashDisplay
          hash={signSignatureValue}
          label={
            signSignatureScheme
              ? signSignatureKeyId
                ? `Manifest Signature (${signSignatureScheme}) [${signSignatureKeyId}]`
                : `Manifest Signature (${signSignatureScheme})`
              : signSignatureKeyId
                ? `Manifest Signature [${signSignatureKeyId}]`
                : 'Manifest Signature'
          }
        />
      ) : null}

      {record.mode === 'verify' && verifySignature && typeof verifySignature?.valid === 'boolean' ? (
        <div className="flex items-center justify-between bg-card border border-border rounded p-4">
          <div>
            <div className="text-xs text-muted-foreground mb-1">Manifest Signature</div>
            <div
              className={`text-sm font-mono ${verifySignature.valid ? 'text-success' : 'text-destructive'}`}
            >
              {verifySignature.valid ? 'VALID' : 'INVALID'}
              {verifySignature.scheme ? ` (${String(verifySignature.scheme)})` : ''}
              {verifySignature.key_id ? ` [${String(verifySignature.key_id)}]` : ''}
              {!verifySignature.valid && verifySignature.reason ? ` — ${String(verifySignature.reason)}` : ''}
            </div>

            {(verifyManifestMode || verifyChainScheme || verifyHashAlgorithm) && (
              <div className="text-xs text-muted-foreground font-mono mt-2 space-y-1">
                {verifyManifestMode ? <div>manifest_mode: {verifyManifestMode}</div> : null}
                {verifyChainScheme ? <div>chain_scheme: {verifyChainScheme}</div> : null}
                {verifyHashAlgorithm ? <div>hash_algorithm: {verifyHashAlgorithm}</div> : null}
              </div>
            )}
          </div>
        </div>
      ) : null}

      {record.mode === 'scan' && scanStats ? (
        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-lg font-semibold text-foreground mb-4">Scan Statistics</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <div className="text-xs text-muted-foreground mb-1">Timestamps Found</div>
              <div className="text-xl font-semibold text-foreground">{Number(scanStats?.timestamps_found ?? 0).toLocaleString()}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Malformed Lines</div>
              <div className="text-xl font-semibold text-foreground">{Number(scanStats?.malformed_lines ?? 0).toLocaleString()}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Gap Threshold (sec)</div>
              <div className="text-xl font-semibold text-foreground">{Number(scanStats?.threshold_seconds ?? scanDetails?.gapThreshold ?? 0)}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Timestamp Anomalies</div>
              <div className="text-xl font-semibold text-foreground">{Number(scanStats?.timestamp_anomalies ?? scanAnomalies ?? 0).toLocaleString()}</div>
            </div>
            {scanStats?.first_timestamp ? (
              <div className="sm:col-span-2">
                <div className="text-xs text-muted-foreground mb-1">First Timestamp</div>
                <div className="text-sm font-mono text-foreground">{formatIsoForDisplay(String(scanStats.first_timestamp))}</div>
              </div>
            ) : null}
            {scanStats?.last_timestamp ? (
              <div className="sm:col-span-2">
                <div className="text-xs text-muted-foreground mb-1">Last Timestamp</div>
                <div className="text-sm font-mono text-foreground">{formatIsoForDisplay(String(scanStats.last_timestamp))}</div>
              </div>
            ) : null}
            {typeof scanStats?.max_gap_seconds === 'number' ? (
              <div>
                <div className="text-xs text-muted-foreground mb-1">Max Gap (sec)</div>
                <div className="text-xl font-semibold text-foreground">{Number(scanStats.max_gap_seconds).toLocaleString()}</div>
              </div>
            ) : null}
            {typeof scanStats?.max_anomaly_seconds === 'number' ? (
              <div>
                <div className="text-xs text-muted-foreground mb-1">Max Anomaly (sec)</div>
                <div className="text-xl font-semibold text-foreground">{Number(scanStats.max_anomaly_seconds).toLocaleString()}</div>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}

      {record.mode === 'sign' && signDetails?.manifest ? (
        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-lg font-semibold text-foreground mb-4">Signing Details</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <div className="text-xs text-muted-foreground mb-1">Signed At</div>
              <div className="text-sm font-mono text-foreground">{formatIsoForDisplay(String((signDetails as any)?.manifest?.signed_at ?? '')) || '—'}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Manifest Mode</div>
              <div className="text-sm font-mono text-foreground">{String((signDetails as any)?.manifest?.manifest_mode ?? '') || '—'}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Chain Scheme</div>
              <div className="text-sm font-mono text-foreground">{String((signDetails as any)?.manifest?.chain_scheme ?? '') || '—'}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Hash Algorithm</div>
              <div className="text-sm font-mono text-foreground">{String((signDetails as any)?.manifest?.hash_algorithm ?? '') || '—'}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Checkpoint Every</div>
              <div className="text-sm font-mono text-foreground">{String((signDetails as any)?.manifest?.checkpoint_every ?? '') || '—'}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Entries</div>
              <div className="text-sm font-mono text-foreground">{Number((signDetails as any)?.manifest?.entry_count ?? 0).toLocaleString()}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Checkpoints</div>
              <div className="text-sm font-mono text-foreground">{Number((signDetails as any)?.manifest?.checkpoint_count ?? 0).toLocaleString()}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Total Lines</div>
              <div className="text-sm font-mono text-foreground">{Number((signDetails as any)?.manifest?.total_lines ?? record.lines ?? 0).toLocaleString()}</div>
            </div>
          </div>
        </div>
      ) : null}

      {record.mode === 'verify' && verifyReport ? (
        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-lg font-semibold text-foreground mb-4">Verification Details</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <div className="text-xs text-muted-foreground mb-1">Manifest Mode</div>
              <div className="text-sm font-mono text-foreground">{String(verifyReport?.manifest_mode ?? '') || '—'}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Chain Scheme</div>
              <div className="text-sm font-mono text-foreground">{String(verifyReport?.chain_scheme ?? '') || '—'}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Hash Algorithm</div>
              <div className="text-sm font-mono text-foreground">{String(verifyReport?.hash_algorithm ?? '') || '—'}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Issues Found</div>
              <div className="text-sm font-mono text-foreground">{Number(verifyReport?.issues_found ?? issues.length ?? 0).toLocaleString()}</div>
            </div>
            {verifyReport?.signed_at ? (
              <div className="sm:col-span-2">
                <div className="text-xs text-muted-foreground mb-1">Signed At</div>
                <div className="text-sm font-mono text-foreground">{formatIsoForDisplay(String(verifyReport.signed_at))}</div>
              </div>
            ) : null}
            {verifyReport?.verified_at ? (
              <div className="sm:col-span-2">
                <div className="text-xs text-muted-foreground mb-1">Verified At</div>
                <div className="text-sm font-mono text-foreground">{formatIsoForDisplay(String(verifyReport.verified_at))}</div>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}

      {record.mode === 'ghost' && ghostReport ? (
        <div className="bg-card border border-border rounded-lg p-6 space-y-4">
          <h2 className="text-lg font-semibold text-foreground">Ghost Protocol Summary</h2>

          {ghostAction && ghostAction !== 'analyze' ? (
            <div className="text-xs text-muted-foreground font-mono">operation: {String(ghostAction)}</div>
          ) : null}

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <div className="text-xs text-muted-foreground mb-1">Baseline Used</div>
              <div className="text-sm font-mono text-foreground">{ghostBaselineUsed ? 'yes' : 'no'}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Risk Score</div>
              <div className="text-sm font-mono text-foreground">{Number.isFinite(ghostRiskScore) ? ghostRiskScore : 0}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Signals</div>
              <div className="text-sm font-mono text-foreground">{ghostEvents.length.toLocaleString()}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Source</div>
              <div className="text-sm font-mono text-foreground">{String(ghostReport?.source_file_name ?? record.file) || '—'}</div>
            </div>
          </div>

          {ghostExplainabilityCards.length ? (
            <div className="pt-1 space-y-2">
              <div className="text-xs text-muted-foreground">Explainability Events</div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
                {ghostExplainabilityCards.map((card) => (
                  <div key={card.id} className="rounded border border-border bg-background p-3 space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-xs font-mono text-foreground">{card.signal}</div>
                      <span className={`px-2 py-0.5 text-[10px] border rounded uppercase tracking-wider ${severityTone(card.severity)}`}>
                        {card.severity}
                      </span>
                    </div>
                    <div className="text-xs text-muted-foreground font-mono">lines: {card.lineRange}</div>
                    {card.message ? <div className="text-xs text-foreground">{card.message}</div> : null}
                    {card.evidence ? <div className="text-[11px] text-muted-foreground font-mono break-all">evidence: {card.evidence}</div> : null}
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {ghostSignalCounts.length ? (
            <div className="pt-2">
              <div className="text-xs text-muted-foreground mb-2">Top Signals</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {ghostSignalCounts.map((row) => (
                  <div key={row.signal} className="flex items-center justify-between px-3 py-2 bg-background border border-border rounded">
                    <div className="text-xs font-mono text-foreground">{row.signal}</div>
                    <div className="text-xs font-mono text-muted-foreground">{row.count}</div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-sm text-muted-foreground">No signals emitted.</div>
          )}
        </div>
      ) : record.mode === 'ghost' && ghostAction === 'baseline' && ghostBaseline ? (
        <div className="bg-card border border-border rounded-lg p-6 space-y-4">
          <h2 className="text-lg font-semibold text-foreground">Ghost Baseline</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <div className="text-xs text-muted-foreground mb-1">Total Lines</div>
              <div className="text-sm font-mono text-foreground">{Number(ghostBaseline?.total_lines ?? 0).toLocaleString()}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Timestamps Found</div>
              <div className="text-sm font-mono text-foreground">{Number(ghostBaseline?.timestamps_found ?? 0).toLocaleString()}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Malformed Lines</div>
              <div className="text-sm font-mono text-foreground">{Number(ghostBaseline?.malformed_lines ?? 0).toLocaleString()}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Created At</div>
              <div className="text-sm font-mono text-foreground">{formatIsoForDisplay(String(ghostBaseline?.created_at ?? '')) || '—'}</div>
            </div>
          </div>

          <div className="text-xs text-muted-foreground font-mono space-y-1">
            {typeof ghostBaseline?.entropy_mean === 'number' ? <div>entropy_mean: {Number(ghostBaseline.entropy_mean).toFixed(4)}</div> : null}
            {typeof ghostBaseline?.entropy_stdev === 'number' ? <div>entropy_stdev: {Number(ghostBaseline.entropy_stdev).toFixed(4)}</div> : null}
            {typeof ghostBaseline?.interval_mean === 'number' ? <div>interval_mean: {Number(ghostBaseline.interval_mean).toFixed(4)}</div> : null}
            {typeof ghostBaseline?.interval_stdev === 'number' ? <div>interval_stdev: {Number(ghostBaseline.interval_stdev).toFixed(4)}</div> : null}
          </div>
        </div>
      ) : record.mode === 'ghost' && ghostAction === 'receipts' && ghostReceipts.length ? (
        <div className="bg-card border border-border rounded-lg p-6 space-y-4">
          <h2 className="text-lg font-semibold text-foreground">Ghost Receipts</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <div className="text-xs text-muted-foreground mb-1">Receipts</div>
              <div className="text-sm font-mono text-foreground">{ghostReceipts.length.toLocaleString()}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Created At</div>
              <div className="text-sm font-mono text-foreground">{formatIsoForDisplay(String(ghostReceipts?.[0]?.created_at ?? '')) || '—'}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">Kinds</div>
              <div className="text-sm font-mono text-foreground">{ghostReceiptsSummary.counts.length ? ghostReceiptsSummary.counts.map((c) => c.kind).join(', ') : '—'}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">File Size</div>
              <div className="text-sm font-mono text-foreground">{ghostReceiptsSummary.file?.data?.size_bytes ? Number(ghostReceiptsSummary.file.data.size_bytes).toLocaleString() : '—'}</div>
            </div>
          </div>

          {ghostReceiptsSummary.counts.length ? (
            <div className="pt-2">
              <div className="text-xs text-muted-foreground mb-2">Receipt Kinds</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {ghostReceiptsSummary.counts.map((row) => (
                  <div key={row.kind} className="flex items-center justify-between px-3 py-2 bg-background border border-border rounded">
                    <div className="text-xs font-mono text-foreground">{row.kind}</div>
                    <div className="text-xs font-mono text-muted-foreground">{row.count}</div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-sm text-muted-foreground">No receipt items.</div>
          )}
        </div>
      ) : null}

      {record.mode === 'sign' && signCompositionData.length ? (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-border flex items-center justify-between">
            <h2 className="text-lg font-semibold text-foreground">Manifest Composition</h2>
            <div className="text-xs text-muted-foreground font-mono">
              {(signDetails as any)?.manifest?.manifest_mode ? `mode: ${String((signDetails as any).manifest.manifest_mode)}` : ''}
            </div>
          </div>
          <div className="p-6">
            <ChartContainer
              className="w-full aspect-auto h-[220px]"
              config={{
                count: { label: 'Count', color: 'hsl(var(--primary))' },
              }}
            >
              <BarChart data={signCompositionData} margin={{ left: 12, right: 12 }}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="kind" tickLine={false} axisLine={false} />
                <YAxis allowDecimals={false} />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Bar dataKey="count" fill="var(--color-count, hsl(var(--primary)))" radius={4} />
              </BarChart>
            </ChartContainer>
          </div>
        </div>
      ) : record.mode === 'sign' ? (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-border flex items-center justify-between">
            <h2 className="text-lg font-semibold text-foreground">Manifest Composition</h2>
          </div>
          <div className="p-6 text-sm text-muted-foreground">No manifest composition data to chart (run Sign again to generate entry/checkpoint counts).</div>
        </div>
      ) : null}

      {record.mode === 'scan' && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-border flex items-center justify-between">
            <h2 className="text-lg font-semibold text-foreground">Timeline Gaps</h2>
            <div className="px-3 py-1 bg-warning/10 border border-warning/30 rounded text-sm text-warning">
              {scanGaps.length} gaps found
            </div>
          </div>
          <div className="p-6 border-b border-border">
            <div className="text-xs text-muted-foreground mb-3">
              {scanGapChartData.length
                ? `Gap durations (first ${scanGapChartData.length} gaps)`
                : 'No gaps to chart (gap table below may still show anomalies).'}
            </div>
            {scanGapChartData.length ? (
              <ChartContainer
                className="w-full aspect-auto h-[240px]"
                config={{
                  duration: { label: 'Duration (sec)', color: 'hsl(var(--primary))' },
                }}
              >
                <BarChart data={scanGapChartData} margin={{ left: 12, right: 12 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="gap" tickLine={false} axisLine={false} interval={0} hide={scanGapChartData.length > 18} />
                  <YAxis allowDecimals={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="duration" fill="var(--color-duration, hsl(var(--primary)))" radius={4} />
                </BarChart>
              </ChartContainer>
            ) : null}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-background border-b border-border">
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Gap #</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Start Time</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">End Time</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Duration (sec)</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Lines</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Note</th>
                </tr>
              </thead>
              <tbody>
                {scanGaps.map((gap, index) => {
                  const idNum = gap.gap_index ?? index + 1;
                  const lineStart = Number(gap.line_start ?? 0);
                  const lineEnd = Number(gap.line_end ?? 0);
                  const lineCount = lineStart && lineEnd && lineEnd >= lineStart ? lineEnd - lineStart + 1 : 0;
                  const isAnomaly = gap.note === 'TIMESTAMP_ANOMALY';
                  return (
                    <tr
                      key={String(idNum)}
                      className={`border-b border-border hover:bg-secondary transition-colors ${
                        isAnomaly ? 'bg-destructive/5' : index % 2 === 0 ? 'bg-background' : 'bg-card'
                      }`}
                    >
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground font-mono">#{idNum}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground font-mono">
                        {formatIsoForDisplay(gap.gap_start)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground font-mono">
                        {formatIsoForDisplay(gap.gap_end)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground">
                        {Number(gap.duration_seconds ?? 0)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground">{lineCount}</td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        {gap.note ? (
                          <span className="px-2 py-1 bg-destructive/10 text-destructive rounded text-xs font-mono">
                            {gap.note}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {record.mode === 'verify' && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-border flex items-center justify-between">
            <h2 className="text-lg font-semibold text-foreground">Integrity Issues</h2>
            <div className={`px-3 py-1 rounded text-sm border ${
              issues.length
                ? 'bg-destructive/10 border-destructive/30 text-destructive'
                : 'bg-success/10 border-success/30 text-success'
            }`}>
              {issues.length} issue(s)
            </div>
          </div>

          {verifyIssueHistogram.length ? (
            <div className="p-6 border-b border-border">
              <div className="text-xs text-muted-foreground mb-3">Issue distribution by line number range</div>
              <ChartContainer
                className="w-full aspect-auto h-[240px]"
                config={{
                  count: { label: 'Issues', color: 'hsl(var(--primary))' },
                }}
              >
                <BarChart data={verifyIssueHistogram} margin={{ left: 12, right: 12 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="bucket" tickLine={false} axisLine={false} interval={0} hide={verifyIssueHistogram.length > 14} />
                  <YAxis allowDecimals={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="count" fill="var(--color-count, hsl(var(--primary)))" radius={4} />
                </BarChart>
              </ChartContainer>
            </div>
          ) : issues.length ? (
            <div className="p-6 border-b border-border text-sm text-muted-foreground">No line-number data available to chart.</div>
          ) : null}

          {verifyIssueTypeData.length > 1 ? (
            <div className="p-6 border-b border-border">
              <div className="text-xs text-muted-foreground mb-3">Issue types</div>
              <ChartContainer
                className="w-full aspect-auto h-[220px]"
                config={{
                  count: { label: 'Count', color: 'hsl(var(--primary))' },
                }}
              >
                <BarChart data={verifyIssueTypeData} margin={{ left: 12, right: 12 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="status" tickLine={false} axisLine={false} interval={0} hide={verifyIssueTypeData.length > 10} />
                  <YAxis allowDecimals={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="count" fill="var(--color-count, hsl(var(--primary)))" radius={4} />
                </BarChart>
              </ChartContainer>
            </div>
          ) : null}

          {issues.length ? (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-background border-b border-border">
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Line #</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Expected Hash</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Actual Hash</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {issues.map((issue: any, index: number) => (
                    <tr
                      key={String(issue?.line_number ?? index)}
                      className={`border-b border-border hover:bg-secondary transition-colors ${
                        index % 2 === 0 ? 'bg-background' : 'bg-card'
                      }`}
                    >
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground font-mono">
                        {typeof issue?.line_number === 'number' ? Number(issue.line_number) : '—'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground font-mono">
                        {String(issue?.expected_chain_hash ?? '') || '—'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground font-mono">
                        {String(issue?.actual_chain_hash ?? '') || '—'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        <span className="px-2 py-1 bg-destructive/10 text-destructive rounded text-xs font-semibold">
                          {String(issue?.status ?? 'MISMATCH')}
                        </span>
                        {issue?.note ? (
                          <div className="text-xs text-muted-foreground font-mono mt-1">
                            {String(issue.note)}
                          </div>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-16">
              <p className="text-muted-foreground">No integrity issues detected.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
