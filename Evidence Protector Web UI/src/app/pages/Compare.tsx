import { useMemo, useState } from 'react';
import { Link } from '../router';
import { Download, GitCompareArrows } from 'lucide-react';
import { getHistoryRecords, type HistoryRecord, type GhostReport } from '../lib/history';
import { ChartContainer, ChartTooltip, ChartTooltipContent } from '../components/ui/chart';
import { CartesianGrid, Line, LineChart, XAxis, YAxis } from 'recharts';

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

function label(record: HistoryRecord) {
  return `${record.timestamp} · ${record.mode.toUpperCase()} · ${record.file}`;
}

function summarize(record: HistoryRecord) {
  const scan = record.details?.scan;
  const sign = record.details?.sign;
  const verify = record.details?.verify;
  const ghost = record.details?.ghost;
  const ghostReport = ghost?.report as GhostReport | undefined;

  return {
    mode: record.mode,
    status: record.status,
    lines: Number(record.lines ?? 0),
    gaps: Number(record.gaps ?? 0),
    scan: {
      timestampsFound: Number(scan?.stats?.timestamps_found ?? 0),
      malformedLines: Number(scan?.stats?.malformed_lines ?? 0),
      gapThreshold: Number(scan?.gapThreshold ?? scan?.stats?.threshold_seconds ?? 0),
      maxGapSeconds: Number(scan?.stats?.max_gap_seconds ?? 0),
      anomalies: Number(scan?.stats?.timestamp_anomalies ?? 0),
    },
    sign: {
      rootHash: String(sign?.rootHash ?? sign?.manifest?.root_hash ?? ''),
      manifestMode: String(sign?.manifest?.manifest_mode ?? ''),
      chainScheme: String(sign?.manifest?.chain_scheme ?? ''),
      signatureScheme: String(sign?.manifest?.signature?.scheme ?? ''),
      entries: Number(sign?.manifest?.entry_count ?? 0),
      checkpoints: Number(sign?.manifest?.checkpoint_count ?? 0),
    },
    verify: {
      clean: Boolean(verify?.report?.clean),
      issuesFound: Number(verify?.report?.issues_found ?? 0),
      currentRootHash: String(verify?.report?.current_root_hash ?? ''),
      signatureValid: verify?.report?.manifest_signature?.valid,
      signatureReason: String(verify?.report?.manifest_signature?.reason ?? ''),
    },
    ghost: {
      action: String(ghost?.action ?? 'analyze'),
      baselineUsed: Boolean(ghostReport?.baseline_used),
      riskScore: Number(ghostReport?.summary?.risk_score ?? 0),
      events: Array.isArray(ghostReport?.events) ? ghostReport.events.length : 0,
      totalLines: Number(ghostReport?.summary?.total_lines ?? 0),
      timestampsFound: Number(ghostReport?.summary?.timestamps_found ?? 0),
      bigGaps: Number(ghostReport?.summary?.big_gaps ?? 0),
      timeReversals: Number(ghostReport?.summary?.time_reversals ?? 0),
      signalCounts: (ghostReport?.summary?.event_counts ?? {}) as Record<string, unknown>,
    },
  };
}

function metricRows(left: any, right: any) {
  return [
    { label: 'Mode', left: left.mode, right: right.mode },
    { label: 'Status', left: left.status, right: right.status },
    { label: 'Lines', left: left.lines, right: right.lines },
    { label: 'Gaps', left: left.gaps, right: right.gaps },
    { label: 'Scan timestamps', left: left.scan.timestampsFound, right: right.scan.timestampsFound },
    { label: 'Scan malformed', left: left.scan.malformedLines, right: right.scan.malformedLines },
    { label: 'Verify issues', left: left.verify.issuesFound, right: right.verify.issuesFound },
    { label: 'Verify clean', left: left.verify.clean ? 'yes' : 'no', right: right.verify.clean ? 'yes' : 'no' },
    { label: 'Manifest root', left: left.sign.rootHash || '—', right: right.sign.rootHash || '—' },
    { label: 'Ghost risk', left: left.ghost.riskScore, right: right.ghost.riskScore },
    { label: 'Ghost signals', left: left.ghost.events, right: right.ghost.events },
    { label: 'Ghost time reversals', left: left.ghost.timeReversals, right: right.ghost.timeReversals },
  ];
}

function diffValue(left: unknown, right: unknown): string {
  if (left === right) return 'Same';
  if (typeof left === 'number' && typeof right === 'number') {
    const delta = right - left;
    return delta > 0 ? `+${delta}` : String(delta);
  }
  return 'Different';
}

function compareMarkdown(leftRecord: HistoryRecord, rightRecord: HistoryRecord, left: any, right: any) {
  return [
    '# Evidence Protector Report Comparison',
    '',
    `- Left: ${label(leftRecord)}`,
    `- Right: ${label(rightRecord)}`,
    '',
    '## Metrics',
    ...metricRows(left, right).map((row) => `- ${row.label}: ${String(row.left)} → ${String(row.right)} (${diffValue(row.left, row.right)})`),
    '',
  ].join('\n') + '\n';
}

function buildTimelineSeries(record?: HistoryRecord): Array<{ idx: number; value: number }> {
  if (!record) return [];
  if (record.mode === 'scan') {
    const gaps = Array.isArray(record.details?.scan?.gaps) ? record.details?.scan?.gaps : [];
    return gaps.slice(0, 80).map((g, idx) => ({ idx: idx + 1, value: Number(g?.duration_seconds ?? 0) }));
  }
  if (record.mode === 'verify') {
    const issues = Array.isArray(record.details?.verify?.report?.issues) ? record.details?.verify?.report?.issues : [];
    return issues.slice(0, 80).map((i: any, idx: number) => ({ idx: idx + 1, value: Number(i?.line_number ?? 0) }));
  }
  if (record.mode === 'ghost') {
    const events = Array.isArray((record.details?.ghost?.report as any)?.events) ? ((record.details?.ghost?.report as any)?.events as any[]) : [];
    return events.slice(0, 80).map((e: any, idx: number) => {
      const sev = String(e?.severity ?? 'low').toLowerCase();
      const weight = sev === 'critical' ? 4 : sev === 'high' ? 3 : sev === 'medium' ? 2 : 1;
      return { idx: idx + 1, value: weight };
    });
  }
  return [];
}

export function Compare() {
  const records = useMemo(() => getHistoryRecords(), []);
  const defaultLeft = records[0]?.id ?? '';
  const defaultRight = records[1]?.id ?? records[0]?.id ?? '';
  const [leftId, setLeftId] = useState(defaultLeft);
  const [rightId, setRightId] = useState(defaultRight);

  const leftRecord = records.find((record) => record.id === leftId) ?? records[0];
  const rightRecord = records.find((record) => record.id === rightId) ?? records[1] ?? records[0];

  const left = leftRecord ? summarize(leftRecord) : undefined;
  const right = rightRecord ? summarize(rightRecord) : undefined;
  const canCompare = Boolean(leftRecord && rightRecord);

  const jsonText = canCompare
    ? JSON.stringify({ leftRecord, rightRecord, comparison: metricRows(left, right) }, null, 2) + '\n'
    : '';
  const mdText = canCompare ? compareMarkdown(leftRecord, rightRecord, left, right) : '';

  const timelineOverlayData = useMemo(() => {
    if (!canCompare) return [] as Array<{ point: string; left: number | null; right: number | null }>;
    const leftSeries = buildTimelineSeries(leftRecord);
    const rightSeries = buildTimelineSeries(rightRecord);
    const size = Math.max(leftSeries.length, rightSeries.length, 0);
    const out: Array<{ point: string; left: number | null; right: number | null }> = [];
    for (let i = 0; i < size; i++) {
      out.push({
        point: `#${i + 1}`,
        left: typeof leftSeries[i]?.value === 'number' ? leftSeries[i].value : null,
        right: typeof rightSeries[i]?.value === 'number' ? rightSeries[i].value : null,
      });
    }
    return out;
  }, [canCompare, leftRecord, rightRecord]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground mb-2">Report Comparison</h1>
          <p className="text-muted-foreground">Compare any two history records side by side, including Ghost reports and baseline metadata.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Link to="/baselines" className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm">
            Baselines
          </Link>
          <Link to="/release-evidence" className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm">
            Evidence pack
          </Link>
          <button
            disabled={!canCompare}
            onClick={() => downloadText('report-comparison.json', jsonText, 'application/json')}
            className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 disabled:opacity-50 transition-colors text-sm flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            JSON
          </button>
          <button
            disabled={!canCompare}
            onClick={() => downloadText('report-comparison.md', mdText, 'text/markdown')}
            className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 disabled:opacity-50 transition-colors text-sm flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            Markdown
          </button>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-6 space-y-4">
        <div className="flex items-center gap-2">
          <GitCompareArrows className="w-5 h-5 text-primary" />
          <h2 className="text-lg font-semibold text-foreground">Pick two records</h2>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-sm text-foreground">Left record</label>
            <select
              value={leftId}
              onChange={(e) => setLeftId(e.target.value)}
              className="w-full px-4 py-2 bg-background border border-border rounded-md text-foreground focus:border-primary focus:outline-none transition-colors"
            >
              {records.map((record) => (
                <option key={record.id} value={record.id}>{label(record)}</option>
              ))}
            </select>
          </div>
          <div className="space-y-2">
            <label className="text-sm text-foreground">Right record</label>
            <select
              value={rightId}
              onChange={(e) => setRightId(e.target.value)}
              className="w-full px-4 py-2 bg-background border border-border rounded-md text-foreground focus:border-primary focus:outline-none transition-colors"
            >
              {records.map((record) => (
                <option key={record.id} value={record.id}>{label(record)}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {!canCompare ? (
        <div className="p-6 rounded-lg border border-dashed border-border text-muted-foreground">
          Add a few records first, then use this page to compare them.
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-card border border-border rounded-lg p-6 space-y-3">
              <div className="text-xs uppercase tracking-wider text-muted-foreground">Left</div>
              <div className="text-lg font-semibold text-foreground">{leftRecord.file}</div>
              <div className="text-xs text-muted-foreground font-mono">{leftRecord.timestamp}</div>
              <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                <span className="px-2.5 py-1 rounded-full border border-border bg-secondary/60">{left.mode.toUpperCase()}</span>
                <span className="px-2.5 py-1 rounded-full border border-border bg-secondary/60">{left.status}</span>
              </div>
            </div>
            <div className="bg-card border border-border rounded-lg p-6 space-y-3">
              <div className="text-xs uppercase tracking-wider text-muted-foreground">Right</div>
              <div className="text-lg font-semibold text-foreground">{rightRecord.file}</div>
              <div className="text-xs text-muted-foreground font-mono">{rightRecord.timestamp}</div>
              <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                <span className="px-2.5 py-1 rounded-full border border-border bg-secondary/60">{right.mode.toUpperCase()}</span>
                <span className="px-2.5 py-1 rounded-full border border-border bg-secondary/60">{right.status}</span>
              </div>
            </div>
          </div>

          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="bg-background border-b border-border">
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Metric</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Left</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Right</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Delta</th>
                </tr>
              </thead>
              <tbody>
                {metricRows(left, right).map((row) => (
                  <tr key={row.label} className="border-b border-border">
                    <td className="px-6 py-4 text-sm text-foreground">{row.label}</td>
                    <td className="px-6 py-4 text-sm text-foreground font-mono">{String(row.left)}</td>
                    <td className="px-6 py-4 text-sm text-foreground font-mono">{String(row.right)}</td>
                    <td className="px-6 py-4 text-sm text-muted-foreground font-mono">{diffValue(row.left, row.right)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-border flex items-center justify-between">
              <h2 className="text-lg font-semibold text-foreground">Timeline Overlay</h2>
              <div className="text-xs text-muted-foreground">Left vs Right event progression</div>
            </div>
            <div className="p-6">
              {timelineOverlayData.length ? (
                <ChartContainer
                  className="w-full aspect-auto h-[260px]"
                  config={{
                    left: { label: 'Left', color: 'hsl(var(--primary))' },
                    right: { label: 'Right', color: 'hsl(var(--warning))' },
                  }}
                >
                  <LineChart data={timelineOverlayData} margin={{ left: 12, right: 12 }}>
                    <CartesianGrid vertical={false} />
                    <XAxis dataKey="point" tickLine={false} axisLine={false} interval={0} hide={timelineOverlayData.length > 18} />
                    <YAxis allowDecimals={false} />
                    <ChartTooltip content={<ChartTooltipContent />} />
                    <Line dataKey="left" connectNulls type="monotone" stroke="var(--color-left, hsl(var(--primary)))" strokeWidth={2} dot={false} />
                    <Line dataKey="right" connectNulls type="monotone" stroke="var(--color-right, hsl(var(--warning)))" strokeWidth={2} dot={false} />
                  </LineChart>
                </ChartContainer>
              ) : (
                <div className="text-sm text-muted-foreground">No timeline points available for this pair.</div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
