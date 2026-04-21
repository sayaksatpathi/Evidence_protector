import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from '../router';
import { Download, Camera, ClipboardCheck, Package2, Copy, Printer, ExternalLink } from 'lucide-react';
import { formatTimestamp, getHistoryRecords } from '../lib/history';
import { buildReleaseEvidenceMarkdown, buildReleaseEvidencePack, getBaselineCollections } from '../lib/organizer';

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

export function ReleaseEvidence() {
  const navigate = useNavigate();
  const [captured, setCaptured] = useState<Record<string, boolean>>(() => {
    try {
      return JSON.parse(localStorage.getItem('evidenceProtector.releaseEvidence.captured.v1') || '{}');
    } catch {
      return {};
    }
  });

  const pack = useMemo(() => buildReleaseEvidencePack(), []);
  const markdown = useMemo(() => buildReleaseEvidenceMarkdown(pack), [pack]);
  const collections = useMemo(() => getBaselineCollections(), []);
  const history = useMemo(() => getHistoryRecords(), []);
  const latestReportId = history[0]?.id;

  useEffect(() => {
    try {
      localStorage.setItem('evidenceProtector.releaseEvidence.captured.v1', JSON.stringify(captured));
    } catch {
      // Best effort only.
    }
  }, [captured]);

  const capturedCount = Object.values(captured).filter(Boolean).length;

  const checklistText = useMemo(() => {
    const lines: string[] = [];
    lines.push('Evidence Protector release evidence checklist');
    lines.push(`Created at: ${formatTimestamp(new Date(pack.createdAt))}`);
    lines.push('');
    for (const shot of pack.requiredScreenshots) {
      lines.push(`[ ] ${shot.name} — ${shot.description}`);
    }
    lines.push('');
    lines.push('Suggested capture order: Dashboard → Report → Baselines → Compare → Evidence pack');
    return lines.join('\n') + '\n';
  }, [pack.createdAt, pack.requiredScreenshots]);

  const copyChecklist = async () => {
    try {
      await navigator.clipboard.writeText(checklistText);
    } catch {
      // ignore
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground mb-2">Release Evidence Capture</h1>
          <p className="text-muted-foreground">Build a manual proof pack and track the screenshots that still need to be captured.</p>
          <p className="text-xs text-muted-foreground font-mono mt-1">{capturedCount.toLocaleString()} of {pack.requiredScreenshots.length} screenshot steps completed</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => navigate('/')}
            className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm inline-flex items-center gap-2"
          >
            <ExternalLink className="w-4 h-4" />
            Dashboard
          </button>
          <button
            onClick={() => navigate('/history')}
            className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm inline-flex items-center gap-2"
          >
            <ExternalLink className="w-4 h-4" />
            History
          </button>
          <button
            onClick={() => navigate('/baselines')}
            className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm inline-flex items-center gap-2"
          >
            <ExternalLink className="w-4 h-4" />
            Baselines
          </button>
          <button
            onClick={() => navigate('/compare')}
            className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm inline-flex items-center gap-2"
          >
            <ExternalLink className="w-4 h-4" />
            Compare
          </button>
          {latestReportId ? (
            <button
              onClick={() => navigate(`/results/${latestReportId}`)}
              className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm inline-flex items-center gap-2"
            >
              <ExternalLink className="w-4 h-4" />
              Latest report
            </button>
          ) : null}
          <Link to="/guide" className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm">Walkthrough</Link>
          <Link to="/baselines" className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm">Baselines</Link>
          <button
            onClick={() => downloadText('release-evidence-pack.json', JSON.stringify(pack, null, 2) + '\n', 'application/json')}
            className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm flex items-center gap-2"
          >
            <Package2 className="w-4 h-4" />
            JSON Pack
          </button>
          <button
            onClick={() => downloadText('release-evidence-pack.md', markdown, 'text/markdown')}
            className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            Markdown Pack
          </button>
          <button
            onClick={copyChecklist}
            className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm flex items-center gap-2"
          >
            <Copy className="w-4 h-4" />
            Copy checklist
          </button>
          <button
            onClick={() => window.print()}
            className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm flex items-center gap-2"
          >
            <Printer className="w-4 h-4" />
            Print page
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="bg-card border border-border rounded-lg p-4"><div className="text-xs text-muted-foreground mb-1">History records</div><div className="text-2xl font-semibold text-foreground">{history.length.toLocaleString()}</div></div>
        <div className="bg-card border border-border rounded-lg p-4"><div className="text-xs text-muted-foreground mb-1">Baseline collections</div><div className="text-2xl font-semibold text-foreground">{collections.length.toLocaleString()}</div></div>
        <div className="bg-card border border-border rounded-lg p-4"><div className="text-xs text-muted-foreground mb-1">Screenshot steps</div><div className="text-2xl font-semibold text-foreground">{pack.requiredScreenshots.length.toLocaleString()}</div></div>
        <div className="bg-card border border-border rounded-lg p-4"><div className="text-xs text-muted-foreground mb-1">Completed</div><div className="text-2xl font-semibold text-foreground">{capturedCount.toLocaleString()}</div></div>
      </div>

      <div className="bg-card border border-border rounded-lg p-6 space-y-4">
        <div className="flex items-center gap-2">
          <ClipboardCheck className="w-5 h-5 text-primary" />
          <h2 className="text-lg font-semibold text-foreground">Screenshot checklist</h2>
        </div>
        <p className="text-sm text-muted-foreground">Mark each screenshot as captured after you save it in your release folder. The proof pack keeps the checklist and history summary together.</p>

        <div className="rounded-lg border border-border bg-background p-4 text-sm text-muted-foreground space-y-2">
          <div className="font-medium text-foreground">Suggested capture order</div>
          <div className="font-mono">1. Dashboard</div>
          <div className="font-mono">2. Latest report</div>
          <div className="font-mono">3. Baseline organizer</div>
          <div className="font-mono">4. Compare view</div>
          <div className="font-mono">5. Release evidence pack</div>
        </div>

        <div className="space-y-3">
          {pack.requiredScreenshots.map((shot) => (
            <label key={shot.name} className="flex items-start gap-3 p-3 rounded-lg border border-border bg-background cursor-pointer">
              <input
                type="checkbox"
                checked={Boolean(captured[shot.name])}
                onChange={(e) => setCaptured((current) => ({ ...current, [shot.name]: e.target.checked }))}
                className="mt-1"
              />
              <div className="flex-1">
                <div className="font-medium text-foreground">{shot.name}</div>
                <div className="text-sm text-muted-foreground">{shot.description}</div>
              </div>
              <Camera className={`w-4 h-4 ${captured[shot.name] ? 'text-success' : 'text-muted-foreground'}`} />
            </label>
          ))}
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => setCaptured(Object.fromEntries(pack.requiredScreenshots.map((shot) => [shot.name, true])))}
            className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm"
          >
            Mark all captured
          </button>
          <button
            onClick={() => setCaptured({})}
            className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm"
          >
            Reset checklist
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-card border border-border rounded-lg p-6 space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Recent history snapshot</h2>
          <div className="space-y-2 text-sm">
            {pack.recentHistory.map((item) => (
              <div key={item.id} className="flex items-center justify-between gap-3 px-3 py-2 rounded-md bg-background border border-border">
                <div>
                  <div className="font-mono text-foreground">{item.file}</div>
                  <div className="text-xs text-muted-foreground">{item.timestamp} · {item.mode.toUpperCase()}</div>
                </div>
                <div className="text-xs font-mono text-muted-foreground">{item.status}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-card border border-border rounded-lg p-6 space-y-3">
          <h2 className="text-lg font-semibold text-foreground">Export notes</h2>
          <p className="text-sm text-muted-foreground">The JSON pack and markdown pack are designed to travel with screenshots, so a reviewer can see the evidence state that was captured during release.</p>
          <div className="text-xs text-muted-foreground font-mono space-y-1">
            <div>created_at: {formatTimestamp(new Date(pack.createdAt))}</div>
            <div>app_version: {pack.appVersion}</div>
            <div>history_count: {pack.historyCount}</div>
            <div>baseline_count: {pack.baselineCount}</div>
            <div>collections_count: {pack.collectionsCount}</div>
          </div>
        </div>
      </div>
    </div>
  );
}
