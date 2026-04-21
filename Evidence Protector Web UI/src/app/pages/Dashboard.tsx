import { useEffect, useMemo, useState } from 'react';
import { StatCard } from '../components/StatCard';
import { StatusBadge } from '../components/StatusBadge';
import { Activity, AlertTriangle, FileCheck, ScanLine, Play, History, PenLine, BookOpenText, Layers3, GitCompareArrows, ClipboardList } from 'lucide-react';
import { Link } from '../router';
import { formatTimestamp, getHistoryRecords, HISTORY_UPDATED_EVENT, type HistoryRecord, type HistoryUpdatedDetail } from '../lib/history';
import { clearApiSettings, getApiSettings, setApiSettings } from '../lib/apiClient';

function pad2(value: number) {
  return String(value).padStart(2, '0');
}

function ymdKey(date: Date) {
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}`;
}

function parseRecordDateKey(timestamp: string): string | null {
  // Expected: "YYYY-MM-DD HH:MM:SS" (stored by formatTimestamp), but be lenient.
  const m = timestamp.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return null;
  return `${m[1]}-${m[2]}-${m[3]}`;
}

function deltaText(delta: number) {
  if (!Number.isFinite(delta) || delta === 0) return '0';
  return delta > 0 ? `+${delta}` : String(delta);
}

export function Dashboard() {
  const [recentActivity, setRecentActivity] = useState<HistoryRecord[]>([]);
  const [records, setRecords] = useState<HistoryRecord[]>([]);
  const [lastUpdated, setLastUpdated] = useState<string>('');
  const [apiBaseUrl, setApiBaseUrl] = useState('');
  const [apiKey, setApiKey] = useState('');

  useEffect(() => {
    const all = getHistoryRecords();
    setRecords(all);
    setRecentActivity(all.slice(0, 5));
    setLastUpdated(formatTimestamp(new Date()));

    const settings = getApiSettings();
    setApiBaseUrl(settings.baseUrl || '');
    setApiKey(settings.apiKey || '');
  }, []);

  useEffect(() => {
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<HistoryUpdatedDetail>).detail;
      const next = detail?.records ?? getHistoryRecords();
      setRecords(next);
      setRecentActivity(next.slice(0, 5));
      const updatedAt = detail?.updatedAt ? new Date(detail.updatedAt) : new Date();
      setLastUpdated(formatTimestamp(updatedAt));
    };

    window.addEventListener(HISTORY_UPDATED_EVENT, handler);
    return () => window.removeEventListener(HISTORY_UPDATED_EVENT, handler);
  }, []);

  const stats = useMemo(() => {
    const now = new Date();
    const today = ymdKey(now);
    const yesterdayDate = new Date(now);
    yesterdayDate.setDate(now.getDate() - 1);
    const yesterday = ymdKey(yesterdayDate);

    const scanRecords = records.filter((r) => r.mode === 'scan');
    const verifyRecords = records.filter((r) => r.mode === 'verify');

    const totalScans = scanRecords.length;
    const filesVerified = verifyRecords.length;
    const tamperAlerts = verifyRecords.filter((r) => r.status === 'TAMPERED').length;

    const isToday = (r: HistoryRecord) => parseRecordDateKey(r.timestamp) === today;
    const isYesterday = (r: HistoryRecord) => parseRecordDateKey(r.timestamp) === yesterday;

    const gapsToday = scanRecords.filter(isToday).reduce((sum, r) => sum + (Number(r.gaps) || 0), 0);
    const gapsYesterday = scanRecords.filter(isYesterday).reduce((sum, r) => sum + (Number(r.gaps) || 0), 0);

    const scansToday = scanRecords.filter(isToday).length;
    const scansYesterday = scanRecords.filter(isYesterday).length;

    const verifiesToday = verifyRecords.filter(isToday).length;
    const verifiesYesterday = verifyRecords.filter(isYesterday).length;

    const tamperToday = verifyRecords.filter(isToday).filter((r) => r.status === 'TAMPERED').length;
    const tamperYesterday = verifyRecords.filter(isYesterday).filter((r) => r.status === 'TAMPERED').length;

    const scansDelta = scansToday - scansYesterday;
    const gapsDelta = gapsToday - gapsYesterday;
    const verifiesDelta = verifiesToday - verifiesYesterday;
    const tamperDelta = tamperToday - tamperYesterday;

    return {
      totalScans,
      gapsToday,
      filesVerified,
      tamperAlerts,
      trend: {
        scans: { value: deltaText(scansDelta), positive: scansDelta >= 0 },
        gaps: { value: deltaText(gapsDelta), positive: gapsDelta <= 0 },
        verifies: { value: deltaText(verifiesDelta), positive: verifiesDelta >= 0 },
        tamper: { value: deltaText(tamperDelta), positive: tamperDelta <= 0 },
      },
    };
  }, [records]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground mb-2">Dashboard</h1>
        <p className="text-muted-foreground">Automated Log Integrity Monitor</p>
        <p className="text-xs text-muted-foreground font-mono mt-1">Last updated: {lastUpdated || '—'}</p>
      </div>

      <div className="bg-card border border-border rounded-lg p-6 space-y-4">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-foreground">Release readiness shortcuts</h2>
            <p className="text-sm text-muted-foreground">Use these to complete the remaining polish flows quickly.</p>
          </div>
          <Link to="/guide" className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm inline-flex items-center gap-2">
            <BookOpenText className="w-4 h-4" />
            Open guide
          </Link>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
          <Link to="/baselines" className="p-4 rounded-lg border border-border bg-background hover:bg-secondary/50 transition-colors">
            <div className="flex items-center gap-2 mb-2"><Layers3 className="w-4 h-4 text-primary" /><span className="font-medium text-foreground">Baseline organizer</span></div>
            <p className="text-sm text-muted-foreground">Group Ghost baselines into named collections.</p>
          </Link>
          <Link to="/compare" className="p-4 rounded-lg border border-border bg-background hover:bg-secondary/50 transition-colors">
            <div className="flex items-center gap-2 mb-2"><GitCompareArrows className="w-4 h-4 text-primary" /><span className="font-medium text-foreground">Compare reports</span></div>
            <p className="text-sm text-muted-foreground">Inspect any two reports side by side.</p>
          </Link>
          <Link to="/release-evidence" className="p-4 rounded-lg border border-border bg-background hover:bg-secondary/50 transition-colors">
            <div className="flex items-center gap-2 mb-2"><ClipboardList className="w-4 h-4 text-primary" /><span className="font-medium text-foreground">Evidence pack</span></div>
            <p className="text-sm text-muted-foreground">Export the proof pack and screenshot checklist.</p>
          </Link>
          <Link to="/guide" className="p-4 rounded-lg border border-border bg-background hover:bg-secondary/50 transition-colors">
            <div className="flex items-center gap-2 mb-2"><BookOpenText className="w-4 h-4 text-primary" /><span className="font-medium text-foreground">Walkthrough</span></div>
            <p className="text-sm text-muted-foreground">Step through the recommended release flow.</p>
          </Link>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-border">
          <h2 className="text-lg font-semibold text-foreground">API Settings</h2>
          <p className="text-sm text-muted-foreground">Configure backend URL and optional API key</p>
        </div>
        <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 space-y-2">
            <label className="text-sm text-foreground">Backend Base URL</label>
            <input
              type="text"
              value={apiBaseUrl}
              onChange={(e) => setApiBaseUrl(e.target.value)}
              placeholder="(blank = use /api via current origin) e.g. http://127.0.0.1:8000"
              className="w-full px-4 py-2 bg-background border border-border rounded-md text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none transition-colors"
            />
            <div className="text-xs text-muted-foreground font-mono">Example: http://127.0.0.1:8000</div>
          </div>

          <div className="space-y-2">
            <label className="text-sm text-foreground">API Key (optional)</label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="X-API-Key"
              className="w-full px-4 py-2 bg-background border border-border rounded-md text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none transition-colors"
            />
            <div className="text-xs text-muted-foreground">Sent as <span className="font-mono">X-API-Key</span> when set.</div>
          </div>

          <div className="lg:col-span-3 flex flex-col sm:flex-row gap-2 sm:justify-end">
            <button
              onClick={() => {
                setApiSettings({ baseUrl: apiBaseUrl, apiKey });
              }}
              className="flex items-center justify-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 text-foreground border border-border rounded-md transition-colors"
            >
              Apply
            </button>
            <button
              onClick={() => {
                clearApiSettings();
                const settings = getApiSettings();
                setApiBaseUrl(settings.baseUrl || '');
                setApiKey(settings.apiKey || '');
              }}
              className="flex items-center justify-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 text-foreground border border-border rounded-md transition-colors"
            >
              Reset to defaults
            </button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={Activity}
          label="Total Scans Run"
          value={stats.totalScans.toLocaleString()}
          trend={stats.trend.scans}
        />
        <StatCard
          icon={AlertTriangle}
          label="Gaps Detected Today"
          value={stats.gapsToday.toLocaleString()}
          trend={stats.trend.gaps}
        />
        <StatCard
          icon={FileCheck}
          label="Files Verified"
          value={stats.filesVerified.toLocaleString()}
          trend={stats.trend.verifies}
        />
        <StatCard
          icon={ScanLine}
          label="Tamper Alerts"
          value={stats.tamperAlerts.toLocaleString()}
          trend={stats.trend.tamper}
        />
      </div>

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-border">
          <h2 className="text-lg font-semibold text-foreground">Recent Activity</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-background border-b border-border">
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider sticky top-0 bg-background">
                  Timestamp
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider sticky top-0 bg-background">
                  File
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider sticky top-0 bg-background">
                  Mode
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider sticky top-0 bg-background">
                  Result
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider sticky top-0 bg-background">
                  Gaps Found
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider sticky top-0 bg-background">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {recentActivity.map((item, index) => (
                <tr
                  key={item.id}
                  className={`border-b border-border hover:bg-secondary transition-colors ${
                    index % 2 === 0 ? 'bg-background' : 'bg-card'
                  }`}
                >
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground font-mono">
                    {item.timestamp}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground font-mono">
                    {item.file}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-muted-foreground uppercase">
                    {item.mode}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <StatusBadge status={item.status as any} />
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground">
                    {item.gaps}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <Link
                      to={`/results/${item.id}`}
                      className="text-primary hover:text-primary/80 transition-colors"
                    >
                      View Report
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {recentActivity.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16">
            <p className="text-muted-foreground">No activity yet. Run a scan to generate reports.</p>
          </div>
        )}
      </div>

      <div className="flex flex-col sm:flex-row gap-4">
        <Link
          to="/scan"
          className="flex items-center justify-center gap-2 px-6 py-3 bg-primary hover:bg-primary/90 text-primary-foreground rounded-md transition-colors"
        >
          <Play className="w-4 h-4" />
          New Scan
        </Link>
        <Link
          to="/sign"
          className="flex items-center justify-center gap-2 px-6 py-3 bg-secondary hover:bg-secondary/80 text-foreground border border-border rounded-md transition-colors"
        >
          <PenLine className="w-4 h-4" />
          Sign Log
        </Link>
        <Link
          to="/verify"
          className="flex items-center justify-center gap-2 px-6 py-3 bg-secondary hover:bg-secondary/80 text-foreground border border-border rounded-md transition-colors"
        >
          <FileCheck className="w-4 h-4" />
          Verify File
        </Link>
        <Link
          to="/history"
          className="flex items-center justify-center gap-2 px-6 py-3 bg-secondary hover:bg-secondary/80 text-foreground border border-border rounded-md transition-colors"
        >
          <History className="w-4 h-4" />
          View Reports
        </Link>
      </div>
    </div>
  );
}
