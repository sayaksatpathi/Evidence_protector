import { useEffect, useMemo, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { fetchApiJson, formatApiErrorMessage, getApiHeaders, isApiOkWithMode } from '../lib/apiClient';

type AuditEvent = {
  timestamp: string;
  request_id: string;
  trace_id: string;
  method: string;
  path: string;
  status_code: number;
  client: string;
  duration_ms: number;
  api_role: string;
};

export function Audit() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [limit, setLimit] = useState(200);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const fetchAudit = async (nextLimit: number) => {
    setLoading(true);
    setError('');
    try {
      const headers: HeadersInit = { ...(getApiHeaders() ?? {}) };
      const { res, json } = await fetchApiJson(`/api/audit?limit=${nextLimit}`, {
        method: 'GET',
        headers,
      });
      if (!res.ok || !isApiOkWithMode(json, 'audit-list')) {
        throw new Error(
          formatApiErrorMessage({
            res,
            json,
            fallback: 'Unable to fetch audit events.',
          }),
        );
      }
      const rows = Array.isArray((json as any).events) ? ((json as any).events as AuditEvent[]) : [];
      setEvents(rows);
    } catch (e: any) {
      setError(String(e?.message ?? e ?? 'Unknown error'));
      setEvents([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAudit(limit);
  }, []);

  const stats = useMemo(() => {
    const failures = events.filter((row) => Number(row.status_code) >= 400).length;
    const avgDuration = events.length
      ? Math.round(events.reduce((sum, row) => sum + Number(row.duration_ms || 0), 0) / events.length)
      : 0;
    return { failures, avgDuration };
  }, [events]);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <ShieldCheck className="w-6 h-6 text-primary" />
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Audit Trail</h1>
          <p className="text-muted-foreground">Recent API access and trace events</p>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-4 grid grid-cols-1 md:grid-cols-4 gap-3">
        <div className="space-y-1">
          <div className="text-xs text-muted-foreground">Total events</div>
          <div className="text-xl font-semibold text-foreground">{events.length.toLocaleString()}</div>
        </div>
        <div className="space-y-1">
          <div className="text-xs text-muted-foreground">Failures</div>
          <div className="text-xl font-semibold text-foreground">{stats.failures.toLocaleString()}</div>
        </div>
        <div className="space-y-1">
          <div className="text-xs text-muted-foreground">Avg duration (ms)</div>
          <div className="text-xl font-semibold text-foreground">{stats.avgDuration.toLocaleString()}</div>
        </div>
        <div className="flex items-end gap-2">
          <input
            type="number"
            min={1}
            max={2000}
            value={limit}
            onChange={(e) => setLimit(Math.max(1, Math.min(2000, Number(e.target.value || 1))))}
            className="w-full px-3 py-2 bg-background border border-border rounded-md text-foreground"
          />
          <button
            onClick={() => fetchAudit(limit)}
            disabled={loading}
            className="px-4 py-2 bg-secondary hover:bg-secondary/80 border border-border rounded-md text-sm disabled:opacity-50"
          >
            Refresh
          </button>
        </div>
      </div>

      {error ? <div className="p-3 border border-destructive/30 rounded text-destructive text-sm">{error}</div> : null}

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-background border-b border-border">
                <th className="px-4 py-3 text-left text-xs text-muted-foreground uppercase">Timestamp</th>
                <th className="px-4 py-3 text-left text-xs text-muted-foreground uppercase">Method</th>
                <th className="px-4 py-3 text-left text-xs text-muted-foreground uppercase">Path</th>
                <th className="px-4 py-3 text-left text-xs text-muted-foreground uppercase">Status</th>
                <th className="px-4 py-3 text-left text-xs text-muted-foreground uppercase">Role</th>
                <th className="px-4 py-3 text-left text-xs text-muted-foreground uppercase">Trace ID</th>
                <th className="px-4 py-3 text-left text-xs text-muted-foreground uppercase">Duration</th>
              </tr>
            </thead>
            <tbody>
              {events.map((row) => (
                <tr key={`${row.trace_id}-${row.request_id}-${row.timestamp}`} className="border-b border-border">
                  <td className="px-4 py-3 text-xs font-mono text-foreground">{row.timestamp}</td>
                  <td className="px-4 py-3 text-xs font-mono text-foreground">{row.method}</td>
                  <td className="px-4 py-3 text-xs font-mono text-foreground">{row.path}</td>
                  <td className="px-4 py-3 text-xs font-mono text-foreground">{row.status_code}</td>
                  <td className="px-4 py-3 text-xs font-mono text-foreground">{row.api_role}</td>
                  <td className="px-4 py-3 text-xs font-mono text-muted-foreground">{row.trace_id}</td>
                  <td className="px-4 py-3 text-xs font-mono text-foreground">{row.duration_ms} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!events.length && !loading ? (
          <div className="p-8 text-sm text-muted-foreground text-center">No audit events yet.</div>
        ) : null}
      </div>
    </div>
  );
}
