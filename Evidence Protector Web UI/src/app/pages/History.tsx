import { useEffect, useState } from 'react';
import { StatusBadge } from '../components/StatusBadge';
import { Link } from '../router';
import { Search, Filter, Eye, Trash2, Layers3, GitCompareArrows, ClipboardList } from 'lucide-react';
import {
  deleteHistoryRecord,
  formatTimestamp,
  getHistoryRecords,
  HISTORY_UPDATED_EVENT,
  type HistoryRecord,
  type HistoryUpdatedDetail,
} from '../lib/history';

export function History() {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterMode, setFilterMode] = useState<'all' | 'scan' | 'sign' | 'verify' | 'ghost'>('all');
  const [filterStatus, setFilterStatus] = useState<
    | 'all'
    | 'CLEAN'
    | 'SIGNED'
    | 'TAMPERED'
    | 'GAPS_FOUND'
    | 'NO_TIMESTAMPS'
    | 'GHOST_CLEAN'
    | 'GHOST_SIGNALS'
    | 'GHOST_BASELINE'
    | 'GHOST_RECEIPTS'
    | 'ERROR'
  >('all');
  const [history, setHistory] = useState<HistoryRecord[]>([]);
  const [lastUpdated, setLastUpdated] = useState<string>('');

  useEffect(() => {
    setHistory(getHistoryRecords());
    setLastUpdated(formatTimestamp(new Date()));
  }, []);

  useEffect(() => {
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<HistoryUpdatedDetail>).detail;
      const next = detail?.records ?? getHistoryRecords();
      setHistory(next);
      const updatedAt = detail?.updatedAt ? new Date(detail.updatedAt) : new Date();
      setLastUpdated(formatTimestamp(updatedAt));
    };

    window.addEventListener(HISTORY_UPDATED_EVENT, handler);
    return () => window.removeEventListener(HISTORY_UPDATED_EVENT, handler);
  }, []);

  const handleDelete = (id: string) => {
    setHistory(deleteHistoryRecord(id));
  };

  const filteredHistory = history.filter((item) => {
    const matchesSearch = item.file.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesMode = filterMode === 'all' || item.mode === filterMode;
    const matchesStatus = filterStatus === 'all' || item.status === filterStatus;
    return matchesSearch && matchesMode && matchesStatus;
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground mb-2">Scan History</h1>
        <p className="text-muted-foreground">View and manage all past integrity scans</p>
        <p className="text-xs text-muted-foreground font-mono mt-1">Last updated: {lastUpdated || '—'}</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <Link to="/baselines" className="p-4 rounded-lg border border-border bg-card hover:bg-secondary/50 transition-colors">
          <div className="flex items-center gap-2 mb-2"><Layers3 className="w-4 h-4 text-primary" /><span className="font-medium text-foreground">Baseline organizer</span></div>
          <p className="text-sm text-muted-foreground">Group and pin Ghost baseline records.</p>
        </Link>
        <Link to="/compare" className="p-4 rounded-lg border border-border bg-card hover:bg-secondary/50 transition-colors">
          <div className="flex items-center gap-2 mb-2"><GitCompareArrows className="w-4 h-4 text-primary" /><span className="font-medium text-foreground">Compare reports</span></div>
          <p className="text-sm text-muted-foreground">Compare any two records side by side.</p>
        </Link>
        <Link to="/release-evidence" className="p-4 rounded-lg border border-border bg-card hover:bg-secondary/50 transition-colors">
          <div className="flex items-center gap-2 mb-2"><ClipboardList className="w-4 h-4 text-primary" /><span className="font-medium text-foreground">Release evidence</span></div>
          <p className="text-sm text-muted-foreground">Export the manual screenshot checklist and proof pack.</p>
        </Link>
      </div>

      <div className="flex flex-col gap-4 lg:flex-row lg:items-center">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search by filename..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-background border border-border rounded-md text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none transition-colors"
          />
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center gap-2">
          <Filter className="w-4 h-4 text-muted-foreground" />
          <select
            value={filterMode}
            onChange={(e) => setFilterMode(e.target.value as any)}
            className="px-4 py-2 bg-background border border-border rounded-md text-foreground focus:border-primary focus:outline-none transition-colors"
          >
            <option value="all">All Modes</option>
            <option value="scan">Scan</option>
            <option value="sign">Sign</option>
            <option value="verify">Verify</option>
            <option value="ghost">Ghost</option>
          </select>

          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value as any)}
            className="px-4 py-2 bg-background border border-border rounded-md text-foreground focus:border-primary focus:outline-none transition-colors"
          >
            <option value="all">All Status</option>
            <option value="CLEAN">Clean</option>
            <option value="SIGNED">Signed</option>
            <option value="TAMPERED">Tampered</option>
            <option value="GAPS_FOUND">Gaps Found</option>
            <option value="NO_TIMESTAMPS">No Timestamps</option>
            <option value="GHOST_CLEAN">Ghost Clean</option>
            <option value="GHOST_SIGNALS">Ghost Signals</option>
            <option value="GHOST_BASELINE">Ghost Baseline</option>
            <option value="GHOST_RECEIPTS">Ghost Receipts</option>
            <option value="ERROR">Error</option>
          </select>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg overflow-hidden">
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
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider sticky top-0 bg-background">
                  Gaps / Signals
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider sticky top-0 bg-background">
                  Lines
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider sticky top-0 bg-background">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredHistory.map((item, index) => (
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
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-muted-foreground">
                    {(item.lines ?? 0).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <div className="flex items-center gap-2">
                      <Link
                        to={`/results/${item.id}`}
                        className="p-2 hover:bg-secondary rounded transition-colors group"
                        title="View Report"
                      >
                        <Eye className="w-4 h-4 text-muted-foreground group-hover:text-primary" />
                      </Link>
                      <button
                        onClick={() => handleDelete(item.id)}
                        className="p-2 hover:bg-secondary rounded transition-colors group"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4 text-muted-foreground group-hover:text-destructive" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredHistory.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16">
            <div className="w-16 h-16 mb-4 rounded-full bg-secondary flex items-center justify-center">
              <Search className="w-8 h-8 text-muted-foreground" />
            </div>
            <p className="text-muted-foreground">No scans found matching your filters</p>
          </div>
        )}
      </div>
    </div>
  );
}
