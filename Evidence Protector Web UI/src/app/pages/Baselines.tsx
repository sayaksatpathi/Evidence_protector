import { useEffect, useMemo, useState } from 'react';
import { Link } from '../router';
import { Download, FolderPlus, Layers3, Star, Trash2 } from 'lucide-react';
import { getHistoryRecords, type HistoryRecord } from '../lib/history';
import {
  createBaselineCollection,
  deleteBaselineCollection,
  getBaselineCollections,
  getGhostBaselineRecords,
  toggleBaselineInCollection,
  type BaselineCollection,
  type BaselineRecord,
} from '../lib/organizer';

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

export function Baselines() {
  const [collections, setCollections] = useState<BaselineCollection[]>([]);
  const [records, setRecords] = useState<BaselineRecord[]>([]);
  const [history, setHistory] = useState<HistoryRecord[]>([]);
  const [search, setSearch] = useState('');
  const [newName, setNewName] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [selected, setSelected] = useState<string[]>([]);

  useEffect(() => {
    const nextHistory = getHistoryRecords();
    setHistory(nextHistory);
    setCollections(getBaselineCollections());
    setRecords(getGhostBaselineRecords(nextHistory));
  }, []);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return records.filter((record) => {
      if (!q) return true;
      return [record.file, record.sourceLabel, record.timestamp].some((value) => String(value).toLowerCase().includes(q));
    });
  }, [records, search]);

  const selectedCount = selected.length;

  const createCollection = () => {
    if (!selected.length) return;
    const latest = createBaselineCollection({
      name: newName || 'New baseline collection',
      description: newDescription,
      baselineIds: selected,
    });
    setCollections(latest);
    setNewName('');
    setNewDescription('');
    setSelected([]);
  };

  const collectionsJson = JSON.stringify({ collections, records }, null, 2) + '\n';

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground mb-2">Baseline Organizer</h1>
          <p className="text-muted-foreground">Group Ghost baselines into collections, pin a working set, and export proof.</p>
          <p className="text-xs text-muted-foreground font-mono mt-1">{records.length.toLocaleString()} baseline(s) from {history.length.toLocaleString()} history record(s)</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Link to="/compare" className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm">
            Compare reports
          </Link>
          <Link to="/release-evidence" className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm">
            Release evidence
          </Link>
          <button
            onClick={() => downloadText('baseline-organizer.json', collectionsJson, 'application/json')}
            className="px-4 py-2 rounded-md border border-border bg-secondary hover:bg-secondary/80 transition-colors text-sm flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            Export JSON
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="bg-card border border-border rounded-lg p-4">
          <div className="text-xs text-muted-foreground mb-1">Baselines</div>
          <div className="text-2xl font-semibold text-foreground">{records.length.toLocaleString()}</div>
        </div>
        <div className="bg-card border border-border rounded-lg p-4">
          <div className="text-xs text-muted-foreground mb-1">Collections</div>
          <div className="text-2xl font-semibold text-foreground">{collections.length.toLocaleString()}</div>
        </div>
        <div className="bg-card border border-border rounded-lg p-4">
          <div className="text-xs text-muted-foreground mb-1">Selected for new collection</div>
          <div className="text-2xl font-semibold text-foreground">{selectedCount.toLocaleString()}</div>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-6 space-y-4">
        <div className="flex items-center gap-2">
          <FolderPlus className="w-5 h-5 text-primary" />
          <h2 className="text-lg font-semibold text-foreground">Create collection</h2>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="space-y-2">
            <label className="text-sm text-foreground">Collection name</label>
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Prod nginx baselines"
              className="w-full px-4 py-2 bg-background border border-border rounded-md text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none transition-colors"
            />
          </div>
          <div className="space-y-2 lg:col-span-2">
            <label className="text-sm text-foreground">Description</label>
            <input
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
              placeholder="Optional notes for source, environment, or retention"
              className="w-full px-4 py-2 bg-background border border-border rounded-md text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none transition-colors"
            />
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={createCollection}
            disabled={!selected.length}
            className="px-4 py-2 rounded-md bg-primary text-primary-foreground disabled:opacity-50 transition-colors"
          >
            Create from selected
          </button>
          <p className="text-xs text-muted-foreground">Select one or more baselines below, then create a named collection.</p>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-6">
        <div className="flex items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2">
            <Layers3 className="w-5 h-5 text-primary" />
            <h2 className="text-lg font-semibold text-foreground">Baseline records</h2>
          </div>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search baselines"
            className="w-full max-w-sm px-4 py-2 bg-background border border-border rounded-md text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none transition-colors"
          />
        </div>

        <div className="space-y-3">
          {filtered.map((baseline) => {
            const inCollections = collections.filter((collection) => collection.baselineIds.includes(baseline.id));
            const json = JSON.stringify(baseline, null, 2) + '\n';
            return (
              <div key={baseline.id} className="rounded-lg border border-border bg-background p-4 space-y-3">
                <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-3">
                  <div>
                    <div className="text-sm text-muted-foreground font-mono">{baseline.timestamp}</div>
                    <div className="text-lg font-semibold text-foreground">{baseline.sourceLabel}</div>
                    <div className="text-xs text-muted-foreground font-mono">{baseline.file}</div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      onClick={() => setSelected((current) => (current.includes(baseline.id) ? current.filter((id) => id !== baseline.id) : [...current, baseline.id]))}
                      className={`px-3 py-2 rounded-md border text-sm transition-colors ${selected.includes(baseline.id) ? 'bg-primary/10 border-primary/30 text-primary' : 'bg-secondary border-border text-foreground hover:bg-secondary/80'}`}
                    >
                      {selected.includes(baseline.id) ? 'Selected' : 'Select'}
                    </button>
                    <button
                      onClick={() => setCollections(createBaselineCollection({ name: `${baseline.sourceLabel} collection`, description: '', baselineIds: [baseline.id] }))}
                      className="px-3 py-2 rounded-md border border-border bg-secondary text-sm hover:bg-secondary/80 transition-colors"
                    >
                      New collection
                    </button>
                    <button
                      onClick={() => downloadText(`${baseline.file}.baseline.json`, json, 'application/json')}
                      className="px-3 py-2 rounded-md border border-border bg-secondary text-sm hover:bg-secondary/80 transition-colors flex items-center gap-2"
                    >
                      <Download className="w-4 h-4" />
                      JSON
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 text-sm">
                  <div><div className="text-xs text-muted-foreground">Lines</div><div className="font-mono text-foreground">{baseline.totalLines.toLocaleString()}</div></div>
                  <div><div className="text-xs text-muted-foreground">Timestamps</div><div className="font-mono text-foreground">{baseline.timestampsFound.toLocaleString()}</div></div>
                  <div><div className="text-xs text-muted-foreground">Malformed</div><div className="font-mono text-foreground">{baseline.malformedLines.toLocaleString()}</div></div>
                  <div><div className="text-xs text-muted-foreground">Entropy</div><div className="font-mono text-foreground">{typeof baseline.entropyMean === 'number' ? baseline.entropyMean.toFixed(4) : '—'}</div></div>
                  <div><div className="text-xs text-muted-foreground">Interval</div><div className="font-mono text-foreground">{typeof baseline.intervalMean === 'number' ? baseline.intervalMean.toFixed(4) : '—'}</div></div>
                </div>

                <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                  {inCollections.length ? (
                    inCollections.map((collection) => (
                      <button
                        key={collection.id}
                        onClick={() => setCollections(toggleBaselineInCollection(collection.id, baseline.id))}
                        className="px-2.5 py-1 rounded-full border border-border bg-secondary/60 hover:bg-secondary/80 transition-colors"
                      >
                        #{collection.name}
                      </button>
                    ))
                  ) : (
                    <span className="px-2.5 py-1 rounded-full border border-dashed border-border">Not in a collection yet</span>
                  )}
                </div>
              </div>
            );
          })}

          {!filtered.length ? (
            <div className="py-16 text-center text-muted-foreground">No baseline records found.</div>
          ) : null}
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-6">
        <div className="flex items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2">
            <Star className="w-5 h-5 text-primary" />
            <h2 className="text-lg font-semibold text-foreground">Collections</h2>
          </div>
          <div className="text-xs text-muted-foreground">{collections.length.toLocaleString()} collection(s)</div>
        </div>

        <div className="space-y-3">
          {collections.map((collection) => (
            <div key={collection.id} className="rounded-lg border border-border bg-background p-4 space-y-3">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-lg font-semibold text-foreground">{collection.name}</div>
                  <div className="text-xs text-muted-foreground">{collection.description || 'No description provided'}</div>
                  <div className="text-[11px] text-muted-foreground font-mono mt-1">Updated {collection.updatedAt}</div>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => downloadText(`${collection.name}.collection.json`, JSON.stringify(collection, null, 2) + '\n', 'application/json')}
                    className="px-3 py-2 rounded-md border border-border bg-secondary text-sm hover:bg-secondary/80 transition-colors"
                  >
                    Export
                  </button>
                  <button
                    onClick={() => setCollections(deleteBaselineCollection(collection.id))}
                    className="px-3 py-2 rounded-md border border-border bg-secondary text-sm hover:bg-secondary/80 transition-colors flex items-center gap-2"
                  >
                    <Trash2 className="w-4 h-4" />
                    Remove
                  </button>
                </div>
              </div>

              <div className="flex flex-wrap gap-2">
                {collection.baselineIds.length ? collection.baselineIds.map((baselineId) => {
                  const item = records.find((record) => record.id === baselineId);
                  return (
                    <span key={baselineId} className="px-2.5 py-1 rounded-full border border-border bg-secondary/60 text-xs font-mono text-muted-foreground">
                      {item?.sourceLabel ?? baselineId}
                    </span>
                  );
                }) : (
                  <span className="text-sm text-muted-foreground">No baselines linked yet</span>
                )}
              </div>
            </div>
          ))}

          {!collections.length ? <div className="py-10 text-center text-muted-foreground">Create your first collection from the baseline records above.</div> : null}
        </div>
      </div>
    </div>
  );
}
