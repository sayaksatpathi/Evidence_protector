import { useEffect, useMemo, useState } from 'react';
import { FileDropzone } from '../components/FileDropzone';
import { TerminalOutput } from '../components/TerminalOutput';
import { HashDisplay } from '../components/HashDisplay';
import { ForensicFingerprint } from '../components/ForensicFingerprint';
import { PenLine, FileText, Download, ShieldCheck } from 'lucide-react';
import { addHistoryRecord, formatTimestamp, newHistoryId, type HistoryStatus } from '../lib/history';
import {
  fetchApiJson,
  formatApiErrorMessage,
  getApiHeaders,
  isApiOkWithMode,
  isHealthResponse,
} from '../lib/apiClient';

const MAX_LOG_BYTES = 50 * 1024 * 1024; // 50 MB

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  const mb = bytes / (1024 * 1024);
  if (mb >= 1) return `${mb.toFixed(2)} MB`;
  const kb = bytes / 1024;
  return `${kb.toFixed(2)} KB`;
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

function toTerminalLines(text: string, maxLines = 1000): string[] {
  if (!text) return ['(No output)'];
  const normalized = text.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  // Remove a single trailing empty line (common for newline-terminated output).
  if (lines.length && lines[lines.length - 1] === '') lines.pop();
  if (!lines.length) return ['(No output)'];
  if (lines.length <= maxLines) return lines;
  return [`[Output truncated: showing last ${maxLines.toLocaleString()} lines]`, ...lines.slice(-maxLines)];
}

export function Sign() {
  const [logFile, setLogFile] = useState<File | null>(null);
  const [logFileError, setLogFileError] = useState<string | null>(null);

  const [apiDown, setApiDown] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [manifestMode, setManifestMode] = useState<'full' | 'compact'>('full');
  const [checkpointEvery, setCheckpointEvery] = useState('1000');
  const [chainScheme, setChainScheme] = useState<'v1-line+prev' | 'v2-prev+lineno+line'>('v1-line+prev');

  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
  const [download, setDownload] = useState<{ filename: string; text: string; mime: string } | null>(null);
  const [manifestPreview, setManifestPreview] = useState<string>('');

  const [result, setResult] = useState<{
    fileName: string;
    rootHash: string;
    fingerprintPhrase: string;
    signatureValue?: string;
    signatureScheme?: string;
    signatureKeyId?: string;
    manifestJsonText: string;
  } | null>(null);

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
    void checkApiHealth();
  }, []);

  useEffect(() => {
    if (!apiDown) return;
    const id = window.setInterval(() => {
      void checkApiHealth();
    }, 3000);
    return () => window.clearInterval(id);
  }, [apiDown]);

  const handleSelectLogFile = (file: File) => {
    const err = validateUpload(file, { label: 'Log file', allowedExts: ['.log', '.txt'], maxBytes: MAX_LOG_BYTES });
    if (err) {
      setLogFile(null);
      setLogFileError(err);
      return;
    }

    setLogFileError(null);
    setError(null);
    setResult(null);
    setDownload(null);
    setManifestPreview('');
    setTerminalOutput([]);
    setLogFile(file);
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

  const handleSign = async () => {
    if (!logFile) return;

    const apiOk = await checkApiHealth();
    if (!apiOk) {
      setError('Backend API not reachable. Start the Python API on http://127.0.0.1:8000.');
      return;
    }

    setIsRunning(true);
    setError(null);
    setResult(null);
    setDownload(null);

    setTerminalOutput([
      `[${new Date().toLocaleTimeString()}] Starting sign...`,
      `[${new Date().toLocaleTimeString()}] File: ${logFile.name} (${formatBytes(logFile.size)})`,
      `[${new Date().toLocaleTimeString()}] Manifest mode: ${manifestMode}`,
      manifestMode === 'compact' ? `[${new Date().toLocaleTimeString()}] Checkpoint every: ${checkpointEvery}` : '',
      `[${new Date().toLocaleTimeString()}] Chain scheme: ${chainScheme}`,
      '',
    ].filter(Boolean));

    try {
      const form = new FormData();
      form.append('file', logFile);
      form.append('manifest_mode', manifestMode);
      if (manifestMode === 'compact') {
        form.append('checkpoint_every', /^\d+$/.test(checkpointEvery) ? checkpointEvery : '1000');
      }
      form.append('chain_scheme', chainScheme);

      const { res, json } = await fetchApiJson('/api/sign', { method: 'POST', body: form, headers: getApiHeaders() });
      if (!res.ok || !isApiOkWithMode(json, 'sign')) {
        const msg = formatApiErrorMessage({ res, json, fallback: `Sign failed (${res.status})` });
        setTerminalOutput((prev) => [...prev, `ERROR: ${msg}`]);
        return;
      }

      const data: any = json;
      const requestId = data?.request_id ? String(data.request_id) : '';
      const manifest = data?.manifest as any;

      const manifestJsonText = JSON.stringify(manifest, null, 2) + '\n';
      setDownload({
        filename: `${logFile.name}.manifest.json`,
        text: manifestJsonText,
        mime: 'application/json',
      });

      const signature = manifest?.signature as any;
      setResult({
        fileName: String(data?.file_name ?? logFile.name),
        rootHash: String(data?.root_hash ?? ''),
        fingerprintPhrase: String(data?.fingerprint_phrase ?? ''),
        signatureValue: signature?.value ? String(signature.value) : undefined,
        signatureScheme: signature?.scheme ? String(signature.scheme) : undefined,
        signatureKeyId: signature?.key_id ? String(signature.key_id) : undefined,
        manifestJsonText,
      });

      // Persist a summary record for History / Results.
      try {
        const now = new Date();
        const status: HistoryStatus = 'SIGNED';
        addHistoryRecord({
          id: newHistoryId(),
          timestamp: formatTimestamp(now),
          file: logFile.name,
          mode: 'sign',
          status,
          gaps: 0,
          lines: Number(manifest?.total_lines ?? 0),
          request_id: requestId || undefined,
          details: {
            sign: {
              request_id: requestId || undefined,
              rootHash: String(data?.root_hash ?? ''),
              manifest: manifest
                ? {
                    file: String(manifest?.file ?? ''),
                    signed_at: String(manifest?.signed_at ?? ''),
                    hash_algorithm: String(manifest?.hash_algorithm ?? ''),
                    chain_scheme: String(manifest?.chain_scheme ?? ''),
                    manifest_mode: String(manifest?.manifest_mode ?? ''),
                    checkpoint_every:
                      typeof manifest?.checkpoint_every === 'number' ? Number(manifest.checkpoint_every) : undefined,
                      checkpoint_count: Array.isArray(manifest?.checkpoints)
                        ? Number((manifest.checkpoints as any[]).length)
                        : undefined,
                      entry_count: Array.isArray(manifest?.entries)
                        ? Number((manifest.entries as any[]).length)
                        : undefined,
                    total_lines: Number(manifest?.total_lines ?? 0),
                    root_hash: String(manifest?.root_hash ?? ''),
                    signature: signature
                      ? {
                          scheme: String(signature?.scheme ?? ''),
                          key_id: String(signature?.key_id ?? ''),
                          value: String(signature?.value ?? ''),
                        }
                      : undefined,
                  }
                : undefined,
              outputText: String(data?.output?.text ?? ''),
            },
          },
        });
      } catch {
        // Best-effort only.
      }

      const outputText: string = String(data?.output?.text ?? '');
      const baseLines = toTerminalLines(outputText);
      const prefix = requestId ? [`[Request ID: ${requestId}]`] : [];
      setTerminalOutput([...prefix, ...baseLines]);
      setManifestPreview(manifestJsonText);
    } catch (e: any) {
      setApiDown(true);
      setTerminalOutput((prev) => [...prev, `ERROR: ${e?.message ?? String(e)}`]);
    } finally {
      setIsRunning(false);
    }
  };

  const runDisabled = useMemo(() => {
    if (!logFile) return true;
    if (Boolean(logFileError)) return true;
    if (isRunning) return true;
    if (manifestMode === 'compact' && !/^\d+$/.test(checkpointEvery)) return true;
    return false;
  }, [checkpointEvery, isRunning, logFile, logFileError, manifestMode]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 lg:h-[calc(100vh-12rem)]">
      <div className="space-y-6 lg:overflow-y-auto lg:pr-2">
        <div>
          <h1 className="text-2xl font-semibold text-foreground mb-2">Sign Log</h1>
          <p className="text-muted-foreground">Generate a signed manifest for chain-hash integrity verification</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <div className="px-2.5 py-1 rounded-md border bg-secondary/60 border-border text-[11px] font-mono text-muted-foreground tracking-wider">
              TOOL: SIGN
            </div>
            <div className="px-2.5 py-1 rounded-md border bg-secondary/60 border-border text-[11px] font-mono text-muted-foreground tracking-wider">
              MODE: {manifestMode.toUpperCase()}
            </div>
            {logFile ? (
              <div className="px-2.5 py-1 rounded-md border bg-secondary/60 border-border text-[11px] font-mono text-muted-foreground tracking-wider">
                FILE: {logFile.name}
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
          <FileDropzone onFileSelect={handleSelectLogFile} accept=".log,.txt" label="Drop log file here or click to browse" />

          {logFileError && <div className="text-sm text-destructive">{logFileError}</div>}

          {logFile && (
            <div className="flex items-center gap-3 p-4 bg-card border border-border rounded">
              <FileText className="w-5 h-5 text-primary" />
              <div className="flex-1">
                <div className="text-sm text-foreground">{logFile.name}</div>
                <div className="text-xs text-muted-foreground">{formatBytes(logFile.size)}</div>
              </div>
            </div>
          )}

          <div className="pt-2 border-t border-border">
            <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Options</div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="space-y-2">
              <label className="text-sm text-foreground">Manifest Mode</label>
              <select
                value={manifestMode}
                onChange={(e) => setManifestMode(e.target.value === 'compact' ? 'compact' : 'full')}
                className="w-full px-4 py-2 bg-background border border-border rounded-md text-foreground focus:border-primary focus:outline-none transition-colors"
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
                value={checkpointEvery}
                onChange={(e) => setCheckpointEvery(e.target.value)}
                disabled={manifestMode !== 'compact'}
                className="w-full px-4 py-2 bg-background border border-border rounded-md text-foreground focus:border-primary focus:outline-none transition-colors disabled:opacity-50"
              />
              {manifestMode !== 'compact' ? (
                <div className="text-xs text-muted-foreground">Used only for compact manifests.</div>
              ) : !/^\d+$/.test(checkpointEvery) ? (
                <div className="text-xs text-destructive">Must be a non-negative integer.</div>
              ) : null}
            </div>

            <div className="space-y-2">
              <label className="text-sm text-foreground">Chain Scheme</label>
              <select
                value={chainScheme}
                onChange={(e) => setChainScheme(e.target.value === 'v2-prev+lineno+line' ? 'v2-prev+lineno+line' : 'v1-line+prev')}
                className="w-full px-4 py-2 bg-background border border-border rounded-md text-foreground focus:border-primary focus:outline-none transition-colors"
              >
                <option value="v1-line+prev">v1 (line + prev)</option>
                <option value="v2-prev+lineno+line">v2 (prev + line# + line)</option>
              </select>
            </div>
          </div>

          <div className="flex gap-2">
            <button
              onClick={handleSign}
              disabled={runDisabled}
              className="flex-1 flex items-center justify-center gap-2 px-6 py-3 bg-primary hover:bg-primary/90 disabled:bg-secondary disabled:text-muted-foreground text-primary-foreground rounded transition-colors"
            >
              <PenLine className="w-4 h-4" />
              {isRunning ? 'Signing…' : 'Sign'}
            </button>
            <button
              onClick={() => download && downloadText(download.filename, download.text, download.mime)}
              disabled={!download || isRunning}
              className="px-4 py-3 bg-secondary hover:bg-secondary/80 disabled:bg-card disabled:text-muted-foreground text-foreground border border-border rounded transition-colors"
              title="Download manifest"
            >
              <Download className="w-4 h-4" />
            </button>
          </div>

          {error && (
            <div className="p-4 bg-destructive/10 border border-destructive/30 rounded text-destructive">
              {error}
            </div>
          )}

          {result && (
            <div className="space-y-4 pt-4 border-t border-border">
              <div className="p-6 rounded-lg bg-success/10 border border-success/30">
                <div className="flex items-center gap-3">
                  <ShieldCheck className="w-6 h-6 text-success" />
                  <div>
                    <div className="text-sm font-semibold text-success">MANIFEST SIGNED</div>
                    <div className="text-xs text-muted-foreground font-mono">{result.fileName}</div>
                  </div>
                </div>
                <div className="text-xs text-muted-foreground font-mono mt-3 space-y-1">
                  <div>manifest_mode: {manifestMode}</div>
                  <div>chain_scheme: {chainScheme}</div>
                  {manifestMode === 'compact' ? <div>checkpoint_every: {checkpointEvery}</div> : null}
                  {result.signatureScheme ? <div>signature_scheme: {result.signatureScheme}</div> : null}
                  {result.signatureKeyId ? <div>key_id: {result.signatureKeyId}</div> : null}
                </div>
              </div>

              {result.rootHash ? <HashDisplay hash={result.rootHash} label="Root Hash" /> : null}
              {result.rootHash ? <ForensicFingerprint hash={result.rootHash} label="Forensic Fingerprint" /> : null}

              {result.fingerprintPhrase ? (
                <div className="bg-card border border-border rounded p-4">
                  <div className="text-xs text-muted-foreground mb-1">Fingerprint Phrase</div>
                  <div className="font-mono text-sm text-foreground break-all">{result.fingerprintPhrase}</div>
                </div>
              ) : null}

              <div className="flex justify-end">
                <button
                  onClick={() => download && downloadText(download.filename, download.text, download.mime)}
                  disabled={!download}
                  className="flex items-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 disabled:opacity-50 text-foreground border border-border rounded transition-colors"
                >
                  <Download className="w-4 h-4" />
                  Download manifest
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="flex flex-col gap-4 lg:h-full">
        <div className="bg-card border border-border rounded-lg overflow-hidden flex-1 min-h-[18rem]">
          <TerminalOutput output={terminalOutput} isRunning={isRunning} />
        </div>

        {manifestPreview ? (
          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-border">
              <div className="text-sm font-semibold text-foreground">Manifest Preview</div>
              <div className="text-xs text-muted-foreground">Signed manifest JSON (what you download)</div>
            </div>
            <div className="p-4">
              <pre className="text-xs font-mono text-foreground whitespace-pre overflow-auto max-h-[18rem] bg-background/40 border border-border rounded p-3">
                {manifestPreview}
              </pre>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
