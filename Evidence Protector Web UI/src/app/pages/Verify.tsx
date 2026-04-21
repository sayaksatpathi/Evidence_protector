import { useEffect, useState } from 'react';
import { FileDropzone } from '../components/FileDropzone';
import { HashDisplay } from '../components/HashDisplay';
import { ForensicFingerprint } from '../components/ForensicFingerprint';
import { ShieldCheck, ShieldAlert, FileText, FileJson, Download } from 'lucide-react';
import { addHistoryRecord, formatTimestamp, newHistoryId, type HistoryStatus } from '../lib/history';
import {
  fetchApiJson,
  formatApiErrorMessage,
  getApiHeaders,
  isApiOkWithMode,
  isHealthResponse,
} from '../lib/apiClient';

const MAX_LOG_BYTES = 50 * 1024 * 1024; // 50 MB
const MAX_MANIFEST_BYTES = 5 * 1024 * 1024; // 5 MB

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

export function Verify() {
  const [logFile, setLogFile] = useState<File | null>(null);
  const [manifestFile, setManifestFile] = useState<File | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [apiDown, setApiDown] = useState(false);
  const [logFileError, setLogFileError] = useState<string | null>(null);
  const [manifestFileError, setManifestFileError] = useState<string | null>(null);
  const [download, setDownload] = useState<{ filename: string; text: string; mime: string } | null>(null);
  const [result, setResult] = useState<{
    status: 'CLEAN' | 'TAMPERED';
    rootHash: string;
    signatureValid?: boolean;
    signatureScheme?: string;
    signatureKeyId?: string;
    signatureReason?: string;
    tamperedLines: Array<{ line: number; expected: string; actual: string; status?: string; note?: string }>;
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
    setLogFile(file);
  };

  const handleSelectManifestFile = (file: File) => {
    const err = validateUpload(file, { label: 'Manifest file', allowedExts: ['.json'], maxBytes: MAX_MANIFEST_BYTES });
    if (err) {
      setManifestFile(null);
      setManifestFileError(err);
      return;
    }
    setManifestFileError(null);
    setError(null);
    setManifestFile(file);
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

  const handleVerify = async () => {
    if (!logFile) return;
    if (!manifestFile) {
      setManifestFileError('Manifest file is required to verify integrity in the Web UI.');
      return;
    }

    const apiOk = await checkApiHealth();
    if (!apiOk) {
      setError('Backend API not reachable. Start the Python API on http://127.0.0.1:8000.');
      return;
    }

    setVerifying(true);
    setError(null);
    setResult(null);
    setDownload(null);

    try {
      const form = new FormData();
      form.append('file', logFile);
      form.append('manifest', manifestFile);

      const { res, json } = await fetchApiJson('/api/verify', { method: 'POST', body: form, headers: getApiHeaders() });
      if (!res.ok || !isApiOkWithMode(json, 'verify')) {
        setError(formatApiErrorMessage({ res, json, fallback: `Verify failed (${res.status})` }));
        return;
      }

      const data: any = json;

      // Persist a summary record for History / Results.
      try {
        const now = new Date();
        const status: HistoryStatus = (String(data?.status ?? 'ERROR') as HistoryStatus);
        const report = data?.report as any;
        addHistoryRecord({
          id: newHistoryId(),
          timestamp: formatTimestamp(now),
          file: logFile.name,
          mode: 'verify',
          status,
          gaps: 0,
          lines: Number(report?.current_total_lines ?? 0),
          request_id: data?.request_id ? String(data.request_id) : undefined,
          details: {
            verify: {
              request_id: data?.request_id ? String(data.request_id) : undefined,
              status,
              report,
              outputText: String(data?.output?.text ?? ''),
            },
          },
        });
      } catch {
        // Best-effort only.
      }

      const report = data.report as any;
      const reportJsonText = JSON.stringify(report, null, 2) + '\n';
      setDownload({
        filename: `${logFile.name}.verify_report.json`,
        text: reportJsonText,
        mime: 'application/json',
      });

      const issues = Array.isArray(report?.issues) ? report.issues : [];
      const sig = report?.manifest_signature as any;
      setResult({
        status: data.status === 'CLEAN' ? 'CLEAN' : 'TAMPERED',
        rootHash: String(report?.current_root_hash ?? ''),
        signatureValid: typeof sig?.valid === 'boolean' ? Boolean(sig.valid) : undefined,
        signatureScheme: sig?.scheme ? String(sig.scheme) : undefined,
        signatureKeyId: sig?.key_id ? String(sig.key_id) : undefined,
        signatureReason: sig?.reason ? String(sig.reason) : undefined,
        tamperedLines: issues.map((issue: any) => ({
          line: typeof issue?.line_number === 'number' ? Number(issue.line_number) : Number.NaN,
          expected: String(issue?.expected_chain_hash ?? ''),
          actual: String(issue?.actual_chain_hash ?? ''),
          status: issue?.status ? String(issue.status) : undefined,
          note: issue?.note ? String(issue.note) : undefined,
        })),
      });
    } catch (e: any) {
      setApiDown(true);
      setError(e?.message ?? String(e));
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground mb-2">Verify Integrity</h1>
        <p className="text-muted-foreground">Verify log file against stored hash manifest</p>
      </div>

      {apiDown && (
        <div className="p-4 bg-destructive/10 border border-destructive/30 rounded-md text-destructive">
          Backend API not reachable. Start the Python API on http://127.0.0.1:8000.
        </div>
      )}

      <div className="space-y-4">
        <div>
          <label className="block text-sm text-foreground mb-2">Log File</label>
          <FileDropzone
            onFileSelect={handleSelectLogFile}
            accept=".log,.txt"
            label="Drop log file here or click to browse"
          />

          {logFileError && (
            <div className="text-sm text-destructive mt-2">{logFileError}</div>
          )}

          {logFile && (
            <div className="flex items-center gap-3 p-4 bg-card border border-border rounded-md mt-3">
              <FileText className="w-5 h-5 text-primary" />
              <div className="flex-1">
                <div className="text-sm text-foreground">{logFile.name}</div>
                <div className="text-xs text-muted-foreground">{(logFile.size / 1024).toFixed(2)} KB</div>
              </div>
            </div>
          )}
        </div>

        <div>
          <label className="block text-sm text-foreground mb-2">
            Manifest File <span className="text-muted-foreground">(required)</span>
          </label>
          <FileDropzone
            onFileSelect={handleSelectManifestFile}
            accept=".json"
            label="Drop manifest.json here or click to browse"
          />

          {manifestFileError && (
            <div className="text-sm text-destructive mt-2">{manifestFileError}</div>
          )}

          {manifestFile && (
            <div className="flex items-center gap-3 p-4 bg-card border border-border rounded-md mt-3">
              <FileJson className="w-5 h-5 text-primary" />
              <div className="flex-1">
                <div className="text-sm text-foreground">{manifestFile.name}</div>
                <div className="text-xs text-muted-foreground">{(manifestFile.size / 1024).toFixed(2)} KB</div>
              </div>
            </div>
          )}
        </div>

        <button
          onClick={handleVerify}
          disabled={!logFile || !manifestFile || verifying}
          className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-primary hover:bg-primary/90 disabled:opacity-50 text-primary-foreground rounded transition-colors"
        >
          <ShieldCheck className="w-4 h-4" />
          {verifying ? 'Verifying...' : 'Verify Integrity'}
        </button>
      </div>

      {error && (
        <div className="p-4 bg-destructive/10 border border-destructive/30 rounded text-destructive">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-4 pt-6 border-t border-border">
          <div className={`p-8 rounded-lg text-center ${
            result.status === 'CLEAN'
              ? 'bg-success/10 border border-success/30'
              : 'bg-destructive/10 border border-destructive/30'
          }`}>
            {result.status === 'CLEAN' ? (
              <>
                <ShieldCheck className="w-16 h-16 mx-auto mb-4 text-success" />
                <h2 className="text-2xl font-semibold text-success mb-2">INTEGRITY CONFIRMED</h2>
                <p className="text-foreground">All hashes match. No tampering detected.</p>
              </>
            ) : (
              <>
                <ShieldAlert className="w-16 h-16 mx-auto mb-4 text-destructive" />
                <h2 className="text-2xl font-semibold text-destructive mb-2">TAMPERING DETECTED</h2>
                <p className="text-foreground">Hash mismatches found. File integrity compromised.</p>
              </>
            )}
          </div>

          <HashDisplay hash={result.rootHash} label="Verified Root Hash" />

          {result.rootHash ? <ForensicFingerprint hash={result.rootHash} /> : null}

          {typeof result.signatureValid === 'boolean' && (
            <div className="flex items-center justify-between bg-card border border-border rounded-md p-4">
              <div>
                <div className="text-xs text-muted-foreground mb-1">Manifest Signature</div>
                <div className={`text-sm font-mono ${result.signatureValid ? 'text-success' : 'text-destructive'}`}>
                  {result.signatureValid ? 'VALID' : 'INVALID'}
                  {result.signatureScheme ? ` (${result.signatureScheme})` : ''}
                  {result.signatureKeyId ? ` [${result.signatureKeyId}]` : ''}
                  {!result.signatureValid && result.signatureReason ? ` — ${result.signatureReason}` : ''}
                </div>
              </div>
            </div>
          )}

          <div className="flex justify-end">
            <button
              onClick={() => download && downloadText(download.filename, download.text, download.mime)}
              disabled={!download}
              className="flex items-center gap-2 px-4 py-2 bg-secondary hover:bg-secondary/80 disabled:opacity-50 text-foreground border border-border rounded transition-colors"
              title="Download JSON verify report"
            >
              <Download className="w-4 h-4" />
              Download report
            </button>
          </div>

          {result.tamperedLines.length > 0 && (
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-border flex items-center justify-between">
                <h2 className="text-lg font-semibold text-foreground">Tampered Lines</h2>
                <div className="px-3 py-1 bg-destructive/10 border border-destructive/30 rounded text-sm text-destructive">
                  {result.tamperedLines.length} lines tampered
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="bg-background border-b border-border">
                      <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                        Line #
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                        Expected Hash
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                        Actual Hash
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                        Status
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.tamperedLines.map((line, index) => (
                      <tr
                        key={line.line}
                        className="border-b border-border bg-destructive/5 hover:bg-destructive/10 transition-colors"
                      >
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground font-mono">
                          {Number.isFinite(line.line) ? line.line : '—'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground font-mono">
                          {line.expected}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground font-mono">
                          {line.actual}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className="px-2 py-1 bg-destructive/10 text-destructive rounded text-xs font-semibold">
                            {line.status ? String(line.status) : 'MISMATCH'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
