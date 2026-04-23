export type ApiErrorPayload = {
  ok: false;
  error?: string;
  detail?: unknown;
  error_code?: string;
  request_id?: string;
};

export type ApiOkPayload = {
  ok: true;
  request_id?: string;
  [key: string]: unknown;
};

export type ApiMode =
  | 'scan'
  | 'sign'
  | 'verify'
  | 'ghost-baseline'
  | 'ghost-analyze'
  | 'ghost-receipts'
  | 'ghost-correlate'
  | 'audit-list'
  | 'jobs-scan'
  | 'jobs-status';

export type ApiOkWithMode<M extends ApiMode> = ApiOkPayload & {
  mode: M;
};

export type HealthResponse = {
  status: 'ok';
  request_id?: string;
};

export type ApiSettings = {
  baseUrl: string; // e.g. "http://127.0.0.1:8000". Empty means use relative /api (dev proxy / same-origin).
  apiKey: string; // sent as X-API-Key when present.
};

const STORAGE_KEY_API_BASE_URL = 'evidenceProtector.api.baseUrl.v1';
const STORAGE_KEY_API_KEY = 'evidenceProtector.api.key.v1';

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

export function getApiHeaders(): HeadersInit | undefined {
  try {
    const { apiKey } = getApiSettings();
    if (!apiKey) return undefined;
    return { 'X-API-Key': apiKey };
  } catch {
    return undefined;
  }
}

function readLocalStorageString(key: string): string {
  try {
    if (typeof window === 'undefined') return '';
    return String(window.localStorage.getItem(key) ?? '').trim();
  } catch {
    return '';
  }
}

function writeLocalStorageString(key: string, value: string) {
  try {
    if (typeof window === 'undefined') return;
    const v = String(value ?? '').trim();
    if (!v) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, v);
  } catch {
    // Best-effort only.
  }
}

function isLocalHost(hostname: string): boolean {
  const host = String(hostname || '').toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '::1';
}

function isLoopbackUrl(url: string): boolean {
  try {
    return isLocalHost(new URL(url).hostname);
  } catch {
    return false;
  }
}

function isRemoteBrowserOrigin(): boolean {
  if (typeof window === 'undefined') return false;
  return !isLocalHost(window.location.hostname);
}

export function getApiSettings(): ApiSettings {
  const envBaseUrl = String((import.meta as any)?.env?.VITE_API_BASE_URL ?? '').trim();
  const envApiKey = String((import.meta as any)?.env?.VITE_API_KEY ?? '').trim();

  const storedBaseUrl = readLocalStorageString(STORAGE_KEY_API_BASE_URL);
  const storedApiKey = readLocalStorageString(STORAGE_KEY_API_KEY);
  const preferredBaseUrl = storedBaseUrl || envBaseUrl;
  const ignoreLoopback = isRemoteBrowserOrigin() && isLoopbackUrl(preferredBaseUrl);

  if (ignoreLoopback && storedBaseUrl) {
    writeLocalStorageString(STORAGE_KEY_API_BASE_URL, '');
  }

  return {
    baseUrl: ignoreLoopback ? envBaseUrl : preferredBaseUrl,
    apiKey: storedApiKey || envApiKey,
  };
}

export function getApiUnavailableMessage(): string {
  const { baseUrl } = getApiSettings();

  if (baseUrl) {
    return `Backend API not reachable at ${baseUrl}. Check backend health and CORS.`;
  }

  if (isRemoteBrowserOrigin()) {
    return 'Backend API not reachable. Configure VITE_API_BASE_URL in Vercel to your backend URL.';
  }

  return 'Backend API not reachable. Start the Python API on http://127.0.0.1:8000.';
}

export function setApiSettings(next: Partial<ApiSettings>) {
  if (typeof next.baseUrl !== 'undefined') writeLocalStorageString(STORAGE_KEY_API_BASE_URL, next.baseUrl);
  if (typeof next.apiKey !== 'undefined') writeLocalStorageString(STORAGE_KEY_API_KEY, next.apiKey);
}

export function clearApiSettings() {
  try {
    if (typeof window === 'undefined') return;
    window.localStorage.removeItem(STORAGE_KEY_API_BASE_URL);
    window.localStorage.removeItem(STORAGE_KEY_API_KEY);
  } catch {
    // Best-effort only.
  }
}

function hasScheme(value: string): boolean {
  return /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(value);
}

function joinUrl(baseUrl: string, path: string): string {
  const b = baseUrl.replace(/\/+$/, '');
  const p = path.startsWith('/') ? path : `/${path}`;
  if (b.endsWith('/api') && (p === '/api' || p.startsWith('/api/'))) {
    const suffix = p.slice('/api'.length);
    return `${b}${suffix}`;
  }
  return `${b}${p}`;
}

function resolveApiInput(input: RequestInfo | URL): RequestInfo | URL {
  const { baseUrl } = getApiSettings();
  if (!baseUrl) return input;

  // Only rewrite string paths like "/api/health".
  if (typeof input !== 'string') return input;
  const trimmed = input.trim();
  if (!trimmed) return input;
  if (hasScheme(trimmed)) return input;
  if (!trimmed.startsWith('/')) return input;
  return joinUrl(baseUrl, trimmed);
}

export function isHealthResponse(value: unknown): value is HealthResponse {
  return isRecord(value) && value.status === 'ok';
}

export function isApiOkPayload(value: unknown): value is ApiOkPayload {
  return isRecord(value) && value.ok === true;
}

export function isApiOkWithMode<M extends ApiMode>(value: unknown, mode: M): value is ApiOkWithMode<M> {
  return isApiOkPayload(value) && value.mode === mode;
}

export function isApiErrorPayload(value: unknown): value is ApiErrorPayload {
  return isRecord(value) && value.ok === false;
}

export async function fetchApiJson(
  input: RequestInfo | URL,
  init: RequestInit,
): Promise<{ res: Response; json: unknown | null }> {
  const resolved = resolveApiInput(input);
  const res = await fetch(resolved, init);
  try {
    const json = await res.json();
    return { res, json };
  } catch {
    return { res, json: null };
  }
}

export function formatApiErrorMessage(args: {
  res?: Response;
  json: unknown | null;
  fallback: string;
}): string {
  const retryAfter = args.res?.headers?.get?.('Retry-After');
  const base = isApiErrorPayload(args.json)
    ? String(args.json.error ?? args.fallback)
    : isRecord(args.json) && typeof args.json.detail === 'string'
      ? args.json.detail
      : args.fallback;

  return retryAfter ? `${base} (retry after ${retryAfter}s)` : base;
}
