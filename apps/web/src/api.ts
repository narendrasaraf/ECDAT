export type Row = Record<string, unknown> & { id?: string };
export type User = { id: string; username: string; role: string };
export type Session = { user: User; csrf_token: string };
export type Workspace = { project: Row; [key: string]: Row | Row[] | undefined };
let csrfToken = '';
export function setCsrf(value: string) { csrfToken = value; }
export class ApiError extends Error {
  constructor(public status: number, message: string, public details?: unknown) { super(message); }
}
export async function api<T>(path: string, options: { method?: string; body?: unknown; signal?: AbortSignal } = {}): Promise<T> {
  const method = options.method ?? 'GET';
  const multipart = options.body instanceof FormData;
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (options.body !== undefined && !multipart) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken;
  const response = await fetch(`/api${path}`, { credentials: 'include', method, headers, signal: options.signal,
    body: options.body === undefined ? undefined : multipart ? options.body as FormData : JSON.stringify(options.body) });
  const contentType = response.headers.get('content-type') ?? '';
  const value = contentType.includes('json') ? await response.json() : await response.text();
  if (!response.ok) throw new ApiError(response.status, value?.error?.message ?? value?.detail ?? `Request failed (${response.status})`, value?.error?.details);
  if (!contentType.includes('json')) throw new ApiError(response.status, 'The API did not return JSON. Check that the backend is running and /api is routed correctly.');
  return value as T;
}
export const rows = (workspace: Workspace | null, key: string): Row[] => Array.isArray(workspace?.[key]) ? workspace[key] as Row[] : workspace?.[key] ? [workspace[key] as Row] : [];
export function label(value: unknown, fallback = 'Not recorded'): string {
  if (value === undefined || value === null || value === '') return fallback;
  if (Array.isArray(value)) return value.map(v => label(v, '')).join(', ');
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}
export function name(row: Row): string { return label(row.title ?? row.name ?? row.algorithm ?? row.subject ?? row.path ?? row.action ?? row.adapter ?? row.kind ?? row.id); }
export function status(row: Row): string { return label(row.status ?? row.state ?? row.outcome ?? row.classification, 'recorded'); }
export function safeDownload(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  try {
    const url = new URL(value, window.location.origin);
    return url.origin === window.location.origin && url.pathname.startsWith('/api/exports/') ? url.pathname + url.search : null;
  } catch { return null; }
}
