import { staticVault } from './staticVault.ts';
import type {
  D1StatusResult,
  DashboardState,
  IpAuditResult,
  ProbeResult,
  ProxyProtocol,
  ProxyToken,
  SystemSettings,
  TransportType,
} from '../types.ts';

const TOKEN_STORAGE_KEY = 'arash_proxy_session_token';
const PREVIEW_MODE_KEY = 'arash_proxy_preview_mode';

function isPreviewEnvironment(): boolean {
  if (typeof window === 'undefined') return false;
  return window.location.hostname.endsWith('.run.app');
}

function isStaticEdgeMode(): boolean {
  if (!isPreviewEnvironment()) return false;
  try {
    return sessionStorage.getItem(PREVIEW_MODE_KEY) === '1';
  } catch {
    return false;
  }
}

function enableStaticEdgeMode(): void {
  if (!isPreviewEnvironment()) return;
  try {
    sessionStorage.setItem(PREVIEW_MODE_KEY, '1');
  } catch {}
}

export function getStoredToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setStoredToken(token: string | null): void {
  try {
    if (token) {
      sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    // Ignore storage quota issues
  }
}

class PreviewFallbackError extends Error {
  constructor() {
    super('PREVIEW_ONLY_FALLBACK');
  }
}

async function apiRequest<T>(url: string, options: RequestInit = {}): Promise<T> {
  if (isStaticEdgeMode()) {
    throw new PreviewFallbackError();
  }

  const token = getStoredToken();
  const headers = new Headers(options.headers || {});
  headers.set('Content-Type', 'application/json');
  headers.set('X-Requested-With', 'ArashProxyConsole');
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const res = await fetch(url, {
    ...options,
    headers,
    credentials: 'include',
  });

  const contentType = res.headers.get('content-type') || '';
  if (isPreviewEnvironment() && (res.status === 405 || res.status === 501)) {
    enableStaticEdgeMode();
    throw new PreviewFallbackError();
  }

  if (!contentType.includes('application/json')) {
    const rawText = await res.text().catch(() => '');
    throw new Error(
      `پاسخ غیرمنتظره از Cloudflare Worker (${res.status}): ${rawText.slice(0, 120) || 'عدم اجرای اسکریپت ورکر'}`
    );
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `خطای سرور (${res.status})`);
  }
  return data as T;
}

export async function login(username: string, password: string): Promise<{ token: string; username: string }> {
  try {
    const data = await apiRequest<{ authenticated: boolean; token: string; username: string }>(
      '/api/auth/login',
      {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      }
    );
    setStoredToken(data.token);
    return { token: data.token, username: data.username };
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      const res = await staticVault.login(username, password);
      setStoredToken(res.token);
      return res;
    }
    throw err;
  }
}

export async function checkSession(): Promise<{ authenticated: boolean; username?: string }> {
  if (isStaticEdgeMode()) {
    return staticVault.checkSession();
  }
  try {
    return await apiRequest<{ authenticated: boolean; username: string }>('/api/auth/session');
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.checkSession();
    }
    setStoredToken(null);
    return { authenticated: false };
  }
}

export async function logout(): Promise<void> {
  if (isStaticEdgeMode()) {
    staticVault.logout();
    setStoredToken(null);
    return;
  }
  try {
    await apiRequest('/api/auth/logout', { method: 'POST' });
  } catch {
    staticVault.logout();
  } finally {
    setStoredToken(null);
  }
}

export async function fetchDashboard(): Promise<DashboardState> {
  try {
    return await apiRequest<DashboardState>('/api/dashboard');
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.getDashboard();
    }
    throw err;
  }
}

export async function createProxyToken(payload: {
  name: string;
  protocol: ProxyProtocol;
  cleanIp: string;
  port: number;
  transport: TransportType;
  fingerprint: 'chrome' | 'firefox' | 'safari' | 'random';
  tlsFragmentEnabled: boolean;
}): Promise<{ token: ProxyToken; dashboard: DashboardState }> {
  try {
    return await apiRequest('/api/tokens', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.createToken(payload);
    }
    throw err;
  }
}

export async function updateProxyToken(
  id: string,
  payload: Partial<Pick<ProxyToken, 'name' | 'cleanIp' | 'port' | 'enabled' | 'tlsFragmentEnabled' | 'ipMaskMode'>>
): Promise<{ token: ProxyToken; dashboard: DashboardState }> {
  try {
    return await apiRequest(`/api/tokens/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.updateToken(id, payload);
    }
    throw err;
  }
}

export async function rotateProxyToken(id: string): Promise<{ token: ProxyToken; dashboard: DashboardState }> {
  try {
    return await apiRequest(`/api/tokens/${encodeURIComponent(id)}/rotate`, {
      method: 'POST',
    });
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.rotateToken(id);
    }
    throw err;
  }
}

export async function deleteProxyToken(id: string): Promise<{ dashboard: DashboardState }> {
  try {
    return await apiRequest(`/api/tokens/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.deleteToken(id);
    }
    throw err;
  }
}

export async function updateSystemSettings(
  settings: Partial<SystemSettings>
): Promise<{ dashboard: DashboardState }> {
  try {
    return await apiRequest('/api/settings', {
      method: 'PUT',
      body: JSON.stringify(settings),
    });
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.updateSettings(settings);
    }
    throw err;
  }
}

export async function rotateSubscriptionSecret(): Promise<{ dashboard: DashboardState }> {
  try {
    return await apiRequest('/api/settings/rotate-sub', {
      method: 'POST',
    });
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.rotateSubscriptionSecret();
    }
    throw err;
  }
}

export async function fetchWorkerScript(): Promise<{ script: string; dashboard: DashboardState }> {
  try {
    return await apiRequest('/api/worker-script');
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.getWorkerScript();
    }
    throw err;
  }
}

export async function fetchIncyExport(): Promise<{ filename: string; content: string }> {
  try {
    return await apiRequest('/api/export/incy');
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.getIncyExport();
    }
    throw err;
  }
}

export async function fetchV2RayExport(tokenId: string): Promise<{ filename: string; content: string }> {
  try {
    return await apiRequest(`/api/export/v2ray/${encodeURIComponent(tokenId)}`);
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.getV2RayExport(tokenId);
    }
    throw err;
  }
}

export async function probeEndpoint(
  target: string,
  port = 443,
  sni?: string
): Promise<{ probe: ProbeResult; dashboard: DashboardState }> {
  try {
    return await apiRequest('/api/network/probe', {
      method: 'POST',
      body: JSON.stringify({ target, port, sni }),
    });
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.probeEndpoint(target, port);
    }
    throw err;
  }
}

export async function probeAllCleanIps(): Promise<{
  results: Array<{ ip: string; probe: ProbeResult }>;
  dashboard: DashboardState;
}> {
  try {
    return await apiRequest('/api/network/probe-all', {
      method: 'POST',
    });
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.probeAllCleanIps();
    }
    throw err;
  }
}

export async function runIpAudit(): Promise<IpAuditResult> {
  try {
    return await apiRequest('/api/network/ip-audit');
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.runIpAudit();
    }
    throw err;
  }
}

export async function fetchD1Status(): Promise<D1StatusResult> {
  try {
    return await apiRequest('/api/d1/status');
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      return staticVault.getD1Status();
    }
    throw err;
  }
}

export async function syncD1Database(): Promise<{
  ok: boolean;
  databaseId: string;
  syncedTokens: number;
  dashboard: DashboardState;
}> {
  try {
    return await apiRequest('/api/d1/sync', { method: 'POST' });
  } catch (err) {
    if (err instanceof PreviewFallbackError) {
      throw new Error('این محیط پیش‌نمایش استاتیک است؛ روی Cloudflare Worker با binding دیتابیس DB، همگام‌سازی D1 به‌صورت مستقیم انجام می‌شود.');
    }
    throw err;
  }
}
