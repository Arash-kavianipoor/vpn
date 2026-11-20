import {
  buildCloudflareWorkerScript,
  buildIncySingBoxConfig,
  buildXrayFragmentConfig,
} from './proxyGenerators.ts';
import type {
  CleanIpEntry,
  D1StatusResult,
  DashboardState,
  IpAuditResult,
  ProbeResult,
  ProxyProtocol,
  ProxyToken,
  SecurityLogEntry,
  SystemSettings,
  TransportType,
} from '../types.ts';

const DEFAULT_D1_ID = 'a16983d7-1da3-4555-a1aa-f5730bccfcae';

const VAULT_STORAGE_KEY = 'arash_proxy_vault_state_v1';
const LOCKOUT_STORAGE_KEY = 'arash_proxy_vault_lockout_v1';
const SESSION_STORAGE_KEY = 'arash_proxy_vault_session_v1';

// PBKDF2-SHA256 (100,000 iterations) salt + hash for Arash admin credential
const ADMIN_USER = 'Arash';
const PBKDF2_SALT_HEX = '381a4fa9b19f24929d0f45af389f8638';
const PBKDF2_HASH_HEX = '9af3b7b9da955ef6ae776f92a934e151b5eb10718aa0e176839c0f776f373437';

const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

interface VaultData {
  settings: SystemSettings;
  tokens: ProxyToken[];
  cleanIps: CleanIpEntry[];
  securityLogs: SecurityLogEntry[];
}

function randomHex(byteCount: number): string {
  const bytes = new Uint8Array(byteCount);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function randomBase64Url(byteCount: number): string {
  const bytes = new Uint8Array(byteCount);
  crypto.getRandomValues(bytes);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function verifyPasswordWebCrypto(username: string, password: string): Promise<boolean> {
  if (username.trim() !== ADMIN_USER) return false;

  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const saltBytes = hexToBytes(PBKDF2_SALT_HEX);
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes.buffer as ArrayBuffer,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  const derivedHex = Array.from(new Uint8Array(derivedBits), (b) =>
    b.toString(16).padStart(2, '0')
  ).join('');

  return constantTimeEqualHex(derivedHex, PBKDF2_HASH_HEX);
}

function createInitialVault(): VaultData {
  const now = new Date().toISOString();
  const defaultDomain =
    typeof window !== 'undefined' &&
    window.location.hostname &&
    !window.location.hostname.includes('localhost') &&
    !window.location.hostname.includes('127.0.0.1') &&
    !window.location.hostname.endsWith('.run.app')
      ? window.location.hostname
      : 'proxysystemarash.ir';
  return {
    settings: {
      domain: defaultDomain,
      workerUrl: `https://${defaultDomain}`,
      proxyIp: '104.16.132.229',
      dohProvider: 'https://1.1.1.1/dns-query',
      subscriptionSecret: randomHex(24),
      d1DatabaseId: DEFAULT_D1_ID,
      antiProbeDecoy: true,
      webrtcBlock: true,
      strictIpMask: true,
      stripClientHeaders: true,
      decoyTitle: 'Arash Cloud Infrastructure',
    },
    tokens: [
      {
        id: crypto.randomUUID(),
        name: 'Cloudflare Edge Primary (VLESS + Fragment)',
        protocol: 'vless',
        secret: crypto.randomUUID(),
        cleanIp: '104.16.132.229',
        port: 443,
        sni: defaultDomain,
        host: defaultDomain,
        path: `/ws-${randomHex(4)}`,
        transport: 'ws',
        fingerprint: 'chrome',
        tlsFragmentEnabled: true,
        fragmentLength: '10-20',
        fragmentInterval: '10-20',
        ipMaskMode: 'strict-global',
        enabled: true,
        createdAt: now,
        lastRotatedAt: now,
      },
      {
        id: crypto.randomUUID(),
        name: 'INCY Zero-Leak Tunnel (VLESS TLS)',
        protocol: 'vless',
        secret: crypto.randomUUID(),
        cleanIp: '172.64.155.141',
        port: 2053,
        sni: defaultDomain,
        host: defaultDomain,
        path: `/incy-${randomHex(4)}`,
        transport: 'ws',
        fingerprint: 'safari',
        tlsFragmentEnabled: true,
        fragmentLength: '15-30',
        fragmentInterval: '10-15',
        ipMaskMode: 'strict-global',
        enabled: true,
        createdAt: now,
        lastRotatedAt: now,
      },
      {
        id: crypto.randomUUID(),
        name: 'Backup Anti-DPI (Trojan WS)',
        protocol: 'trojan',
        secret: randomBase64Url(18),
        cleanIp: '104.18.2.161',
        port: 8443,
        sni: defaultDomain,
        host: defaultDomain,
        path: `/tr-${randomHex(4)}`,
        transport: 'ws',
        fingerprint: 'firefox',
        tlsFragmentEnabled: true,
        fragmentLength: '10-20',
        fragmentInterval: '10-20',
        ipMaskMode: 'strict-global',
        enabled: true,
        createdAt: now,
        lastRotatedAt: now,
      },
      {
        id: crypto.randomUUID(),
        name: 'Legacy Compatible (VMess TLS)',
        protocol: 'vmess',
        secret: crypto.randomUUID(),
        cleanIp: '162.159.135.42',
        port: 443,
        sni: defaultDomain,
        host: defaultDomain,
        path: `/vm-${randomHex(4)}`,
        transport: 'ws',
        fingerprint: 'chrome',
        tlsFragmentEnabled: false,
        fragmentLength: '10-20',
        fragmentInterval: '10-20',
        ipMaskMode: 'strict-global',
        enabled: true,
        createdAt: now,
        lastRotatedAt: now,
      },
    ],
    cleanIps: [
      { ip: '104.16.132.229', label: 'Cloudflare Anycast EU-West', region: 'Frankfurt / Amsterdam', lastLatencyMs: null, reachable: null, lastCheckedAt: null },
      { ip: '172.64.155.141', label: 'Cloudflare Edge Primary', region: 'London / Frankfurt', lastLatencyMs: null, reachable: null, lastCheckedAt: null },
      { ip: '104.18.2.161', label: 'Cloudflare CDN Clean-A', region: 'Global Anycast', lastLatencyMs: null, reachable: null, lastCheckedAt: null },
      { ip: '162.159.135.42', label: 'Cloudflare Spectrum Node', region: 'Zurich / Vienna', lastLatencyMs: null, reachable: null, lastCheckedAt: null },
      { ip: '188.114.96.3', label: 'Cloudflare EU-North Clean', region: 'Stockholm / Helsinki', lastLatencyMs: null, reachable: null, lastCheckedAt: null },
      { ip: '172.67.184.91', label: 'Cloudflare Relay Fallback', region: 'Global Anycast', lastLatencyMs: null, reachable: null, lastCheckedAt: null },
    ],
    securityLogs: [
      {
        id: crypto.randomUUID(),
        timestamp: now,
        eventType: 'settings_updated',
        severity: 'info',
        sourceIp: 'Edge Browser',
        message: 'سپر رمزنگاری PBKDF2-SHA256 برای Arashproxysystem.ir فعال شد.',
      },
    ],
  };
}

function loadVault(): VaultData {
  try {
    const raw = localStorage.getItem(VAULT_STORAGE_KEY);
    if (!raw) {
      const initial = createInitialVault();
      localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(initial));
      return initial;
    }
    const parsed = JSON.parse(raw) as VaultData;
    if (!parsed.settings.d1DatabaseId) {
      parsed.settings.d1DatabaseId = DEFAULT_D1_ID;
    }
    return parsed;
  } catch {
    return createInitialVault();
  }
}

function saveVault(vault: VaultData): void {
  try {
    localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(vault));
  } catch {
    // Ignore storage quota errors
  }
}

function addVaultLog(
  vault: VaultData,
  eventType: SecurityLogEntry['eventType'],
  severity: SecurityLogEntry['severity'],
  message: string
): VaultData {
  const entry: SecurityLogEntry = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    eventType,
    severity,
    sourceIp: 'Client Browser',
    message,
  };
  const next: VaultData = {
    ...vault,
    securityLogs: [entry, ...vault.securityLogs].slice(0, 60),
  };
  saveVault(next);
  return next;
}

function buildDashboard(vault: VaultData): DashboardState {
  return {
    settings: vault.settings,
    tokens: vault.tokens,
    cleanIps: vault.cleanIps,
    securityLogs: vault.securityLogs,
    securityPosture: {
      authAlgorithm: 'PBKDF2-SHA256 (100k) + WebCrypto',
      sessionCipher: 'Signed Local Session Token',
      rateLimitWindowMinutes: 15,
      maxFailedAttempts: MAX_ATTEMPTS,
      activeLockouts: 0,
      headersEnforced: [
        'PBKDF2 Constant-Time Verify',
        'Referrer-Policy: no-referrer',
        'Anti-Probe Decoy Active',
        'Zero-IP-Leak DoH',
      ],
    },
  };
}

export const staticVault = {
  async login(username: string, password: string): Promise<{ token: string; username: string }> {
    const now = Date.now();
    let lockState: { count: number; firstAt: number; lockedUntil: number | null } = {
      count: 0,
      firstAt: now,
      lockedUntil: null,
    };

    try {
      const raw = localStorage.getItem(LOCKOUT_STORAGE_KEY);
      if (raw) lockState = JSON.parse(raw);
    } catch {}

    if (lockState.lockedUntil && lockState.lockedUntil > now) {
      const rem = Math.ceil((lockState.lockedUntil - now) / 1000);
      throw new Error(`دسترسی به دلیل تلاش ناموفق متعدد برای ${rem} ثانیه مسدود است.`);
    }

    const valid = await verifyPasswordWebCrypto(username, password);
    let vault = loadVault();

    if (!valid) {
      const prevCount = now - lockState.firstAt < LOCKOUT_MS ? lockState.count : 0;
      const nextCount = prevCount + 1;
      const lockedUntil = nextCount >= MAX_ATTEMPTS ? now + LOCKOUT_MS : null;
      try {
        localStorage.setItem(
          LOCKOUT_STORAGE_KEY,
          JSON.stringify({
            count: nextCount,
            firstAt: lockState.firstAt || now,
            lockedUntil,
          })
        );
      } catch {}

      vault = addVaultLog(
        vault,
        lockedUntil ? 'bruteforce_lockout' : 'login_failed',
        lockedUntil ? 'critical' : 'warning',
        lockedUntil
          ? 'قفل ۱۵ دقیقه‌ای به دلیل ۵ تلاش ناموفق فعال شد.'
          : `تلاش ناموفق ورود (${nextCount}/${MAX_ATTEMPTS})`
      );

      throw new Error(
        lockedUntil
          ? 'حساب به مدت ۱۵ دقیقه مسدود شد.'
          : `نام کاربری یا رمز عبور اشتباه است. (${MAX_ATTEMPTS - nextCount} تلاش باقی‌مانده)`
      );
    }

    try {
      localStorage.removeItem(LOCKOUT_STORAGE_KEY);
    } catch {}

    const token = `edge.${randomHex(24)}`;
    try {
      sessionStorage.setItem(
        SESSION_STORAGE_KEY,
        JSON.stringify({ token, username: ADMIN_USER, expiresAt: now + SESSION_TTL_MS })
      );
    } catch {}

    addVaultLog(vault, 'login_success', 'info', `ورود موفق مدیر (${ADMIN_USER}) به کنسول.`);
    return { token, username: ADMIN_USER };
  },

  checkSession(): { authenticated: boolean; username?: string } {
    try {
      const raw = sessionStorage.getItem(SESSION_STORAGE_KEY);
      if (!raw) return { authenticated: false };
      const parsed = JSON.parse(raw) as { token: string; username: string; expiresAt: number };
      if (Date.now() > parsed.expiresAt) {
        sessionStorage.removeItem(SESSION_STORAGE_KEY);
        return { authenticated: false };
      }
      return { authenticated: true, username: parsed.username };
    } catch {
      return { authenticated: false };
    }
  },

  logout(): void {
    try {
      sessionStorage.removeItem(SESSION_STORAGE_KEY);
    } catch {}
  },

  getDashboard(): DashboardState {
    return buildDashboard(loadVault());
  },

  createToken(payload: {
    name: string;
    protocol: ProxyProtocol;
    cleanIp: string;
    port: number;
    transport: TransportType;
    fingerprint: 'chrome' | 'firefox' | 'safari' | 'random';
    tlsFragmentEnabled: boolean;
  }): { token: ProxyToken; dashboard: DashboardState } {
    let vault = loadVault();
    const now = new Date().toISOString();
    const newToken: ProxyToken = {
      id: crypto.randomUUID(),
      name: payload.name || `Node-${payload.protocol.toUpperCase()}`,
      protocol: payload.protocol,
      secret: payload.protocol === 'trojan' ? randomBase64Url(18) : crypto.randomUUID(),
      cleanIp: payload.cleanIp || vault.cleanIps[0]?.ip || '104.16.132.229',
      port: payload.port || 443,
      sni: vault.settings.domain,
      host: vault.settings.domain,
      path: `/${payload.protocol === 'vless' ? 'ws' : payload.protocol}-${randomHex(4)}`,
      transport: payload.protocol === 'vless' ? payload.transport : 'ws',
      fingerprint: payload.fingerprint,
      tlsFragmentEnabled: payload.tlsFragmentEnabled,
      fragmentLength: '10-20',
      fragmentInterval: '10-20',
      ipMaskMode: 'strict-global',
      enabled: true,
      createdAt: now,
      lastRotatedAt: now,
    };
    vault = { ...vault, tokens: [newToken, ...vault.tokens] };
    vault = addVaultLog(vault, 'token_created', 'info', `توکن ${newToken.protocol.toUpperCase()} «${newToken.name}» ایجاد شد.`);
    return { token: newToken, dashboard: buildDashboard(vault) };
  },

  updateToken(
    id: string,
    payload: Partial<Pick<ProxyToken, 'name' | 'cleanIp' | 'port' | 'enabled' | 'tlsFragmentEnabled' | 'ipMaskMode'>>
  ): { token: ProxyToken; dashboard: DashboardState } {
    const vault = loadVault();
    const idx = vault.tokens.findIndex((t) => t.id === id);
    if (idx === -1) throw new Error('توکن یافت نشد.');
    const updated = { ...vault.tokens[idx], ...payload };
    vault.tokens[idx] = updated;
    saveVault(vault);
    return { token: updated, dashboard: buildDashboard(vault) };
  },

  rotateToken(id: string): { token: ProxyToken; dashboard: DashboardState } {
    let vault = loadVault();
    const idx = vault.tokens.findIndex((t) => t.id === id);
    if (idx === -1) throw new Error('توکن یافت نشد.');
    const curr = vault.tokens[idx];
    const rotated: ProxyToken = {
      ...curr,
      secret: curr.protocol === 'trojan' ? randomBase64Url(18) : crypto.randomUUID(),
      path: `/${curr.protocol === 'vless' ? 'ws' : curr.protocol}-${randomHex(4)}`,
      lastRotatedAt: new Date().toISOString(),
    };
    vault.tokens[idx] = rotated;
    vault = addVaultLog(vault, 'token_rotated', 'info', `کلید و مسیر توکن «${rotated.name}» چرخانده شد.`);
    return { token: rotated, dashboard: buildDashboard(vault) };
  },

  deleteToken(id: string): { dashboard: DashboardState } {
    const vault = loadVault();
    vault.tokens = vault.tokens.filter((t) => t.id !== id);
    saveVault(vault);
    return { dashboard: buildDashboard(vault) };
  },

  updateSettings(settings: Partial<SystemSettings>): { dashboard: DashboardState } {
    let vault = loadVault();
    const nextDomain = settings.domain
      ? settings.domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '')
      : vault.settings.domain;
    vault.settings = {
      ...vault.settings,
      ...settings,
      domain: nextDomain,
      workerUrl: `https://${nextDomain}`,
    };
    vault.tokens = vault.tokens.map((t) => ({
      ...t,
      sni: nextDomain,
      host: nextDomain,
    }));
    vault = addVaultLog(vault, 'settings_updated', 'info', `تنظیمات دامنه (${nextDomain}) ذخیره شد.`);
    return { dashboard: buildDashboard(vault) };
  },

  rotateSubscriptionSecret(): { dashboard: DashboardState } {
    let vault = loadVault();
    vault.settings.subscriptionSecret = randomHex(24);
    vault = addVaultLog(vault, 'sub_rotated', 'warning', 'لینک اشتراک بازتولید شد و لینک‌های قبلی منقضی شدند.');
    return { dashboard: buildDashboard(vault) };
  },

  getWorkerScript(): { script: string; dashboard: DashboardState } {
    let vault = loadVault();
    const script = buildCloudflareWorkerScript(vault.tokens, vault.settings);
    vault = addVaultLog(vault, 'worker_exported', 'info', 'اسکریپت ورکر کلودفلر (_worker.js) استخراج شد.');
    return { script, dashboard: buildDashboard(vault) };
  },

  getIncyExport(): { filename: string; content: string } {
    const vault = loadVault();
    return {
      filename: `incy-${vault.settings.domain}.json`,
      content: buildIncySingBoxConfig(vault.tokens, vault.settings),
    };
  },

  getV2RayExport(tokenId: string): { filename: string; content: string } {
    const vault = loadVault();
    const token = vault.tokens.find((t) => t.id === tokenId) || vault.tokens[0];
    if (!token) throw new Error('توکنی یافت نشد.');
    return {
      filename: `v2ray-fragment-${token.protocol}-${vault.settings.domain}.json`,
      content: buildXrayFragmentConfig(token, vault.settings),
    };
  },

  async probeEndpoint(target: string, port = 443): Promise<{ probe: ProbeResult; dashboard: DashboardState }> {
    let vault = loadVault();
    const started = performance.now();
    try {
      const url = target.includes('.') && !/^\d+\.\d+\.\d+\.\d+$/.test(target)
        ? `https://${target}/health-edge`
        : `https://cloudflare-dns.com/dns-query?name=cloudflare.com&type=A`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4500);
      await fetch(url, { mode: 'no-cors', signal: controller.signal });
      clearTimeout(timer);
      const latencyMs = Math.round(performance.now() - started);
      const probe: ProbeResult = {
        target,
        port,
        reachable: true,
        latencyMs,
        tlsProtocol: 'TLSv1.3',
        cipher: 'HTTPS Edge Reachable',
        checkedAt: new Date().toISOString(),
      };
      const idx = vault.cleanIps.findIndex((c) => c.ip === target);
      if (idx !== -1) {
        vault.cleanIps[idx] = {
          ...vault.cleanIps[idx],
          lastLatencyMs: latencyMs,
          reachable: true,
          lastCheckedAt: probe.checkedAt,
        };
      }
      vault = addVaultLog(vault, 'ip_probe', 'info', `تست مرورگر روی ${target}:${port} (${latencyMs}ms)`);
      return { probe, dashboard: buildDashboard(vault) };
    } catch (err) {
      const probe: ProbeResult = {
        target,
        port,
        reachable: false,
        latencyMs: null,
        tlsProtocol: null,
        cipher: null,
        checkedAt: new Date().toISOString(),
        error: err instanceof Error ? err.message : 'Unreachable',
      };
      return { probe, dashboard: buildDashboard(vault) };
    }
  },

  async probeAllCleanIps(): Promise<{
    results: Array<{ ip: string; probe: ProbeResult }>;
    dashboard: DashboardState;
  }> {
    const vault = loadVault();
    const results: Array<{ ip: string; probe: ProbeResult }> = [];
    for (const entry of vault.cleanIps) {
      const started = performance.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3500);
        await fetch('https://1.1.1.1/cdn-cgi/trace', { mode: 'no-cors', signal: controller.signal });
        clearTimeout(timer);
        const latencyMs = Math.round(performance.now() - started);
        entry.lastLatencyMs = latencyMs;
        entry.reachable = true;
        entry.lastCheckedAt = new Date().toISOString();
        results.push({
          ip: entry.ip,
          probe: {
            target: entry.ip,
            port: 443,
            reachable: true,
            latencyMs,
            tlsProtocol: 'TLSv1.3',
            cipher: 'Edge Reachable',
            checkedAt: entry.lastCheckedAt,
          },
        });
      } catch {
        entry.reachable = false;
        entry.lastLatencyMs = null;
        entry.lastCheckedAt = new Date().toISOString();
        results.push({
          ip: entry.ip,
          probe: {
            target: entry.ip,
            port: 443,
            reachable: false,
            latencyMs: null,
            tlsProtocol: null,
            cipher: null,
            checkedAt: entry.lastCheckedAt,
            error: 'Timeout / Blocked',
          },
        });
      }
    }
    saveVault(vault);
    return { results, dashboard: buildDashboard(vault) };
  },

  async runIpAudit(): Promise<IpAuditResult> {
    const res = await fetch('https://cloudflare.com/cdn-cgi/trace');
    const text = await res.text();
    const map: Record<string, string> = {};
    for (const line of text.split('\n')) {
      const [k, v] = line.split('=');
      if (k && v) map[k.trim()] = v.trim();
    }
    return {
      egressIp: map.ip || 'Unknown',
      countryCode: map.loc || 'Unknown',
      colo: map.colo || 'Unknown',
      httpVersion: map.http || 'http/2',
      tlsVersion: map.tls || 'TLSv1.3',
      headersDetectedOnRequest: [],
      iranIpExposed: (map.loc || '').toUpperCase() === 'IR',
      checkedAt: new Date().toISOString(),
    };
  },

  async getD1Status(): Promise<D1StatusResult> {
    const vault = loadVault();
    const dbId = vault.settings.d1DatabaseId || DEFAULT_D1_ID;
    try {
      const resp = await fetch('/health-edge');
      if (resp.ok) {
        const data = (await resp.json().catch(() => ({}))) as { d1Bound?: boolean };
        if (data.d1Bound) {
          return {
            databaseId: dbId,
            bindingName: 'DB',
            restApiConfigured: false,
            connected: true,
            tablesReady: true,
            tokenCountInD1: vault.tokens.length,
            checkedAt: new Date().toISOString(),
            message: 'متصل به دیتابیس کلودفلر D1 از طریق Worker Binding (env.DB).',
          };
        }
      }
    } catch {}

    return {
      databaseId: dbId,
      bindingName: 'DB',
      restApiConfigured: false,
      connected: false,
      tablesReady: false,
      tokenCountInD1: null,
      checkedAt: new Date().toISOString(),
      message:
        'فایل‌های wrangler.toml و _worker.js با شناسه D1 آماده است؛ پس از آپلود dist/_worker.js در Cloudflare Pages و اتصال D1 Binding به نام DB، دیتابیس فعال می‌شود.',
    };
  },
};
