import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import express from 'express';
import {
  buildCloudflareWorkerScript,
  buildD1SchemaSql,
  buildIncySingBoxConfig,
  buildV2RaySubscriptionPayload,
  buildWranglerToml,
  buildXrayFragmentConfig,
} from './src/lib/proxyGenerators.ts';
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
} from './src/types.ts';

const DEFAULT_D1_DATABASE_ID =
  process.env.CLOUDFLARE_D1_DATABASE_ID || 'a16983d7-1da3-4555-a1aa-f5730bccfcae';

const PORT = 3000;
const DATA_DIR = path.resolve(process.cwd(), 'data');
const STORE_PATH = path.join(DATA_DIR, 'store.json');

// Security constants
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

// Derived scrypt credential store (never plaintext comparison)
const ADMIN_USERNAME = 'Arash';
const PASSWORD_SALT = crypto.randomBytes(16).toString('hex');
const ADMIN_PASSWORD_HASH = crypto.scryptSync('Arash741852963', PASSWORD_SALT, 64);

// Ephemeral HMAC key persisted per server boot or derived from env
const SESSION_HMAC_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

interface PersistentStore {
  settings: SystemSettings;
  tokens: ProxyToken[];
  cleanIps: CleanIpEntry[];
  securityLogs: SecurityLogEntry[];
}

interface SessionRecord {
  id: string;
  username: string;
  createdAt: number;
  expiresAt: number;
  ip: string;
}

interface LoginAttemptRecord {
  count: number;
  firstAttemptAt: number;
  lockedUntil: number | null;
}

const activeSessions = new Map<string, SessionRecord>();
const loginAttempts = new Map<string, LoginAttemptRecord>();

function ensureDataDir(): void {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function createInitialStore(): PersistentStore {
  const now = new Date().toISOString();
  const subSecret = crypto.randomBytes(24).toString('hex');
  return {
    settings: {
      domain: 'proxysystemarash.ir',
      workerUrl: 'https://proxysystemarash.ir',
      proxyIp: '104.16.132.229',
      dohProvider: 'https://1.1.1.1/dns-query',
      subscriptionSecret: subSecret,
      d1DatabaseId: DEFAULT_D1_DATABASE_ID,
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
        sni: 'proxysystemarash.ir',
        host: 'proxysystemarash.ir',
        path: `/ws-${crypto.randomBytes(4).toString('hex')}`,
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
        sni: 'proxysystemarash.ir',
        host: 'proxysystemarash.ir',
        path: `/incy-${crypto.randomBytes(4).toString('hex')}`,
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
        secret: crypto.randomBytes(18).toString('base64url'),
        cleanIp: '104.18.2.161',
        port: 8443,
        sni: 'proxysystemarash.ir',
        host: 'proxysystemarash.ir',
        path: `/tr-${crypto.randomBytes(4).toString('hex')}`,
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
        sni: 'proxysystemarash.ir',
        host: 'proxysystemarash.ir',
        path: `/vm-${crypto.randomBytes(4).toString('hex')}`,
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
        sourceIp: '127.0.0.1',
        message: 'هسته امنیتی Arashproxysystem.ir با رمزنگاری scrypt و محافظت Brute-Force راه‌اندازی شد.',
      },
    ],
  };
}

function loadStore(): PersistentStore {
  ensureDataDir();
  if (!fs.existsSync(STORE_PATH)) {
    const initial = createInitialStore();
    fs.writeFileSync(STORE_PATH, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
  try {
    const raw = fs.readFileSync(STORE_PATH, 'utf8');
    const parsed = JSON.parse(raw) as PersistentStore;
    if (!parsed.settings.d1DatabaseId) {
      parsed.settings.d1DatabaseId = DEFAULT_D1_DATABASE_ID;
    }
    return parsed;
  } catch {
    const fallback = createInitialStore();
    fs.writeFileSync(STORE_PATH, JSON.stringify(fallback, null, 2), 'utf8');
    return fallback;
  }
}

let store: PersistentStore = loadStore();

function saveStore(): void {
  ensureDataDir();
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), 'utf8');
  try {
    const workerDir = path.resolve(process.cwd(), 'worker');
    if (!fs.existsSync(workerDir)) fs.mkdirSync(workerDir, { recursive: true });
    fs.writeFileSync(
      path.join(workerDir, 'index.js'),
      buildCloudflareWorkerScript(store.tokens, store.settings),
      'utf8'
    );
    fs.writeFileSync(
      path.resolve(process.cwd(), 'wrangler.toml'),
      buildWranglerToml(store.settings),
      'utf8'
    );
  } catch {
    // Non-fatal if filesystem is read-only
  }
}

async function queryCloudflareD1(
  databaseId: string,
  sql: string
): Promise<{ success: boolean; results?: Array<Record<string, unknown>>; error?: string }> {
  const accountId = process.env.CLOUDFLARE_ACCOUNT_ID?.trim();
  const apiToken = process.env.CLOUDFLARE_API_TOKEN?.trim();
  if (!accountId || !apiToken) {
    return { success: false, error: 'CLOUDFLARE_ACCOUNT_ID or CLOUDFLARE_API_TOKEN not set' };
  }

  const endpoint = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/d1/database/${encodeURIComponent(databaseId)}/query`;
  const resp = await fetch(endpoint, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ sql }),
  });

  const data = (await resp.json().catch(() => ({}))) as {
    success?: boolean;
    errors?: Array<{ message?: string }>;
    result?: Array<{ results?: Array<Record<string, unknown>> }>;
  };

  if (!resp.ok || !data.success) {
    return {
      success: false,
      error: data.errors?.[0]?.message || `Cloudflare D1 HTTP ${resp.status}`,
    };
  }

  return {
    success: true,
    results: data.result?.[0]?.results || [],
  };
}

function appendSecurityLog(
  eventType: SecurityLogEntry['eventType'],
  severity: SecurityLogEntry['severity'],
  sourceIp: string,
  message: string
): void {
  const entry: SecurityLogEntry = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    eventType,
    severity,
    sourceIp,
    message,
  };
  store.securityLogs = [entry, ...store.securityLogs].slice(0, 60);
  saveStore();
}

function getClientIp(req: express.Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function maskIpForLog(ip: string): string {
  if (ip === '127.0.0.1' || ip === '::1') return 'Localhost';
  const parts = ip.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.*.*`;
  }
  return ip.slice(0, 12) + '...';
}

function signSessionToken(sessionId: string): string {
  const signature = crypto
    .createHmac('sha256', SESSION_HMAC_SECRET)
    .update(sessionId)
    .digest('hex');
  return `${sessionId}.${signature}`;
}

function verifySignedToken(token: string | undefined): SessionRecord | null {
  if (!token || !token.includes('.')) return null;
  const [sessionId, sig] = token.split('.');
  if (!sessionId || !sig) return null;

  const expectedSig = crypto
    .createHmac('sha256', SESSION_HMAC_SECRET)
    .update(sessionId)
    .digest('hex');

  const sigBuf = Buffer.from(sig, 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return null;
  }

  const record = activeSessions.get(sessionId);
  if (!record) return null;
  if (Date.now() > record.expiresAt) {
    activeSessions.delete(sessionId);
    return null;
  }
  return record;
}

function extractTokenFromRequest(req: express.Request): string | undefined {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    for (const part of cookieHeader.split(';')) {
      const [k, ...rest] = part.trim().split('=');
      if (k === 'arash_session') {
        return decodeURIComponent(rest.join('='));
      }
    }
  }
  return undefined;
}

function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const token = extractTokenFromRequest(req);
  const session = verifySignedToken(token);
  if (!session) {
    res.status(401).json({ error: 'نشست کاربری نامعتبر یا منقضی شده است.' });
    return;
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const requestedWith = req.headers['x-requested-with'];
    if (requestedWith !== 'ArashProxyConsole') {
      res.status(403).json({ error: 'درخواست فاقد هدر امنیتی CSRF است.' });
      return;
    }
  }
  (req as express.Request & { session?: SessionRecord }).session = session;
  next();
}

function verifyPasswordTimingSafe(username: string, password: string): boolean {
  const userBuf = Buffer.from(username.trim(), 'utf8');
  const expectedUserBuf = Buffer.from(ADMIN_USERNAME, 'utf8');
  const userMatch =
    userBuf.length === expectedUserBuf.length && crypto.timingSafeEqual(userBuf, expectedUserBuf);

  const derived = crypto.scryptSync(password, PASSWORD_SALT, 64);
  const passMatch =
    derived.length === ADMIN_PASSWORD_HASH.length &&
    crypto.timingSafeEqual(derived, ADMIN_PASSWORD_HASH);

  return userMatch && passMatch;
}

function getActiveLockoutsCount(): number {
  const now = Date.now();
  let count = 0;
  for (const [, rec] of loginAttempts) {
    if (rec.lockedUntil && rec.lockedUntil > now) count++;
  }
  return count;
}

function getDashboardPayload(): DashboardState {
  return {
    settings: store.settings,
    tokens: store.tokens,
    cleanIps: store.cleanIps,
    securityLogs: store.securityLogs,
    securityPosture: {
      authAlgorithm: 'scrypt (N=16384) + timingSafeEqual',
      sessionCipher: 'HMAC-SHA256 Signed Session',
      rateLimitWindowMinutes: 15,
      maxFailedAttempts: MAX_FAILED_ATTEMPTS,
      activeLockouts: getActiveLockoutsCount(),
      headersEnforced: [
        'X-Content-Type-Options: nosniff',
        'Referrer-Policy: no-referrer',
        'Strict-Transport-Security',
        'CSRF Custom Header Check',
      ],
    },
  };
}

function probeTlsEndpoint(host: string, port: number, servername: string): Promise<ProbeResult> {
  return new Promise((resolve) => {
    const started = performance.now();
    let settled = false;

    const socket = tls.connect(
      {
        host,
        port,
        servername: servername || host,
        rejectUnauthorized: false,
        timeout: 4500,
      },
      () => {
        if (settled) return;
        settled = true;
        const latencyMs = Math.round(performance.now() - started);
        const protocol = socket.getProtocol() || 'TLSv1.3';
        const cipher = socket.getCipher()?.name || 'TLS_AES_128_GCM_SHA256';
        socket.end();
        resolve({
          target: host,
          port,
          reachable: true,
          latencyMs,
          tlsProtocol: protocol,
          cipher,
          checkedAt: new Date().toISOString(),
        });
      }
    );

    socket.setTimeout(4500, () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({
        target: host,
        port,
        reachable: false,
        latencyMs: null,
        tlsProtocol: null,
        cipher: null,
        checkedAt: new Date().toISOString(),
        error: 'Timeout (4500ms)',
      });
    });

    socket.on('error', (err) => {
      if (settled) return;
      settled = true;
      resolve({
        target: host,
        port,
        reachable: false,
        latencyMs: null,
        tlsProtocol: null,
        cipher: null,
        checkedAt: new Date().toISOString(),
        error: err.message,
      });
    });
  });
}

async function startServer(): Promise<void> {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  // Security headers on every response (preserving iframe preview compatibility)
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-DNS-Prefetch-Control', 'off');
    next();
  });

  app.use(express.json({ limit: '256kb' }));

  // Live Subscription Endpoint for V2Ray & INCY clients
  app.get('/sub/:secret', (req, res) => {
    const { secret } = req.params;
    const expectedBuf = Buffer.from(store.settings.subscriptionSecret, 'utf8');
    const providedBuf = Buffer.from(secret || '', 'utf8');

    if (
      expectedBuf.length !== providedBuf.length ||
      !crypto.timingSafeEqual(expectedBuf, providedBuf)
    ) {
      res.status(404).type('text/plain').send('Not Found');
      return;
    }

    const format = String(req.query.format || 'v2ray').toLowerCase();
    res.setHeader('Profile-Title', 'Arashproxysystem.ir');
    res.setHeader('Profile-Update-Interval', '6');
    res.setHeader('Subscription-Userinfo', 'upload=0; download=0; total=10737418240000; expire=0');
    res.setHeader('Cache-Control', 'no-store');

    if (format === 'incy' || format === 'singbox') {
      res
        .type('application/json; charset=utf-8')
        .send(buildIncySingBoxConfig(store.tokens, store.settings));
      return;
    }

    res.type('text/plain; charset=utf-8').send(buildV2RaySubscriptionPayload(store.tokens));
  });

  // Authentication Routes
  app.post('/api/auth/login', (req, res) => {
    const clientIp = getClientIp(req);
    const maskedIp = maskIpForLog(clientIp);
    const now = Date.now();

    const record = loginAttempts.get(clientIp);
    if (record && record.lockedUntil && record.lockedUntil > now) {
      const remainingSec = Math.ceil((record.lockedUntil - now) / 1000);
      res.status(429).json({
        error: `به دلیل تلاش‌های ناموفق متعدد، دسترسی موقتاً مسدود شد. لطفاً ${remainingSec} ثانیه دیگر تلاش کنید.`,
        lockedUntil: record.lockedUntil,
      });
      return;
    }

    const username = typeof req.body?.username === 'string' ? req.body.username : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!verifyPasswordTimingSafe(username, password)) {
      const prevCount =
        record && now - record.firstAttemptAt < LOCKOUT_WINDOW_MS ? record.count : 0;
      const nextCount = prevCount + 1;
      const shouldLock = nextCount >= MAX_FAILED_ATTEMPTS;

      loginAttempts.set(clientIp, {
        count: nextCount,
        firstAttemptAt: record ? record.firstAttemptAt : now,
        lockedUntil: shouldLock ? now + LOCKOUT_WINDOW_MS : null,
      });

      appendSecurityLog(
        shouldLock ? 'bruteforce_lockout' : 'login_failed',
        shouldLock ? 'critical' : 'warning',
        maskedIp,
        shouldLock
          ? `قفل امنیتی ۱۵ دقیقه‌ای پس از ${MAX_FAILED_ATTEMPTS} تلاش ناموفق ورود فعال شد.`
          : `تلاش ناموفق ورود با نام کاربری «${username || 'خالی'}» مسدود گردید (${nextCount}/${MAX_FAILED_ATTEMPTS}).`
      );

      res.status(401).json({
        error: shouldLock
          ? 'حساب به مدت ۱۵ دقیقه برای جلوگیری از حمله Brute-Force قفل شد.'
          : `نام کاربری یا رمز عبور اشتباه است. (${MAX_FAILED_ATTEMPTS - nextCount} تلاش باقی‌مانده)`,
      });
      return;
    }

    loginAttempts.delete(clientIp);

    const sessionId = crypto.randomBytes(24).toString('hex');
    const session: SessionRecord = {
      id: sessionId,
      username: ADMIN_USERNAME,
      createdAt: now,
      expiresAt: now + SESSION_TTL_MS,
      ip: maskedIp,
    };
    activeSessions.set(sessionId, session);
    const signedToken = signSessionToken(sessionId);

    res.cookie('arash_session', signedToken, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: SESSION_TTL_MS,
    });

    appendSecurityLog(
      'login_success',
      'info',
      maskedIp,
      `ورود موفق مدیر (${ADMIN_USERNAME}) به سامانه ${store.settings.domain}.`
    );

    res.json({
      authenticated: true,
      username: ADMIN_USERNAME,
      token: signedToken,
      expiresAt: session.expiresAt,
    });
  });

  app.get('/api/auth/session', (req, res) => {
    const token = extractTokenFromRequest(req);
    const session = verifySignedToken(token);
    if (!session) {
      res.status(401).json({ authenticated: false });
      return;
    }
    res.json({
      authenticated: true,
      username: session.username,
      expiresAt: session.expiresAt,
    });
  });

  app.post('/api/auth/logout', requireAuth, (req, res) => {
    const token = extractTokenFromRequest(req);
    if (token && token.includes('.')) {
      const [sessionId] = token.split('.');
      activeSessions.delete(sessionId);
    }
    res.clearCookie('arash_session', { path: '/' });
    res.json({ ok: true });
  });

  // Protected Dashboard & Proxy Management APIs
  app.get('/api/dashboard', requireAuth, (_req, res) => {
    res.json(getDashboardPayload());
  });

  app.post('/api/tokens', requireAuth, (req, res) => {
    const clientIp = maskIpForLog(getClientIp(req));
    const protocol: ProxyProtocol =
      req.body?.protocol === 'trojan' || req.body?.protocol === 'vmess'
        ? req.body.protocol
        : 'vless';
    const name =
      typeof req.body?.name === 'string' && req.body.name.trim()
        ? req.body.name.trim().slice(0, 64)
        : `Node-${protocol.toUpperCase()}-${crypto.randomBytes(2).toString('hex')}`;
    const cleanIp =
      typeof req.body?.cleanIp === 'string' && req.body.cleanIp.trim()
        ? req.body.cleanIp.trim()
        : store.cleanIps[0]?.ip || '104.16.132.229';
    const port = Number(req.body?.port) || 443;
    const transport = req.body?.transport === 'grpc' && protocol === 'vless' ? 'grpc' : 'ws';
    const tlsFragmentEnabled = req.body?.tlsFragmentEnabled !== false;
    const fingerprint =
      req.body?.fingerprint === 'firefox' ||
      req.body?.fingerprint === 'safari' ||
      req.body?.fingerprint === 'random'
        ? req.body.fingerprint
        : 'chrome';

    const now = new Date().toISOString();
    const newToken: ProxyToken = {
      id: crypto.randomUUID(),
      name,
      protocol,
      secret:
        protocol === 'trojan'
          ? crypto.randomBytes(18).toString('base64url')
          : crypto.randomUUID(),
      cleanIp,
      port,
      sni: store.settings.domain,
      host: store.settings.domain,
      path: `/${protocol === 'vless' ? 'ws' : protocol}-${crypto.randomBytes(4).toString('hex')}`,
      transport,
      fingerprint,
      tlsFragmentEnabled,
      fragmentLength: '10-20',
      fragmentInterval: '10-20',
      ipMaskMode: 'strict-global',
      enabled: true,
      createdAt: now,
      lastRotatedAt: now,
    };

    store.tokens = [newToken, ...store.tokens];
    saveStore();
    appendSecurityLog(
      'token_created',
      'info',
      clientIp,
      `توکن جدید ${protocol.toUpperCase()} با نام «${newToken.name}» ایجاد شد.`
    );

    res.status(201).json({ token: newToken, dashboard: getDashboardPayload() });
  });

  app.patch('/api/tokens/:id', requireAuth, (req, res) => {
    const idx = store.tokens.findIndex((t) => t.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({ error: 'توکن یافت نشد.' });
      return;
    }

    const current = store.tokens[idx];
    const updated: ProxyToken = {
      ...current,
      ...(typeof req.body?.name === 'string' && req.body.name.trim()
        ? { name: req.body.name.trim().slice(0, 64) }
        : {}),
      ...(typeof req.body?.cleanIp === 'string' && req.body.cleanIp.trim()
        ? { cleanIp: req.body.cleanIp.trim() }
        : {}),
      ...(typeof req.body?.port === 'number' && req.body.port > 0 && req.body.port <= 65535
        ? { port: req.body.port }
        : {}),
      ...(typeof req.body?.enabled === 'boolean' ? { enabled: req.body.enabled } : {}),
      ...(typeof req.body?.tlsFragmentEnabled === 'boolean'
        ? { tlsFragmentEnabled: req.body.tlsFragmentEnabled }
        : {}),
      ...(req.body?.ipMaskMode === 'strict-global' || req.body?.ipMaskMode === 'lan-only-bypass'
        ? { ipMaskMode: req.body.ipMaskMode }
        : {}),
    };

    store.tokens[idx] = updated;
    saveStore();
    res.json({ token: updated, dashboard: getDashboardPayload() });
  });

  app.post('/api/tokens/:id/rotate', requireAuth, (req, res) => {
    const clientIp = maskIpForLog(getClientIp(req));
    const idx = store.tokens.findIndex((t) => t.id === req.params.id);
    if (idx === -1) {
      res.status(404).json({ error: 'توکن یافت نشد.' });
      return;
    }

    const current = store.tokens[idx];
    const rotated: ProxyToken = {
      ...current,
      secret:
        current.protocol === 'trojan'
          ? crypto.randomBytes(18).toString('base64url')
          : crypto.randomUUID(),
      path: `/${current.protocol === 'vless' ? 'ws' : current.protocol}-${crypto.randomBytes(4).toString('hex')}`,
      lastRotatedAt: new Date().toISOString(),
    };

    store.tokens[idx] = rotated;
    saveStore();
    appendSecurityLog(
      'token_rotated',
      'info',
      clientIp,
      `شناسه رمزنگاری و مسیر WebSocket توکن «${rotated.name}» برای جلوگیری از شناسایی چرخانده شد.`
    );

    res.json({ token: rotated, dashboard: getDashboardPayload() });
  });

  app.delete('/api/tokens/:id', requireAuth, (req, res) => {
    const before = store.tokens.length;
    store.tokens = store.tokens.filter((t) => t.id !== req.params.id);
    if (store.tokens.length === before) {
      res.status(404).json({ error: 'توکن یافت نشد.' });
      return;
    }
    saveStore();
    res.json({ dashboard: getDashboardPayload() });
  });

  app.put('/api/settings', requireAuth, (req, res) => {
    const clientIp = maskIpForLog(getClientIp(req));
    const b = req.body || {};

    const nextDomain =
      typeof b.domain === 'string' && b.domain.trim()
        ? b.domain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
        : store.settings.domain;

    store.settings = {
      ...store.settings,
      domain: nextDomain,
      workerUrl:
        typeof b.workerUrl === 'string' && b.workerUrl.trim()
          ? b.workerUrl.trim()
          : `https://${nextDomain}`,
      proxyIp:
        typeof b.proxyIp === 'string' && b.proxyIp.trim()
          ? b.proxyIp.trim()
          : store.settings.proxyIp,
      dohProvider:
        typeof b.dohProvider === 'string' && b.dohProvider.trim()
          ? b.dohProvider.trim()
          : store.settings.dohProvider,
      antiProbeDecoy:
        typeof b.antiProbeDecoy === 'boolean' ? b.antiProbeDecoy : store.settings.antiProbeDecoy,
      webrtcBlock: typeof b.webrtcBlock === 'boolean' ? b.webrtcBlock : store.settings.webrtcBlock,
      strictIpMask:
        typeof b.strictIpMask === 'boolean' ? b.strictIpMask : store.settings.strictIpMask,
      stripClientHeaders:
        typeof b.stripClientHeaders === 'boolean'
          ? b.stripClientHeaders
          : store.settings.stripClientHeaders,
      decoyTitle:
        typeof b.decoyTitle === 'string' && b.decoyTitle.trim()
          ? b.decoyTitle.trim().slice(0, 80)
          : store.settings.decoyTitle,
      d1DatabaseId:
        typeof b.d1DatabaseId === 'string' && b.d1DatabaseId.trim()
          ? b.d1DatabaseId.trim()
          : store.settings.d1DatabaseId,
    };

    // Sync SNI and Host across tokens when domain changes
    store.tokens = store.tokens.map((t) => ({
      ...t,
      sni: store.settings.domain,
      host: store.settings.domain,
    }));

    saveStore();
    appendSecurityLog(
      'settings_updated',
      'info',
      clientIp,
      `تنظیمات امنیتی و دامنه (${store.settings.domain}) به‌روزرسانی شد.`
    );

    res.json({ dashboard: getDashboardPayload() });
  });

  app.post('/api/settings/rotate-sub', requireAuth, (req, res) => {
    const clientIp = maskIpForLog(getClientIp(req));
    store.settings.subscriptionSecret = crypto.randomBytes(24).toString('hex');
    saveStore();
    appendSecurityLog(
      'sub_rotated',
      'warning',
      clientIp,
      'توکن لینک اشتراک (Subscription) بازتولید شد؛ لینک‌های قبلی فوراً غیرفعال شدند.'
    );
    res.json({ dashboard: getDashboardPayload() });
  });

  app.get('/api/worker-script', requireAuth, (req, res) => {
    const clientIp = maskIpForLog(getClientIp(req));
    const script = buildCloudflareWorkerScript(store.tokens, store.settings);
    appendSecurityLog(
      'worker_exported',
      'info',
      clientIp,
      'اسکریپت ورکر کلودفلر (_worker.js) با تنظیمات ضدنشت IP استخراج شد.'
    );
    res.json({ script, dashboard: getDashboardPayload() });
  });

  app.get('/api/export/incy', requireAuth, (_req, res) => {
    res.json({
      filename: `incy-${store.settings.domain}.json`,
      content: buildIncySingBoxConfig(store.tokens, store.settings),
    });
  });

  app.get('/api/d1/status', requireAuth, async (_req, res) => {
    const dbId = store.settings.d1DatabaseId || DEFAULT_D1_DATABASE_ID;
    const hasEnvCreds = Boolean(
      process.env.CLOUDFLARE_ACCOUNT_ID?.trim() && process.env.CLOUDFLARE_API_TOKEN?.trim()
    );

    if (!hasEnvCreds) {
      const payload: D1StatusResult = {
        databaseId: dbId,
        bindingName: 'DB',
        restApiConfigured: false,
        connected: false,
        tablesReady: false,
        tokenCountInD1: null,
        checkedAt: new Date().toISOString(),
        message:
          'شناسه D1 در wrangler.toml و _worker.js متصل است. برای همگام‌سازی مستقیم از طریق REST API، متغیرهای CLOUDFLARE_ACCOUNT_ID و CLOUDFLARE_API_TOKEN را در محیط سرور تنظیم کنید.',
      };
      res.json(payload);
      return;
    }

    const q = await queryCloudflareD1(dbId, 'SELECT COUNT(*) AS cnt FROM proxy_tokens');
    if (!q.success) {
      const isNoTable = (q.error || '').toLowerCase().includes('no such table');
      const payload: D1StatusResult = {
        databaseId: dbId,
        bindingName: 'DB',
        restApiConfigured: true,
        connected: isNoTable,
        tablesReady: false,
        tokenCountInD1: null,
        checkedAt: new Date().toISOString(),
        message: isNoTable
          ? 'اتصال به کلودفلر D1 برقرار است؛ جداول هنوز ساخته نشده‌اند. روی «همگام‌سازی و ساخت جداول D1» کلیک کنید.'
          : `خطا در اتصال به D1: ${q.error}`,
      };
      res.json(payload);
      return;
    }

    const countVal = Number(q.results?.[0]?.cnt ?? 0);
    const payload: D1StatusResult = {
      databaseId: dbId,
      bindingName: 'DB',
      restApiConfigured: true,
      connected: true,
      tablesReady: true,
      tokenCountInD1: countVal,
      checkedAt: new Date().toISOString(),
      message: `متصل به دیتابیس کلودفلر D1 (${countVal} توکن همگام‌سازی‌شده).`,
    };
    res.json(payload);
  });

  app.post('/api/d1/sync', requireAuth, async (req, res) => {
    const clientIp = maskIpForLog(getClientIp(req));
    const dbId = store.settings.d1DatabaseId || DEFAULT_D1_DATABASE_ID;
    const sql = buildD1SchemaSql(store.tokens, store.settings);
    const result = await queryCloudflareD1(dbId, sql);

    if (!result.success) {
      res.status(400).json({
        error: result.error || 'خطا در همگام‌سازی با کلودفلر D1',
      });
      return;
    }

    appendSecurityLog(
      'settings_updated',
      'info',
      clientIp,
      `همگام‌سازی کامل توکن‌ها و تنظیمات با دیتابیس کلودفلر D1 (${dbId}) انجام شد.`
    );

    res.json({
      ok: true,
      databaseId: dbId,
      syncedTokens: store.tokens.length,
      dashboard: getDashboardPayload(),
    });
  });

  app.get('/api/export/v2ray/:id', requireAuth, (req, res) => {
    const token = store.tokens.find((t) => t.id === req.params.id) || store.tokens[0];
    if (!token) {
      res.status(404).json({ error: 'هیچ توکنی یافت نشد.' });
      return;
    }
    res.json({
      filename: `v2ray-fragment-${token.protocol}-${store.settings.domain}.json`,
      content: buildXrayFragmentConfig(token, store.settings),
    });
  });

  // Real TLS/Socket probe for Cloudflare Clean IPs and Arashproxysystem.ir
  app.post('/api/network/probe', requireAuth, async (req, res) => {
    const clientIp = maskIpForLog(getClientIp(req));
    const target =
      typeof req.body?.target === 'string' && req.body.target.trim()
        ? req.body.target.trim()
        : store.cleanIps[0]?.ip;

    if (!target) {
      res.status(400).json({ error: 'آدرس هدف مشخص نشده است.' });
      return;
    }

    const port = Number(req.body?.port) || 443;
    const sni =
      typeof req.body?.sni === 'string' && req.body.sni.trim()
        ? req.body.sni.trim()
        : store.settings.domain;

    const result = await probeTlsEndpoint(target, port, sni);

    // Update cleanIps table if matching IP exists
    const ipIdx = store.cleanIps.findIndex((c) => c.ip === target);
    if (ipIdx !== -1) {
      store.cleanIps[ipIdx] = {
        ...store.cleanIps[ipIdx],
        lastLatencyMs: result.latencyMs,
        reachable: result.reachable,
        lastCheckedAt: result.checkedAt,
      };
      saveStore();
    }

    appendSecurityLog(
      'ip_probe',
      result.reachable ? 'info' : 'warning',
      clientIp,
      `تست TLS روی ${target}:${port} — ${result.reachable ? `متصل (${result.latencyMs}ms)` : 'عدم دسترسی'}`
    );

    res.json({ probe: result, dashboard: getDashboardPayload() });
  });

  app.post('/api/network/probe-all', requireAuth, async (_req, res) => {
    const results = await Promise.all(
      store.cleanIps.map((entry) =>
        probeTlsEndpoint(entry.ip, 443, store.settings.domain).then((probe) => ({
          ip: entry.ip,
          probe,
        }))
      )
    );

    for (const item of results) {
      const idx = store.cleanIps.findIndex((c) => c.ip === item.ip);
      if (idx !== -1) {
        store.cleanIps[idx] = {
          ...store.cleanIps[idx],
          lastLatencyMs: item.probe.latencyMs,
          reachable: item.probe.reachable,
          lastCheckedAt: item.probe.checkedAt,
        };
      }
    }
    saveStore();
    res.json({ results, dashboard: getDashboardPayload() });
  });

  // Real Egress IP & Anti-Iran-Leak Verification
  app.get('/api/network/ip-audit', requireAuth, async (req, res) => {
    const detectedHeaders = ['x-forwarded-for', 'x-real-ip', 'cf-connecting-ip', 'true-client-ip']
      .filter((h) => Boolean(req.headers[h]));

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4500);
      const traceRes = await fetch('https://1.1.1.1/cdn-cgi/trace', {
        signal: controller.signal,
      });
      clearTimeout(timeout);
      const text = await traceRes.text();
      const map: Record<string, string> = {};
      for (const line of text.split('\n')) {
        const [k, v] = line.split('=');
        if (k && v) map[k.trim()] = v.trim();
      }

      const payload: IpAuditResult = {
        egressIp: map.ip || 'Unknown',
        countryCode: map.loc || 'Unknown',
        colo: map.colo || 'Unknown',
        httpVersion: map.http || 'http/2',
        tlsVersion: map.tls || 'TLSv1.3',
        headersDetectedOnRequest: detectedHeaders,
        iranIpExposed: (map.loc || '').toUpperCase() === 'IR',
        checkedAt: new Date().toISOString(),
      };
      res.json(payload);
    } catch {
      res.status(502).json({ error: 'خطا در برقراری ارتباط با سرویس بررسی IP کلودفلر.' });
    }
  });

  // Vite Dev Middleware or Static Production Serving
  const distDir = path.resolve(process.cwd(), 'dist');
  const isProd =
    process.env.NODE_ENV === 'production' ||
    (process.env.npm_lifecycle_event !== 'dev' && fs.existsSync(distDir));

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`ArashProxy System running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
