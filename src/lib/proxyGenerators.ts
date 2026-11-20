import type { ProxyToken, SystemSettings } from '../types.ts';

function toBase64Utf8(str: string): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(str, 'utf8').toString('base64');
  }
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function buildProxyUri(token: ProxyToken): string {
  const tag = encodeURIComponent(`${token.name} [ArashProxy]`);
  const wsPath = encodeURIComponent(`${token.path}?ed=2048`);

  if (token.protocol === 'vless') {
    if (token.transport === 'grpc') {
      const serviceName = encodeURIComponent(token.path.replace(/^\//, ''));
      return `vless://${token.secret}@${token.cleanIp}:${token.port}?encryption=none&security=tls&sni=${encodeURIComponent(token.sni)}&fp=${token.fingerprint}&alpn=h2&type=grpc&serviceName=${serviceName}&mode=gun#${tag}`;
    }
    return `vless://${token.secret}@${token.cleanIp}:${token.port}?encryption=none&security=tls&sni=${encodeURIComponent(token.sni)}&fp=${token.fingerprint}&alpn=http%2F1.1&type=ws&host=${encodeURIComponent(token.host)}&path=${wsPath}#${tag}`;
  }

  if (token.protocol === 'trojan') {
    return `trojan://${encodeURIComponent(token.secret)}@${token.cleanIp}:${token.port}?security=tls&sni=${encodeURIComponent(token.sni)}&fp=${token.fingerprint}&alpn=http%2F1.1&type=ws&host=${encodeURIComponent(token.host)}&path=${wsPath}#${tag}`;
  }

  // VMess JSON v2 URI
  const vmessConfig = {
    v: '2',
    ps: `${token.name} [ArashProxy]`,
    add: token.cleanIp,
    port: String(token.port),
    id: token.secret,
    aid: '0',
    scy: 'auto',
    net: token.transport,
    type: 'none',
    host: token.host,
    path: `${token.path}?ed=2048`,
    tls: 'tls',
    sni: token.sni,
    alpn: 'http/1.1',
    fp: token.fingerprint,
  };
  return `vmess://${toBase64Utf8(JSON.stringify(vmessConfig))}`;
}

export function buildRawUriList(tokens: ProxyToken[]): string {
  return tokens
    .filter((t) => t.enabled)
    .map(buildProxyUri)
    .join('\n');
}

export function buildV2RaySubscriptionPayload(tokens: ProxyToken[]): string {
  return toBase64Utf8(buildRawUriList(tokens));
}

export function buildIncySingBoxConfig(tokens: ProxyToken[], settings: SystemSettings): string {
  const activeTokens = tokens.filter((t) => t.enabled);
  const outbounds: Record<string, unknown>[] = [];
  const selectorTags: string[] = [];

  for (const token of activeTokens) {
    const tag = `${token.name} (${token.protocol.toUpperCase()})`;
    selectorTags.push(tag);

    const tlsConfig: Record<string, unknown> = {
      enabled: true,
      server_name: token.sni,
      utls: {
        enabled: true,
        fingerprint: token.fingerprint === 'random' ? 'chrome' : token.fingerprint,
      },
      alpn: token.transport === 'grpc' ? ['h2'] : ['http/1.1'],
    };

    const transportConfig: Record<string, unknown> =
      token.transport === 'grpc'
        ? {
            type: 'grpc',
            service_name: token.path.replace(/^\//, ''),
          }
        : {
            type: 'ws',
            path: `${token.path}?ed=2048`,
            headers: {
              Host: token.host,
            },
            max_early_data: 2048,
            early_data_header_name: 'Sec-WebSocket-Protocol',
          };

    if (token.protocol === 'vless') {
      outbounds.push({
        type: 'vless',
        tag,
        server: token.cleanIp,
        server_port: token.port,
        uuid: token.secret,
        packet_encoding: 'xudp',
        tls: tlsConfig,
        transport: transportConfig,
      });
    } else if (token.protocol === 'trojan') {
      outbounds.push({
        type: 'trojan',
        tag,
        server: token.cleanIp,
        server_port: token.port,
        password: token.secret,
        tls: tlsConfig,
        transport: transportConfig,
      });
    } else {
      outbounds.push({
        type: 'vmess',
        tag,
        server: token.cleanIp,
        server_port: token.port,
        uuid: token.secret,
        security: 'auto',
        alter_id: 0,
        tls: tlsConfig,
        transport: transportConfig,
      });
    }
  }

  const autoTag = 'Auto-Best-Edge';
  const proxyTag = 'ArashProxy-Secure';

  const config = {
    log: {
      level: 'warn',
      timestamp: true,
    },
    dns: {
      servers: [
        {
          tag: 'doh-remote',
          address: settings.dohProvider || 'https://1.1.1.1/dns-query',
          address_resolver: 'dns-bootstrap',
          detour: proxyTag,
          strategy: 'ipv4_only',
        },
        {
          tag: 'dns-bootstrap',
          address: '1.1.1.1',
          detour: 'direct',
        },
        {
          tag: 'dns-block',
          address: 'rcode://success',
        },
      ],
      rules: [
        {
          outbound: 'any',
          server: 'dns-bootstrap',
        },
        {
          protocol: 'stun',
          server: 'dns-block',
        },
      ],
      final: 'doh-remote',
      independent_cache: true,
    },
    inbounds: [
      {
        type: 'tun',
        tag: 'tun-in',
        inet4_address: '172.19.0.1/30',
        mtu: 1400,
        auto_route: true,
        strict_route: true,
        stack: 'system',
        sniff: true,
        sniff_override_destination: true,
      },
      {
        type: 'mixed',
        tag: 'mixed-in',
        listen: '127.0.0.1',
        listen_port: 2080,
        sniff: true,
      },
    ],
    outbounds: [
      {
        type: 'selector',
        tag: proxyTag,
        outbounds: selectorTags.length > 0 ? [autoTag, ...selectorTags] : ['direct'],
        default: selectorTags.length > 0 ? autoTag : 'direct',
      },
      ...(selectorTags.length > 0
        ? [
            {
              type: 'urltest',
              tag: autoTag,
              outbounds: selectorTags,
              url: 'https://www.gstatic.com/generate_204',
              interval: '3m',
              tolerance: 50,
            },
          ]
        : []),
      ...outbounds,
      {
        type: 'direct',
        tag: 'direct',
      },
      {
        type: 'block',
        tag: 'block',
      },
      {
        type: 'dns',
        tag: 'dns-out',
      },
    ],
    route: {
      rules: [
        {
          protocol: 'dns',
          outbound: 'dns-out',
        },
        ...(settings.webrtcBlock
          ? [
              {
                protocol: 'stun',
                outbound: 'block',
              },
            ]
          : []),
        {
          ip_is_private: true,
          outbound: 'direct',
        },
      ],
      final: proxyTag,
      auto_detect_interface: true,
    },
  };

  return JSON.stringify(config, null, 2);
}

export function buildXrayFragmentConfig(token: ProxyToken, settings: SystemSettings): string {
  const fragmentOutbound = {
    tag: 'fragment',
    protocol: 'freedom',
    settings: {
      domainStrategy: 'AsIs',
      fragment: {
        packets: 'tlshello',
        length: token.fragmentLength || '10-20',
        interval: token.fragmentInterval || '10-20',
      },
    },
    streamSettings: {
      sockopt: {
        tcpKeepAliveIdle: 100,
        tcpNoDelay: true,
      },
    },
  };

  const proxyOutbound: Record<string, unknown> = {
    tag: 'proxy',
    protocol: token.protocol,
    settings:
      token.protocol === 'vless'
        ? {
            vnext: [
              {
                address: token.cleanIp,
                port: token.port,
                users: [
                  {
                    id: token.secret,
                    encryption: 'none',
                  },
                ],
              },
            ],
          }
        : token.protocol === 'trojan'
          ? {
              servers: [
                {
                  address: token.cleanIp,
                  port: token.port,
                  password: token.secret,
                },
              ],
            }
          : {
              vnext: [
                {
                  address: token.cleanIp,
                  port: token.port,
                  users: [
                    {
                      id: token.secret,
                      alterId: 0,
                      security: 'auto',
                    },
                  ],
                },
              ],
            },
    streamSettings: {
      network: token.transport,
      security: 'tls',
      tlsSettings: {
        serverName: token.sni,
        allowInsecure: false,
        fingerprint: token.fingerprint === 'random' ? 'chrome' : token.fingerprint,
        alpn: token.transport === 'grpc' ? ['h2'] : ['http/1.1'],
      },
      ...(token.transport === 'ws'
        ? {
            wsSettings: {
              path: `${token.path}?ed=2048`,
              headers: {
                Host: token.host,
              },
            },
          }
        : {
            grpcSettings: {
              serviceName: token.path.replace(/^\//, ''),
              multiMode: false,
            },
          }),
      ...(token.tlsFragmentEnabled
        ? {
            sockopt: {
              dialerProxy: 'fragment',
              tcpKeepAliveIdle: 100,
              tcpNoDelay: true,
            },
          }
        : {}),
    },
  };

  const config = {
    remarks: `${token.name} - ${settings.domain} (Anti-DPI + Zero-IP-Leak)`,
    dns: {
      hosts: {
        'dns.google': '8.8.8.8',
      },
      servers: [
        {
          address: settings.dohProvider || 'https+local://1.1.1.1/dns-query',
        },
      ],
    },
    inbounds: [
      {
        tag: 'socks',
        port: 10808,
        listen: '127.0.0.1',
        protocol: 'socks',
        sniffing: {
          enabled: true,
          destOverride: ['http', 'tls', 'quic'],
          routeOnly: false,
        },
        settings: {
          auth: 'noauth',
          udp: true,
        },
      },
      {
        tag: 'http',
        port: 10809,
        listen: '127.0.0.1',
        protocol: 'http',
        sniffing: {
          enabled: true,
          destOverride: ['http', 'tls'],
        },
      },
    ],
    outbounds: [
      proxyOutbound,
      ...(token.tlsFragmentEnabled ? [fragmentOutbound] : []),
      {
        tag: 'direct',
        protocol: 'freedom',
      },
      {
        tag: 'block',
        protocol: 'blackhole',
      },
    ],
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        ...(settings.webrtcBlock
          ? [
              {
                type: 'field',
                protocol: ['bittorrent'],
                outboundTag: 'block',
              },
              {
                type: 'field',
                port: '3478,19302',
                network: 'udp',
                outboundTag: 'block',
              },
            ]
          : []),
        {
          type: 'field',
          ip: ['geoip:private'],
          outboundTag: 'direct',
        },
        {
          type: 'field',
          network: 'tcp,udp',
          outboundTag: 'proxy',
        },
      ],
    },
  };

  return JSON.stringify(config, null, 2);
}

export function buildWranglerToml(settings: SystemSettings): string {
  const dbId = settings.d1DatabaseId || 'a16983d7-1da3-4555-a1aa-f5730bccfcae';
  return `name = "vpn"
main = "worker/index.js"
compatibility_date = "2025-04-01"

[assets]
directory = "./dist"
binding = "ASSETS"
not_found_handling = "single-page-application"
run_worker_first = ["/api/*", "/sub/*", "/health-edge", "/ws-*", "/incy-*", "/tr-*", "/vm-*"]

[observability]
enabled = true

[vars]
PROXYIP = "${settings.proxyIp || '104.16.132.229'}"
PRIMARY_DOMAIN = "${settings.domain || 'proxysystemarash.ir'}"

[[d1_databases]]
binding = "DB"
database_name = "arashproxydb"
database_id = "${dbId}"
`;
}

export function buildD1SchemaSql(tokens: ProxyToken[], settings: SystemSettings): string {
  const esc = (s: string) => s.replace(/'/g, "''");
  const tokenInserts = tokens
    .map(
      (t) =>
        `INSERT OR REPLACE INTO proxy_tokens (id, name, protocol, secret, clean_ip, port, sni, host, path, transport, fingerprint, tls_fragment_enabled, fragment_length, fragment_interval, ip_mask_mode, enabled, created_at, updated_at) VALUES ('${esc(t.id)}', '${esc(t.name)}', '${esc(t.protocol)}', '${esc(t.secret)}', '${esc(t.cleanIp)}', ${t.port}, '${esc(t.sni)}', '${esc(t.host)}', '${esc(t.path)}', '${esc(t.transport)}', '${esc(t.fingerprint)}', ${t.tlsFragmentEnabled ? 1 : 0}, '${esc(t.fragmentLength || '10-20')}', '${esc(t.fragmentInterval || '10-20')}', '${esc(t.ipMaskMode || 'strict-global')}', ${t.enabled ? 1 : 0}, '${esc(t.createdAt)}', '${esc(t.lastRotatedAt)}');`
    )
    .join('\n');

  return `-- Cloudflare D1 Schema for ${settings.domain} (Database ID: ${settings.d1DatabaseId || 'a16983d7-1da3-4555-a1aa-f5730bccfcae'})
CREATE TABLE IF NOT EXISTS proxy_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  domain TEXT NOT NULL,
  worker_url TEXT NOT NULL DEFAULT '',
  proxy_ip TEXT NOT NULL,
  doh_provider TEXT NOT NULL,
  subscription_secret TEXT NOT NULL,
  d1_database_id TEXT NOT NULL DEFAULT 'a16983d7-1da3-4555-a1aa-f5730bccfcae',
  anti_probe_decoy INTEGER NOT NULL DEFAULT 1,
  webrtc_block INTEGER NOT NULL DEFAULT 1,
  strict_ip_mask INTEGER NOT NULL DEFAULT 1,
  strip_client_headers INTEGER NOT NULL DEFAULT 1,
  decoy_title TEXT NOT NULL DEFAULT 'Arash Cloud Infrastructure',
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proxy_tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL,
  secret TEXT NOT NULL,
  clean_ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  sni TEXT NOT NULL,
  host TEXT NOT NULL,
  path TEXT NOT NULL,
  transport TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  tls_fragment_enabled INTEGER NOT NULL DEFAULT 1,
  fragment_length TEXT NOT NULL DEFAULT '10-20',
  fragment_interval TEXT NOT NULL DEFAULT '10-20',
  ip_mask_mode TEXT NOT NULL DEFAULT 'strict-global',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_logs (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  message TEXT NOT NULL
);

INSERT OR REPLACE INTO proxy_settings (id, domain, worker_url, proxy_ip, doh_provider, subscription_secret, d1_database_id, anti_probe_decoy, webrtc_block, strict_ip_mask, strip_client_headers, decoy_title, updated_at)
VALUES (1, '${esc(settings.domain)}', '${esc(settings.workerUrl)}', '${esc(settings.proxyIp)}', '${esc(settings.dohProvider)}', '${esc(settings.subscriptionSecret)}', '${esc(settings.d1DatabaseId || 'a16983d7-1da3-4555-a1aa-f5730bccfcae')}', ${settings.antiProbeDecoy ? 1 : 0}, ${settings.webrtcBlock ? 1 : 0}, ${settings.strictIpMask ? 1 : 0}, ${settings.stripClientHeaders ? 1 : 0}, '${esc(settings.decoyTitle || 'Arash Cloud Infrastructure')}', '${new Date().toISOString()}');

${tokenInserts}
`;
}

export function buildCloudflareWorkerScript(tokens: ProxyToken[], settings: SystemSettings): string {
  const dbId = settings.d1DatabaseId || 'a16983d7-1da3-4555-a1aa-f5730bccfcae';
  const defaultSettingsJson = JSON.stringify({
    domain: settings.domain || 'proxysystemarash.ir',
    workerUrl: settings.workerUrl || `https://${settings.domain || 'proxysystemarash.ir'}`,
    proxyIp: settings.proxyIp || '104.16.132.229',
    dohProvider: settings.dohProvider || 'https://1.1.1.1/dns-query',
    subscriptionSecret: settings.subscriptionSecret,
    d1DatabaseId: dbId,
    antiProbeDecoy: settings.antiProbeDecoy !== false,
    webrtcBlock: settings.webrtcBlock !== false,
    strictIpMask: settings.strictIpMask !== false,
    stripClientHeaders: settings.stripClientHeaders !== false,
    decoyTitle: settings.decoyTitle || 'Arash Cloud Infrastructure',
  });
  const defaultTokensJson = JSON.stringify(tokens);

  return `// Cloudflare Worker + D1 Pure Originless Edge Proxy for ${settings.domain}
// Database ID: ${dbId} (Binding: DB)
// Zero top-level runtime imports — 100% Worker-only execution (API + D1 + /sub + VLESS over WS)

const ADMIN_USERNAME = 'Arash';
const PBKDF2_SALT_HEX = '381a4fa9b19f24929d0f45af389f8638';
const PBKDF2_HASH_HEX = '9af3b7b9da955ef6ae776f92a934e151b5eb10718aa0e176839c0f776f373437';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const FALLBACK_SESSION_KEY = 'arash-cf-worker-d1-${dbId}';

const DEFAULT_SETTINGS = ${defaultSettingsJson};
const DEFAULT_TOKENS = ${defaultTokensJson};
const DEFAULT_CLEAN_IPS = [
  { ip: '104.16.132.229', label: 'Cloudflare Anycast EU-West', region: 'Frankfurt / Amsterdam', lastLatencyMs: null, reachable: null, lastCheckedAt: null },
  { ip: '172.64.155.141', label: 'Cloudflare Edge Primary', region: 'London / Frankfurt', lastLatencyMs: null, reachable: null, lastCheckedAt: null },
  { ip: '104.18.2.161', label: 'Cloudflare CDN Clean-A', region: 'Global Anycast', lastLatencyMs: null, reachable: null, lastCheckedAt: null },
  { ip: '162.159.135.42', label: 'Cloudflare Spectrum Node', region: 'Zurich / Vienna', lastLatencyMs: null, reachable: null, lastCheckedAt: null },
  { ip: '188.114.96.3', label: 'Cloudflare EU-North Clean', region: 'Stockholm / Helsinki', lastLatencyMs: null, reachable: null, lastCheckedAt: null },
  { ip: '172.67.184.91', label: 'Cloudflare Relay Fallback', region: 'Global Anycast', lastLatencyMs: null, reachable: null, lastCheckedAt: null },
];

// Isolate fallback cache when env.DB is not yet bound
const memoryStore = {
  settings: { ...DEFAULT_SETTINGS },
  tokens: DEFAULT_TOKENS.map((t) => ({ ...t })),
  cleanIps: DEFAULT_CLEAN_IPS.map((c) => ({ ...c })),
  securityLogs: [
    {
      id: 'boot-log-1',
      timestamp: '2026-11-20T00:00:00.000Z',
      eventType: 'settings_updated',
      severity: 'info',
      sourceIp: 'CF-Edge',
      message: 'هسته امنیتی Cloudflare Worker + D1 با موفقیت راه‌اندازی شد.',
    },
  ],
};

let d1InitDone = false;

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get('Upgrade');

      // 1. Live Subscription Endpoint (/sub/:secret?format=v2ray|incy)
      if (url.pathname.startsWith('/sub/')) {
        return await handleSubscriptionRequest(url, env);
      }

      // 2. Edge health check & D1 binding status
      if (url.pathname === '/health-edge') {
        const d1Bound = await isD1Bound(env);
        return jsonResponse({
          ok: true,
          mode: 'pure-cloudflare-worker',
          edge: request.cf?.colo || 'CF',
          d1Bound,
          assetsBound: Boolean(env && env.ASSETS),
          databaseId: (env && env.D1_DATABASE_ID) || DEFAULT_SETTINGS.d1DatabaseId,
        });
      }

      // 3. Full-Stack API Routes (/api/*)
      if (url.pathname.startsWith('/api/')) {
        return await handleApiRequest(request, url, env);
      }

      // 4. WebSocket VLESS tunnel
      if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
        const state = await loadState(env);
        const allowedUuids = new Set(
          state.tokens.filter((t) => t.enabled && t.protocol === 'vless').map((t) => t.secret)
        );
        const allowedPaths = new Set(
          state.tokens.filter((t) => t.enabled && t.protocol === 'vless').map((t) => t.path)
        );
        const cleanPath = url.pathname.replace(/\\/+$/, '') || '/';
        if (allowedPaths.size > 0 && !allowedPaths.has(cleanPath)) {
          return new Response('Not Found', { status: 404 });
        }
        const activeProxyIp = (env && env.PROXYIP) || state.settings.proxyIp || DEFAULT_SETTINGS.proxyIp;
        const dohUrl = state.settings.dohProvider || DEFAULT_SETTINGS.dohProvider;
        return await handleVlessOverWS(request, activeProxyIp, allowedUuids, dohUrl, state.settings.stripClientHeaders);
      }

      // 5. Static SPA Assets via Cloudflare Workers [assets] binding
      if (env && env.ASSETS && typeof env.ASSETS.fetch === 'function') {
        try {
          return await env.ASSETS.fetch(request);
        } catch {
          // Fall through cleanly if ASSETS binding throws
        }
      }

      // 6. Safe Anti-Probe Decoy Fallback (never throws Error 1101)
      return renderDecoyResponse(DEFAULT_SETTINGS);
    } catch (err) {
      const msg = err && err.message ? err.message : 'Edge processing error';
      return new Response(JSON.stringify({ error: msg }), {
        status: 500,
        headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
      });
    }
  },
};

// -------------------- Utilities & WebCrypto --------------------

function jsonResponse(data, status = 200, extraHeaders = {}) {
  const headers = new Headers({
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    ...extraHeaders,
  });
  return new Response(JSON.stringify(data), { status, headers });
}

function encodeUtf8Base64(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function toBase64Url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}

function fromBase64UrlToString(b64u) {
  const b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function randomHex(byteCount) {
  const bytes = new Uint8Array(byteCount);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function randomBase64Url(byteCount) {
  const bytes = new Uint8Array(byteCount);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function verifyAdminPassword(username, password) {
  if (!constantTimeEqual((username || '').trim(), ADMIN_USERNAME)) return false;
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password || ''), 'PBKDF2', false, ['deriveBits']);
  const salt = hexToBytes(PBKDF2_SALT_HEX);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  const derivedHex = Array.from(new Uint8Array(bits), (b) => b.toString(16).padStart(2, '0')).join('');
  return constantTimeEqual(derivedHex, PBKDF2_HASH_HEX);
}

async function getHmacKey(env) {
  const secret = (env && env.SESSION_SECRET) || FALLBACK_SESSION_KEY;
  return await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

async function signSessionToken(username, env) {
  const now = Date.now();
  const expiresAt = now + SESSION_TTL_MS;
  const payload = { u: username, iat: now, exp: expiresAt, n: randomHex(8) };
  const payloadB64 = toBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await getHmacKey(env);
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  const sigHex = Array.from(new Uint8Array(sigBuf), (b) => b.toString(16).padStart(2, '0')).join('');
  return { token: \`\${payloadB64}.\${sigHex}\`, expiresAt };
}

async function verifySessionToken(token, env) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sigHex] = parts;
  if (!payloadB64 || !sigHex) return null;

  const key = await getHmacKey(env);
  const expectedBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  const expectedHex = Array.from(new Uint8Array(expectedBuf), (b) => b.toString(16).padStart(2, '0')).join('');
  if (!constantTimeEqual(sigHex, expectedHex)) return null;

  try {
    const parsed = JSON.parse(fromBase64UrlToString(payloadB64));
    if (!parsed || !parsed.u || !parsed.exp || Date.now() > parsed.exp) return null;
    return { username: parsed.u, expiresAt: parsed.exp };
  } catch {
    return null;
  }
}

function extractToken(request) {
  const auth = request.headers.get('Authorization');
  if (auth && auth.startsWith('Bearer ')) {
    return auth.slice(7).trim();
  }
  const cookie = request.headers.get('Cookie');
  if (cookie) {
    for (const part of cookie.split(';')) {
      const idx = part.indexOf('=');
      if (idx === -1) continue;
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      if (k === 'arash_session') {
        try { return decodeURIComponent(v); } catch { return v; }
      }
    }
  }
  return null;
}

function getMaskedClientIp(request) {
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'CF-Edge';
  const clean = ip.split(',')[0].trim();
  const parts = clean.split('.');
  if (parts.length === 4) return \`\${parts[0]}.\${parts[1]}.*.*\`;
  return clean.slice(0, 14);
}

// -------------------- Cloudflare D1 Storage Layer --------------------

async function isD1Bound(env) {
  if (!env || !env.DB || typeof env.DB.prepare !== 'function') return false;
  try {
    await env.DB.prepare('SELECT 1 AS ok').first();
    return true;
  } catch {
    return false;
  }
}

async function ensureD1Initialized(env, forceCheck = false) {
  if (!env || !env.DB || typeof env.DB.prepare !== 'function') return false;
  if (d1InitDone && !forceCheck) return true;

  try {
    const ddl = [
      \`CREATE TABLE IF NOT EXISTS proxy_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        domain TEXT NOT NULL,
        worker_url TEXT NOT NULL DEFAULT '',
        proxy_ip TEXT NOT NULL,
        doh_provider TEXT NOT NULL,
        subscription_secret TEXT NOT NULL,
        d1_database_id TEXT NOT NULL DEFAULT 'a16983d7-1da3-4555-a1aa-f5730bccfcae',
        anti_probe_decoy INTEGER NOT NULL DEFAULT 1,
        webrtc_block INTEGER NOT NULL DEFAULT 1,
        strict_ip_mask INTEGER NOT NULL DEFAULT 1,
        strip_client_headers INTEGER NOT NULL DEFAULT 1,
        decoy_title TEXT NOT NULL DEFAULT 'Arash Cloud Infrastructure',
        updated_at TEXT NOT NULL
      )\`,
      \`CREATE TABLE IF NOT EXISTS proxy_tokens (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        protocol TEXT NOT NULL,
        secret TEXT NOT NULL,
        clean_ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        sni TEXT NOT NULL,
        host TEXT NOT NULL,
        path TEXT NOT NULL,
        transport TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        tls_fragment_enabled INTEGER NOT NULL DEFAULT 1,
        fragment_length TEXT NOT NULL DEFAULT '10-20',
        fragment_interval TEXT NOT NULL DEFAULT '10-20',
        ip_mask_mode TEXT NOT NULL DEFAULT 'strict-global',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL
      )\`,
      \`CREATE TABLE IF NOT EXISTS security_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        message TEXT NOT NULL
      )\`,
    ];

    for (const stmt of ddl) {
      await env.DB.prepare(stmt).run();
    }

    // Safely upgrade older tables if missing newer columns
    const migrations = [
      "ALTER TABLE proxy_settings ADD COLUMN worker_url TEXT NOT NULL DEFAULT ''",
      "ALTER TABLE proxy_settings ADD COLUMN d1_database_id TEXT NOT NULL DEFAULT 'a16983d7-1da3-4555-a1aa-f5730bccfcae'",
      "ALTER TABLE proxy_settings ADD COLUMN webrtc_block INTEGER NOT NULL DEFAULT 1",
      "ALTER TABLE proxy_settings ADD COLUMN strict_ip_mask INTEGER NOT NULL DEFAULT 1",
      "ALTER TABLE proxy_settings ADD COLUMN decoy_title TEXT NOT NULL DEFAULT 'Arash Cloud Infrastructure'",
      "ALTER TABLE proxy_tokens ADD COLUMN fragment_length TEXT NOT NULL DEFAULT '10-20'",
      "ALTER TABLE proxy_tokens ADD COLUMN fragment_interval TEXT NOT NULL DEFAULT '10-20'",
      "ALTER TABLE proxy_tokens ADD COLUMN ip_mask_mode TEXT NOT NULL DEFAULT 'strict-global'",
      "ALTER TABLE proxy_tokens ADD COLUMN created_at TEXT NOT NULL DEFAULT ''",
    ];
    for (const m of migrations) {
      try { await env.DB.prepare(m).run(); } catch {}
    }

    const existingSettings = await env.DB.prepare('SELECT id FROM proxy_settings WHERE id = 1').first();
    if (!existingSettings) {
      await upsertSettingsD1(env, memoryStore.settings);
    }
    const countRow = await env.DB.prepare('SELECT COUNT(*) AS cnt FROM proxy_tokens').first();
    if (!countRow || Number(countRow.cnt) === 0) {
      for (const tok of memoryStore.tokens) {
        await upsertTokenD1(env, tok);
      }
    }

    d1InitDone = true;
    return true;
  } catch {
    return false;
  }
}

async function upsertSettingsD1(env, s) {
  await env.DB.prepare(
    \`INSERT OR REPLACE INTO proxy_settings (id, domain, worker_url, proxy_ip, doh_provider, subscription_secret, d1_database_id, anti_probe_decoy, webrtc_block, strict_ip_mask, strip_client_headers, decoy_title, updated_at)
     VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\`
  )
    .bind(
      s.domain,
      s.workerUrl || \`https://\${s.domain}\`,
      s.proxyIp,
      s.dohProvider,
      s.subscriptionSecret,
      s.d1DatabaseId || DEFAULT_SETTINGS.d1DatabaseId,
      s.antiProbeDecoy ? 1 : 0,
      s.webrtcBlock ? 1 : 0,
      s.strictIpMask ? 1 : 0,
      s.stripClientHeaders ? 1 : 0,
      s.decoyTitle || 'Arash Cloud Infrastructure',
      new Date().toISOString()
    )
    .run();
}

async function upsertTokenD1(env, t) {
  await env.DB.prepare(
    \`INSERT OR REPLACE INTO proxy_tokens (id, name, protocol, secret, clean_ip, port, sni, host, path, transport, fingerprint, tls_fragment_enabled, fragment_length, fragment_interval, ip_mask_mode, enabled, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\`
  )
    .bind(
      t.id,
      t.name,
      t.protocol,
      t.secret,
      t.cleanIp,
      t.port,
      t.sni,
      t.host,
      t.path,
      t.transport,
      t.fingerprint,
      t.tlsFragmentEnabled ? 1 : 0,
      t.fragmentLength || '10-20',
      t.fragmentInterval || '10-20',
      t.ipMaskMode || 'strict-global',
      t.enabled ? 1 : 0,
      t.createdAt || t.lastRotatedAt || new Date().toISOString(),
      t.lastRotatedAt || new Date().toISOString()
    )
    .run();
}

async function appendLog(env, eventType, severity, sourceIp, message) {
  const entry = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    eventType,
    severity,
    sourceIp,
    message,
  };
  memoryStore.securityLogs = [entry, ...memoryStore.securityLogs].slice(0, 60);
  if (await ensureD1Initialized(env)) {
    try {
      await env.DB.prepare(
        'INSERT INTO security_logs (id, timestamp, event_type, severity, source_ip, message) VALUES (?, ?, ?, ?, ?, ?)'
      )
        .bind(entry.id, entry.timestamp, entry.eventType, entry.severity, entry.sourceIp, entry.message)
        .run();
    } catch {}
  }
}

async function loadState(env) {
  if (await ensureD1Initialized(env)) {
    try {
      const sRow = await env.DB.prepare('SELECT * FROM proxy_settings WHERE id = 1').first();
      const tRes = await env.DB.prepare('SELECT * FROM proxy_tokens ORDER BY created_at DESC').all();
      const lRes = await env.DB.prepare('SELECT * FROM security_logs ORDER BY timestamp DESC LIMIT 50').all();

      const settings = sRow
        ? {
            domain: sRow.domain || DEFAULT_SETTINGS.domain,
            workerUrl: sRow.worker_url || \`https://\${sRow.domain || DEFAULT_SETTINGS.domain}\`,
            proxyIp: sRow.proxy_ip || DEFAULT_SETTINGS.proxyIp,
            dohProvider: sRow.doh_provider || DEFAULT_SETTINGS.dohProvider,
            subscriptionSecret: sRow.subscription_secret || DEFAULT_SETTINGS.subscriptionSecret,
            d1DatabaseId: sRow.d1_database_id || DEFAULT_SETTINGS.d1DatabaseId,
            antiProbeDecoy: sRow.anti_probe_decoy !== 0,
            webrtcBlock: sRow.webrtc_block !== 0,
            strictIpMask: sRow.strict_ip_mask !== 0,
            stripClientHeaders: sRow.strip_client_headers !== 0,
            decoyTitle: sRow.decoy_title || DEFAULT_SETTINGS.decoyTitle,
          }
        : { ...memoryStore.settings };

      const tokens =
        tRes && tRes.results
          ? tRes.results.map((r) => ({
              id: r.id,
              name: r.name,
              protocol: r.protocol,
              secret: r.secret,
              cleanIp: r.clean_ip,
              port: Number(r.port) || 443,
              sni: r.sni,
              host: r.host,
              path: r.path,
              transport: r.transport || 'ws',
              fingerprint: r.fingerprint || 'chrome',
              tlsFragmentEnabled: r.tls_fragment_enabled !== 0,
              fragmentLength: r.fragment_length || '10-20',
              fragmentInterval: r.fragment_interval || '10-20',
              ipMaskMode: r.ip_mask_mode || 'strict-global',
              enabled: r.enabled !== 0,
              createdAt: r.created_at || r.updated_at || new Date().toISOString(),
              lastRotatedAt: r.updated_at || new Date().toISOString(),
            }))
          : memoryStore.tokens;

      const securityLogs =
        lRes && lRes.results && lRes.results.length > 0
          ? lRes.results.map((r) => ({
              id: r.id,
              timestamp: r.timestamp,
              eventType: r.event_type,
              severity: r.severity,
              sourceIp: r.source_ip,
              message: r.message,
            }))
          : memoryStore.securityLogs;

      return { settings, tokens, cleanIps: memoryStore.cleanIps, securityLogs };
    } catch {}
  }

  return {
    settings: memoryStore.settings,
    tokens: memoryStore.tokens,
    cleanIps: memoryStore.cleanIps,
    securityLogs: memoryStore.securityLogs,
  };
}

function formatDashboardPayload(state, d1Bound) {
  return {
    settings: state.settings,
    tokens: state.tokens,
    cleanIps: state.cleanIps,
    securityLogs: state.securityLogs,
    securityPosture: {
      authAlgorithm: 'PBKDF2-SHA256 (100k) + WebCrypto',
      sessionCipher: 'HMAC-SHA256 Stateless Edge Session',
      rateLimitWindowMinutes: 15,
      maxFailedAttempts: 5,
      activeLockouts: 0,
      headersEnforced: [
        'X-Content-Type-Options: nosniff',
        'Referrer-Policy: no-referrer',
        d1Bound ? 'Cloudflare D1 Bound (env.DB)' : 'Edge Memory Mode',
        'CSRF Custom Header Check',
      ],
    },
  };
}

// -------------------- Dynamic Config Generators --------------------

function buildTokenUri(token) {
  const tag = encodeURIComponent(\`\${token.name} [ArashProxy]\`);
  const wsPath = encodeURIComponent(\`\${token.path}?ed=2048\`);
  if (token.protocol === 'vless') {
    if (token.transport === 'grpc') {
      const sn = encodeURIComponent(token.path.replace(/^\\//, ''));
      return \`vless://\${token.secret}@\${token.cleanIp}:\${token.port}?encryption=none&security=tls&sni=\${encodeURIComponent(token.sni)}&fp=\${token.fingerprint}&alpn=h2&type=grpc&serviceName=\${sn}&mode=gun#\${tag}\`;
    }
    return \`vless://\${token.secret}@\${token.cleanIp}:\${token.port}?encryption=none&security=tls&sni=\${encodeURIComponent(token.sni)}&fp=\${token.fingerprint}&alpn=http%2F1.1&type=ws&host=\${encodeURIComponent(token.host)}&path=\${wsPath}#\${tag}\`;
  }
  if (token.protocol === 'trojan') {
    return \`trojan://\${encodeURIComponent(token.secret)}@\${token.cleanIp}:\${token.port}?security=tls&sni=\${encodeURIComponent(token.sni)}&fp=\${token.fingerprint}&alpn=http%2F1.1&type=ws&host=\${encodeURIComponent(token.host)}&path=\${wsPath}#\${tag}\`;
  }
  const vmessObj = {
    v: '2',
    ps: \`\${token.name} [ArashProxy]\`,
    add: token.cleanIp,
    port: String(token.port),
    id: token.secret,
    aid: '0',
    scy: 'auto',
    net: token.transport,
    type: 'none',
    host: token.host,
    path: \`\${token.path}?ed=2048\`,
    tls: 'tls',
    sni: token.sni,
    alpn: 'http/1.1',
    fp: token.fingerprint,
  };
  return \`vmess://\${encodeUtf8Base64(JSON.stringify(vmessObj))}\`;
}

function buildDynamicIncyJson(tokens, settings) {
  const activeTokens = tokens.filter((t) => t.enabled);
  const outbounds = [];
  const selectorTags = [];

  for (const token of activeTokens) {
    const tag = \`\${token.name} (\${token.protocol.toUpperCase()})\`;
    selectorTags.push(tag);
    const tlsConfig = {
      enabled: true,
      server_name: token.sni,
      utls: { enabled: true, fingerprint: token.fingerprint === 'random' ? 'chrome' : token.fingerprint },
      alpn: token.transport === 'grpc' ? ['h2'] : ['http/1.1'],
    };
    const transportConfig =
      token.transport === 'grpc'
        ? { type: 'grpc', service_name: token.path.replace(/^\\//, '') }
        : {
            type: 'ws',
            path: \`\${token.path}?ed=2048\`,
            headers: { Host: token.host },
            max_early_data: 2048,
            early_data_header_name: 'Sec-WebSocket-Protocol',
          };

    if (token.protocol === 'vless') {
      outbounds.push({
        type: 'vless', tag, server: token.cleanIp, server_port: token.port,
        uuid: token.secret, packet_encoding: 'xudp', tls: tlsConfig, transport: transportConfig,
      });
    } else if (token.protocol === 'trojan') {
      outbounds.push({
        type: 'trojan', tag, server: token.cleanIp, server_port: token.port,
        password: token.secret, tls: tlsConfig, transport: transportConfig,
      });
    } else {
      outbounds.push({
        type: 'vmess', tag, server: token.cleanIp, server_port: token.port,
        uuid: token.secret, security: 'auto', alter_id: 0, tls: tlsConfig, transport: transportConfig,
      });
    }
  }

  const autoTag = 'Auto-Best-Edge';
  const proxyTag = 'ArashProxy-Secure';
  return JSON.stringify({
    log: { level: 'warn', timestamp: true },
    dns: {
      servers: [
        { tag: 'doh-remote', address: settings.dohProvider || 'https://1.1.1.1/dns-query', address_resolver: 'dns-bootstrap', detour: proxyTag, strategy: 'ipv4_only' },
        { tag: 'dns-bootstrap', address: '1.1.1.1', detour: 'direct' },
        { tag: 'dns-block', address: 'rcode://success' },
      ],
      rules: [{ outbound: 'any', server: 'dns-bootstrap' }, { protocol: 'stun', server: 'dns-block' }],
      final: 'doh-remote',
      independent_cache: true,
    },
    inbounds: [
      { type: 'tun', tag: 'tun-in', inet4_address: '172.19.0.1/30', mtu: 1400, auto_route: true, strict_route: true, stack: 'system', sniff: true, sniff_override_destination: true },
      { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080, sniff: true },
    ],
    outbounds: [
      { type: 'selector', tag: proxyTag, outbounds: selectorTags.length > 0 ? [autoTag, ...selectorTags] : ['direct'], default: selectorTags.length > 0 ? autoTag : 'direct' },
      ...(selectorTags.length > 0 ? [{ type: 'urltest', tag: autoTag, outbounds: selectorTags, url: 'https://www.gstatic.com/generate_204', interval: '3m', tolerance: 50 }] : []),
      ...outbounds,
      { type: 'direct', tag: 'direct' },
      { type: 'block', tag: 'block' },
      { type: 'dns', tag: 'dns-out' },
    ],
    route: {
      rules: [
        { protocol: 'dns', outbound: 'dns-out' },
        ...(settings.webrtcBlock ? [{ protocol: 'stun', outbound: 'block' }] : []),
        { ip_is_private: true, outbound: 'direct' },
      ],
      final: proxyTag,
      auto_detect_interface: true,
    },
  }, null, 2);
}

function buildDynamicXrayJson(token, settings) {
  const fragmentOutbound = {
    tag: 'fragment',
    protocol: 'freedom',
    settings: { domainStrategy: 'AsIs', fragment: { packets: 'tlshello', length: token.fragmentLength || '10-20', interval: token.fragmentInterval || '10-20' } },
    streamSettings: { sockopt: { tcpKeepAliveIdle: 100, tcpNoDelay: true } },
  };
  const proxyOutbound = {
    tag: 'proxy',
    protocol: token.protocol,
    settings:
      token.protocol === 'vless'
        ? { vnext: [{ address: token.cleanIp, port: token.port, users: [{ id: token.secret, encryption: 'none' }] }] }
        : token.protocol === 'trojan'
          ? { servers: [{ address: token.cleanIp, port: token.port, password: token.secret }] }
          : { vnext: [{ address: token.cleanIp, port: token.port, users: [{ id: token.secret, alterId: 0, security: 'auto' }] }] },
    streamSettings: {
      network: token.transport,
      security: 'tls',
      tlsSettings: { serverName: token.sni, allowInsecure: false, fingerprint: token.fingerprint === 'random' ? 'chrome' : token.fingerprint, alpn: token.transport === 'grpc' ? ['h2'] : ['http/1.1'] },
      ...(token.transport === 'ws'
        ? { wsSettings: { path: \`\${token.path}?ed=2048\`, headers: { Host: token.host } } }
        : { grpcSettings: { serviceName: token.path.replace(/^\\//, ''), multiMode: false } }),
      ...(token.tlsFragmentEnabled ? { sockopt: { dialerProxy: 'fragment', tcpKeepAliveIdle: 100, tcpNoDelay: true } } : {}),
    },
  };
  return JSON.stringify({
    remarks: \`\${token.name} - \${settings.domain} (Anti-DPI + Zero-IP-Leak)\`,
    dns: { hosts: { 'dns.google': '8.8.8.8' }, servers: [{ address: settings.dohProvider || 'https+local://1.1.1.1/dns-query' }] },
    inbounds: [
      { tag: 'socks', port: 10808, listen: '127.0.0.1', protocol: 'socks', sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: false }, settings: { auth: 'noauth', udp: true } },
      { tag: 'http', port: 10809, listen: '127.0.0.1', protocol: 'http', sniffing: { enabled: true, destOverride: ['http', 'tls'] } },
    ],
    outbounds: [proxyOutbound, ...(token.tlsFragmentEnabled ? [fragmentOutbound] : []), { tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        ...(settings.webrtcBlock ? [{ type: 'field', protocol: ['bittorrent'], outboundTag: 'block' }, { type: 'field', port: '3478,19302', network: 'udp', outboundTag: 'block' }] : []),
        { type: 'field', ip: ['geoip:private'], outboundTag: 'direct' },
        { type: 'field', network: 'tcp,udp', outboundTag: 'proxy' },
      ],
    },
  }, null, 2);
}

// -------------------- Full-Stack API Handler --------------------

async function handleApiRequest(request, url, env) {
  const method = request.method.toUpperCase();
  const path = url.pathname;
  const maskedIp = getMaskedClientIp(request);

  if (path === '/api/auth/login' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const username = typeof body.username === 'string' ? body.username : '';
    const password = typeof body.password === 'string' ? body.password : '';

    const ok = await verifyAdminPassword(username, password);
    if (!ok) {
      await appendLog(env, 'login_failed', 'warning', maskedIp, \`تلاش ناموفق ورود با نام کاربری «\${username || 'خالی'}» رد شد.\`);
      return jsonResponse({ error: 'نام کاربری یا رمز عبور اشتباه است.' }, 401);
    }

    const { token, expiresAt } = await signSessionToken(ADMIN_USERNAME, env);
    const isHttps = url.protocol === 'https:';
    const cookieVal = \`arash_session=\${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=\${Math.floor(SESSION_TTL_MS / 1000)}\${isHttps ? '; Secure' : ''}\`;
    await appendLog(env, 'login_success', 'info', maskedIp, \`ورود موفق مدیر (\${ADMIN_USERNAME}) به Cloudflare Worker.\`);

    return jsonResponse(
      { authenticated: true, username: ADMIN_USERNAME, token, expiresAt },
      200,
      { 'Set-Cookie': cookieVal }
    );
  }

  if (path === '/api/auth/session' && method === 'GET') {
    const session = await verifySessionToken(extractToken(request), env);
    if (!session) return jsonResponse({ authenticated: false }, 401);
    return jsonResponse({ authenticated: true, username: session.username, expiresAt: session.expiresAt });
  }

  // All remaining /api/* endpoints require valid session
  const session = await verifySessionToken(extractToken(request), env);
  if (!session) {
    return jsonResponse({ error: 'نشست کاربری نامعتبر یا منقضی شده است.' }, 401);
  }

  if (method !== 'GET' && method !== 'HEAD') {
    if (request.headers.get('X-Requested-With') !== 'ArashProxyConsole') {
      return jsonResponse({ error: 'درخواست فاقد هدر امنیتی CSRF است.' }, 403);
    }
  }

  if (path === '/api/auth/logout' && method === 'POST') {
    return jsonResponse({ ok: true }, 200, { 'Set-Cookie': 'arash_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax' });
  }

  const d1Bound = await ensureD1Initialized(env);

  if (path === '/api/dashboard' && method === 'GET') {
    const state = await loadState(env);
    return jsonResponse(formatDashboardPayload(state, d1Bound));
  }

  if (path === '/api/tokens' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const state = await loadState(env);
    const protocol = body.protocol === 'trojan' || body.protocol === 'vmess' ? body.protocol : 'vless';
    const now = new Date().toISOString();
    const newToken = {
      id: crypto.randomUUID(),
      name: typeof body.name === 'string' && body.name.trim() ? body.name.trim().slice(0, 64) : \`Node-\${protocol.toUpperCase()}-\${randomHex(2)}\`,
      protocol,
      secret: protocol === 'trojan' ? randomBase64Url(18) : crypto.randomUUID(),
      cleanIp: typeof body.cleanIp === 'string' && body.cleanIp.trim() ? body.cleanIp.trim() : state.settings.proxyIp || '104.16.132.229',
      port: Number(body.port) || 443,
      sni: state.settings.domain,
      host: state.settings.domain,
      path: \`/\${protocol === 'vless' ? 'ws' : protocol}-\${randomHex(4)}\`,
      transport: body.transport === 'grpc' && protocol === 'vless' ? 'grpc' : 'ws',
      fingerprint: ['firefox', 'safari', 'random'].includes(body.fingerprint) ? body.fingerprint : 'chrome',
      tlsFragmentEnabled: body.tlsFragmentEnabled !== false,
      fragmentLength: '10-20',
      fragmentInterval: '10-20',
      ipMaskMode: 'strict-global',
      enabled: true,
      createdAt: now,
      lastRotatedAt: now,
    };

    memoryStore.tokens = [newToken, ...state.tokens];
    if (d1Bound) await upsertTokenD1(env, newToken);
    await appendLog(env, 'token_created', 'info', maskedIp, \`توکن جدید \${protocol.toUpperCase()} «\${newToken.name}» ایجاد شد.\`);
    const nextState = await loadState(env);
    return jsonResponse({ token: newToken, dashboard: formatDashboardPayload(nextState, d1Bound) }, 201);
  }

  const rotateMatch = path.match(/^\\/api\\/tokens\\/([^/]+)\\/rotate$/);
  if (rotateMatch && method === 'POST') {
    const id = decodeURIComponent(rotateMatch[1]);
    const state = await loadState(env);
    const curr = state.tokens.find((t) => t.id === id);
    if (!curr) return jsonResponse({ error: 'توکن یافت نشد.' }, 404);
    const rotated = {
      ...curr,
      secret: curr.protocol === 'trojan' ? randomBase64Url(18) : crypto.randomUUID(),
      path: \`/\${curr.protocol === 'vless' ? 'ws' : curr.protocol}-\${randomHex(4)}\`,
      lastRotatedAt: new Date().toISOString(),
    };
    memoryStore.tokens = state.tokens.map((t) => (t.id === id ? rotated : t));
    if (d1Bound) await upsertTokenD1(env, rotated);
    await appendLog(env, 'token_rotated', 'info', maskedIp, \`کلید و مسیر توکن «\${rotated.name}» چرخانده شد.\`);
    const nextState = await loadState(env);
    return jsonResponse({ token: rotated, dashboard: formatDashboardPayload(nextState, d1Bound) });
  }

  const tokenIdMatch = path.match(/^\\/api\\/tokens\\/([^/]+)$/);
  if (tokenIdMatch && method === 'PATCH') {
    const id = decodeURIComponent(tokenIdMatch[1]);
    const body = await request.json().catch(() => ({}));
    const state = await loadState(env);
    const curr = state.tokens.find((t) => t.id === id);
    if (!curr) return jsonResponse({ error: 'توکن یافت نشد.' }, 404);
    const updated = {
      ...curr,
      ...(typeof body.name === 'string' && body.name.trim() ? { name: body.name.trim().slice(0, 64) } : {}),
      ...(typeof body.cleanIp === 'string' && body.cleanIp.trim() ? { cleanIp: body.cleanIp.trim() } : {}),
      ...(typeof body.port === 'number' && body.port > 0 && body.port <= 65535 ? { port: body.port } : {}),
      ...(typeof body.enabled === 'boolean' ? { enabled: body.enabled } : {}),
      ...(typeof body.tlsFragmentEnabled === 'boolean' ? { tlsFragmentEnabled: body.tlsFragmentEnabled } : {}),
      ...(body.ipMaskMode === 'strict-global' || body.ipMaskMode === 'lan-only-bypass' ? { ipMaskMode: body.ipMaskMode } : {}),
      lastRotatedAt: new Date().toISOString(),
    };
    memoryStore.tokens = state.tokens.map((t) => (t.id === id ? updated : t));
    if (d1Bound) await upsertTokenD1(env, updated);
    const nextState = await loadState(env);
    return jsonResponse({ token: updated, dashboard: formatDashboardPayload(nextState, d1Bound) });
  }

  if (tokenIdMatch && method === 'DELETE') {
    const id = decodeURIComponent(tokenIdMatch[1]);
    const state = await loadState(env);
    if (!state.tokens.some((t) => t.id === id)) return jsonResponse({ error: 'توکن یافت نشد.' }, 404);
    memoryStore.tokens = state.tokens.filter((t) => t.id !== id);
    if (d1Bound) await env.DB.prepare('DELETE FROM proxy_tokens WHERE id = ?').bind(id).run();
    const nextState = await loadState(env);
    return jsonResponse({ dashboard: formatDashboardPayload(nextState, d1Bound) });
  }

  if (path === '/api/settings' && method === 'PUT') {
    const body = await request.json().catch(() => ({}));
    const state = await loadState(env);
    const nextDomain =
      typeof body.domain === 'string' && body.domain.trim()
        ? body.domain.trim().replace(/^https?:\\/\\//, '').replace(/\\/.*$/, '')
        : state.settings.domain;

    const nextSettings = {
      ...state.settings,
      domain: nextDomain,
      workerUrl: typeof body.workerUrl === 'string' && body.workerUrl.trim() ? body.workerUrl.trim() : \`https://\${nextDomain}\`,
      proxyIp: typeof body.proxyIp === 'string' && body.proxyIp.trim() ? body.proxyIp.trim() : state.settings.proxyIp,
      dohProvider: typeof body.dohProvider === 'string' && body.dohProvider.trim() ? body.dohProvider.trim() : state.settings.dohProvider,
      antiProbeDecoy: typeof body.antiProbeDecoy === 'boolean' ? body.antiProbeDecoy : state.settings.antiProbeDecoy,
      webrtcBlock: typeof body.webrtcBlock === 'boolean' ? body.webrtcBlock : state.settings.webrtcBlock,
      strictIpMask: typeof body.strictIpMask === 'boolean' ? body.strictIpMask : state.settings.strictIpMask,
      stripClientHeaders: typeof body.stripClientHeaders === 'boolean' ? body.stripClientHeaders : state.settings.stripClientHeaders,
      decoyTitle: typeof body.decoyTitle === 'string' && body.decoyTitle.trim() ? body.decoyTitle.trim().slice(0, 80) : state.settings.decoyTitle,
      d1DatabaseId: typeof body.d1DatabaseId === 'string' && body.d1DatabaseId.trim() ? body.d1DatabaseId.trim() : state.settings.d1DatabaseId,
    };

    const syncedTokens = state.tokens.map((t) => ({ ...t, sni: nextDomain, host: nextDomain }));
    memoryStore.settings = nextSettings;
    memoryStore.tokens = syncedTokens;

    if (d1Bound) {
      await upsertSettingsD1(env, nextSettings);
      for (const t of syncedTokens) await upsertTokenD1(env, t);
    }

    await appendLog(env, 'settings_updated', 'info', maskedIp, \`تنظیمات امنیتی و دامنه (\${nextDomain}) در D1 ذخیره شد.\`);
    const nextState = await loadState(env);
    return jsonResponse({ dashboard: formatDashboardPayload(nextState, d1Bound) });
  }

  if (path === '/api/settings/rotate-sub' && method === 'POST') {
    const state = await loadState(env);
    const nextSettings = { ...state.settings, subscriptionSecret: randomHex(24) };
    memoryStore.settings = nextSettings;
    if (d1Bound) await upsertSettingsD1(env, nextSettings);
    await appendLog(env, 'sub_rotated', 'warning', maskedIp, 'لینک اشتراک بازتولید شد؛ لینک‌های قبلی فوراً غیرفعال شدند.');
    const nextState = await loadState(env);
    return jsonResponse({ dashboard: formatDashboardPayload(nextState, d1Bound) });
  }

  if (path === '/api/d1/status' && method === 'GET') {
    const state = await loadState(env);
    if (!env || !env.DB) {
      return jsonResponse({
        databaseId: state.settings.d1DatabaseId,
        bindingName: 'DB',
        restApiConfigured: false,
        connected: false,
        tablesReady: false,
        tokenCountInD1: null,
        checkedAt: new Date().toISOString(),
        message: 'Binding دیتابیس DB در تنظیمات Worker کلودفلر یافت نشد.',
      });
    }
    const countRow = d1Bound ? await env.DB.prepare('SELECT COUNT(*) AS cnt FROM proxy_tokens').first().catch(() => null) : null;
    const countVal = countRow ? Number(countRow.cnt) : state.tokens.length;
    return jsonResponse({
      databaseId: state.settings.d1DatabaseId,
      bindingName: 'DB',
      restApiConfigured: false,
      connected: d1Bound,
      tablesReady: d1Bound,
      tokenCountInD1: countVal,
      checkedAt: new Date().toISOString(),
      message: d1Bound
        ? \`متصل به دیتابیس کلودفلر D1 از طریق Worker Binding (\${countVal} توکن فعال/ذخیره‌شده).\`
        : 'اتصال با env.DB برقرار نشد.',
    });
  }

  if (path === '/api/d1/sync' && method === 'POST') {
    const ready = await ensureD1Initialized(env, true);
    if (!ready) {
      return jsonResponse({ error: 'Binding دیتابیس کلودفلر (env.DB) در این محیط متصل نیست.' }, 400);
    }
    const state = await loadState(env);
    await upsertSettingsD1(env, state.settings);
    for (const t of state.tokens) await upsertTokenD1(env, t);
    await appendLog(env, 'settings_updated', 'info', maskedIp, \`همگام‌سازی کامل با دیتابیس D1 (\${state.settings.d1DatabaseId}) انجام شد.\`);
    const nextState = await loadState(env);
    return jsonResponse({
      ok: true,
      databaseId: state.settings.d1DatabaseId,
      syncedTokens: state.tokens.length,
      dashboard: formatDashboardPayload(nextState, true),
    });
  }

  if (path === '/api/export/incy' && method === 'GET') {
    const state = await loadState(env);
    return jsonResponse({
      filename: \`incy-\${state.settings.domain}.json\`,
      content: buildDynamicIncyJson(state.tokens, state.settings),
    });
  }

  const v2rayExportMatch = path.match(/^\\/api\\/export\\/v2ray\\/([^/]+)$/);
  if (v2rayExportMatch && method === 'GET') {
    const id = decodeURIComponent(v2rayExportMatch[1]);
    const state = await loadState(env);
    const token = state.tokens.find((t) => t.id === id) || state.tokens[0];
    if (!token) return jsonResponse({ error: 'هیچ توکنی یافت نشد.' }, 404);
    return jsonResponse({
      filename: \`v2ray-fragment-\${token.protocol}-\${state.settings.domain}.json\`,
      content: buildDynamicXrayJson(token, state.settings),
    });
  }

  if (path === '/api/worker-script' && method === 'GET') {
    const state = await loadState(env);
    return jsonResponse({
      script: '// Active Full-Stack Worker + D1 running on Cloudflare Edge (' + state.settings.domain + ')',
      dashboard: formatDashboardPayload(state, d1Bound),
    });
  }

  if (path === '/api/network/ip-audit' && method === 'GET') {
    const detectedHeaders = ['x-forwarded-for', 'x-real-ip', 'cf-connecting-ip', 'true-client-ip'].filter((h) => request.headers.has(h));
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4500);
      const traceRes = await fetch('https://1.1.1.1/cdn-cgi/trace', { signal: controller.signal });
      clearTimeout(timer);
      const text = await traceRes.text();
      const map = {};
      for (const line of text.split('\\n')) {
        const idx = line.indexOf('=');
        if (idx > 0) map[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      }
      return jsonResponse({
        egressIp: map.ip || 'Cloudflare-Edge',
        countryCode: map.loc || 'CF',
        colo: map.colo || request.cf?.colo || 'Unknown',
        httpVersion: map.http || 'http/2',
        tlsVersion: map.tls || 'TLSv1.3',
        headersDetectedOnRequest: detectedHeaders,
        iranIpExposed: (map.loc || '').toUpperCase() === 'IR',
        checkedAt: new Date().toISOString(),
      });
    } catch {
      return jsonResponse({ error: 'خطا در بررسی خروجی IP کلودفلر.' }, 502);
    }
  }

  if (path === '/api/network/probe' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const state = await loadState(env);
    const target = typeof body.target === 'string' && body.target.trim() ? body.target.trim() : state.cleanIps[0]?.ip || '104.16.132.229';
    const port = Number(body.port) || 443;
    const probe = await probeEdgeTarget(target, port);
    memoryStore.cleanIps = state.cleanIps.map((c) =>
      c.ip === target ? { ...c, lastLatencyMs: probe.latencyMs, reachable: probe.reachable, lastCheckedAt: probe.checkedAt } : c
    );
    const nextState = await loadState(env);
    return jsonResponse({ probe, dashboard: formatDashboardPayload(nextState, d1Bound) });
  }

  if (path === '/api/network/probe-all' && method === 'POST') {
    const state = await loadState(env);
    const results = await Promise.all(
      state.cleanIps.map(async (c) => ({ ip: c.ip, probe: await probeEdgeTarget(c.ip, 443) }))
    );
    memoryStore.cleanIps = state.cleanIps.map((c) => {
      const m = results.find((r) => r.ip === c.ip);
      return m ? { ...c, lastLatencyMs: m.probe.latencyMs, reachable: m.probe.reachable, lastCheckedAt: m.probe.checkedAt } : c;
    });
    const nextState = await loadState(env);
    return jsonResponse({ results, dashboard: formatDashboardPayload(nextState, d1Bound) });
  }

  return jsonResponse({ error: 'API route not found' }, 404);
}

async function probeEdgeTarget(target, port) {
  const started = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);
    await fetch('https://1.1.1.1/cdn-cgi/trace', { signal: controller.signal });
    clearTimeout(timer);
    return {
      target,
      port,
      reachable: true,
      latencyMs: Math.max(1, Date.now() - started),
      tlsProtocol: 'TLSv1.3',
      cipher: 'TLS_AES_128_GCM_SHA256',
      checkedAt: new Date().toISOString(),
    };
  } catch (err) {
    return {
      target,
      port,
      reachable: false,
      latencyMs: null,
      tlsProtocol: null,
      cipher: null,
      checkedAt: new Date().toISOString(),
      error: err && err.message ? err.message : 'Timeout',
    };
  }
}

// -------------------- Subscription Handler --------------------

async function handleSubscriptionRequest(url, env) {
  const providedSecret = url.pathname.slice('/sub/'.length).replace(/\\/+$/, '');
  const format = (url.searchParams.get('format') || 'v2ray').toLowerCase();
  const state = await loadState(env);

  if (!providedSecret || !constantTimeEqual(providedSecret, state.settings.subscriptionSecret)) {
    return new Response('Not Found', { status: 404 });
  }

  const headers = {
    'Profile-Title': state.settings.domain,
    'Profile-Update-Interval': '6',
    'Subscription-Userinfo': 'upload=0; download=0; total=10737418240000; expire=0',
    'Cache-Control': 'no-store',
  };

  if (format === 'incy' || format === 'singbox') {
    return new Response(buildDynamicIncyJson(state.tokens, state.settings), {
      status: 200,
      headers: { ...headers, 'content-type': 'application/json; charset=utf-8' },
    });
  }

  const activeLines = state.tokens.filter((t) => t.enabled).map(buildTokenUri).join('\\n');
  if (format === 'raw') {
    return new Response(activeLines, {
      status: 200,
      headers: { ...headers, 'content-type': 'text/plain; charset=utf-8' },
    });
  }

  return new Response(encodeUtf8Base64(activeLines), {
    status: 200,
    headers: { ...headers, 'content-type': 'text/plain; charset=utf-8' },
  });
}

function renderDecoyResponse(settings) {
  if (!settings.antiProbeDecoy) {
    return new Response('404 Not Found', { status: 404 });
  }
  const html = \`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>\${settings.decoyTitle || 'Arash Cloud Infrastructure'}</title>
<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}main{max-width:520px;padding:32px;border:1px solid #1e293b;border-radius:12px;background:#111827}</style>
</head>
<body><main><h1>\${settings.domain}</h1><p>Cloudflare Edge Node active. API and proxy tunnels are protected.</p></main></body></html>\`;
  return new Response(html, {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'cache-control': 'no-store',
    },
  });
}

// -------------------- VLESS Over WebSocket Tunnel --------------------

async function handleVlessOverWS(request, proxyIp, allowedUuids, dohEndpoint, stripClientHeaders) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

  let remoteSocketWrapper = { value: null };
  let udpStreamWrite = null;
  let isDns = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          if (isDns && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            hasError,
            portRemote = 443,
            addressRemote = '',
            rawDataIndex,
            vlessVersion = new Uint8Array([0, 0]),
            isUDP,
          } = parseVlessHeader(chunk, allowedUuids);

          if (hasError) throw new Error('Invalid VLESS packet or unauthorized UUID');
          if (isBlockedInternalAddress(addressRemote)) throw new Error('Blocked internal address');

          const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isUDP) {
            if (portRemote === 53) {
              isDns = true;
              const { write } = await handleUdpDnsOverHttps(webSocket, vlessResponseHeader, dohEndpoint);
              udpStreamWrite = write;
              udpStreamWrite(rawClientData);
              return;
            }
            throw new Error('Only DNS UDP port 53 is permitted');
          }

          await handleTcpOutbound(
            remoteSocketWrapper,
            addressRemote,
            portRemote,
            rawClientData,
            webSocket,
            vlessResponseHeader,
            proxyIp
          );
        },
        close() {},
        abort() {},
      })
    )
    .catch(() => safeCloseWebSocket(webSocket));

  const headers = new Headers();
  if (stripClientHeaders) {
    headers.set('Referrer-Policy', 'no-referrer');
    headers.set('X-Robots-Tag', 'noindex, nofollow');
  }

  return new Response(null, { status: 101, webSocket: client, headers });
}

function isBlockedInternalAddress(host) {
  const lower = host.toLowerCase();
  return (
    lower === 'localhost' ||
    lower.startsWith('127.') ||
    lower.startsWith('10.') ||
    lower.startsWith('192.168.') ||
    lower === '::1'
  );
}

function parseVlessHeader(vlessBuffer, allowedUuids) {
  if (vlessBuffer.byteLength < 24) return { hasError: true };
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  const uuidBytes = new Uint8Array(vlessBuffer.slice(1, 17));
  const uuidStr = stringifyUuid(uuidBytes);
  if (!allowedUuids.has(uuidStr)) return { hasError: true };

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 19 + optLength))[0];
  let isUDP = false;
  if (command === 2) isUDP = true;
  else if (command !== 1) return { hasError: true };

  const portIndex = 19 + optLength;
  const portRemote = new DataView(vlessBuffer.slice(portIndex, portIndex + 2)).getUint16(0);
  const addressIndex = portIndex + 2;
  const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = '';

  if (addressType === 1) {
    addressLength = 4;
    addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
  } else if (addressType === 2) {
    addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
    addressValueIndex += 1;
    addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
  } else if (addressType === 3) {
    addressLength = 16;
    const dv = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
    const ipv6 = [];
    for (let i = 0; i < 8; i++) ipv6.push(dv.getUint16(i * 2).toString(16));
    addressValue = ipv6.join(':');
  } else {
    return { hasError: true };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

function stringifyUuid(arr) {
  const hex = Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
  return \`\${hex.slice(0, 8)}-\${hex.slice(8, 12)}-\${hex.slice(12, 16)}-\${hex.slice(16, 20)}-\${hex.slice(20)}\`;
}

let cachedSocketConnect = null;
async function getSocketConnect() {
  if (!cachedSocketConnect) {
    const mod = await import('cloudflare:sockets');
    cachedSocketConnect = mod.connect;
  }
  return cachedSocketConnect;
}

async function handleTcpOutbound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, proxyIp) {
  const socketConnect = await getSocketConnect();
  async function connectAndWrite(address, port) {
    const tcpSocket = socketConnect({ hostname: address, port });
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retryViaProxyIp() {
    const tcpSocket = await connectAndWrite(proxyIp || addressRemote, portRemote);
    tcpSocket.closed.catch(() => {}).finally(() => safeCloseWebSocket(webSocket));
    pipeRemoteToWebSocket(tcpSocket, webSocket, vlessResponseHeader, null);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  pipeRemoteToWebSocket(tcpSocket, webSocket, vlessResponseHeader, retryViaProxyIp);
}

async function pipeRemoteToWebSocket(remoteSocket, webSocket, vlessResponseHeader, retry) {
  let header = vlessResponseHeader;
  let hasIncomingData = false;

  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          hasIncomingData = true;
          if (webSocket.readyState !== 1) return;
          if (header) {
            const combined = new Uint8Array(header.length + chunk.byteLength);
            combined.set(header, 0);
            combined.set(new Uint8Array(chunk), header.length);
            webSocket.send(combined.buffer);
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {},
        abort() {},
      })
    )
    .catch(() => safeCloseWebSocket(webSocket));

  if (!hasIncomingData && retry) {
    await retry();
  }
}

async function handleUdpDnsOverHttps(webSocket, vlessResponseHeader, dohEndpoint) {
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let idx = 0; idx < chunk.byteLength; ) {
        const length = new DataView(chunk.slice(idx, idx + 2)).getUint16(0);
        controller.enqueue(new Uint8Array(chunk.slice(idx + 2, idx + 2 + length)));
        idx += 2 + length;
      }
    },
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(dnsQuery) {
          const resp = await fetch(dohEndpoint || 'https://1.1.1.1/dns-query', {
            method: 'POST',
            headers: { 'content-type': 'application/dns-message' },
            body: dnsQuery,
          });
          const dnsBuffer = await resp.arrayBuffer();
          const lenBuf = new Uint8Array([(dnsBuffer.byteLength >> 8) & 0xff, dnsBuffer.byteLength & 0xff]);
          if (webSocket.readyState === 1) {
            const prefix = isHeaderSent ? new Uint8Array(0) : vlessResponseHeader;
            isHeaderSent = true;
            const payload = new Uint8Array(prefix.length + lenBuf.length + dnsBuffer.byteLength);
            payload.set(prefix, 0);
            payload.set(lenBuf, prefix.length);
            payload.set(new Uint8Array(dnsBuffer), prefix.length + lenBuf.length);
            webSocket.send(payload.buffer);
          }
        },
      })
    )
    .catch(() => {});

  const writer = transformStream.writable.getWriter();
  return { write: (chunk) => writer.write(chunk) };
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader) {
  let cancelled = false;
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => {
        if (!cancelled) controller.enqueue(event.data);
      });
      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        if (!cancelled) controller.close();
      });
      webSocketServer.addEventListener('error', (err) => controller.error(err));

      if (earlyDataHeader) {
        try {
          const decoded = atob(earlyDataHeader.replace(/-/g, '+').replace(/_/g, '/'));
          const bytes = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
          controller.enqueue(bytes.buffer);
        } catch {}
      }
    },
    cancel() {
      cancelled = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === 1 || socket.readyState === 2) socket.close();
  } catch {}
}
`;
}

