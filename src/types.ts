export type ProxyProtocol = 'vless' | 'trojan' | 'vmess';
export type TransportType = 'ws' | 'grpc';
export type IpMaskMode = 'strict-global' | 'lan-only-bypass';

export interface ProxyToken {
  id: string;
  name: string;
  protocol: ProxyProtocol;
  secret: string; // UUID for VLESS/VMess, high-entropy password for Trojan
  cleanIp: string;
  port: number;
  sni: string;
  host: string;
  path: string;
  transport: TransportType;
  fingerprint: 'chrome' | 'firefox' | 'safari' | 'random';
  tlsFragmentEnabled: boolean;
  fragmentLength: string;
  fragmentInterval: string;
  ipMaskMode: IpMaskMode;
  enabled: boolean;
  createdAt: string;
  lastRotatedAt: string;
}

export interface CleanIpEntry {
  ip: string;
  label: string;
  region: string;
  lastLatencyMs: number | null;
  reachable: boolean | null;
  lastCheckedAt: string | null;
}

export interface SecurityLogEntry {
  id: string;
  timestamp: string;
  eventType:
    | 'login_success'
    | 'login_failed'
    | 'bruteforce_lockout'
    | 'token_created'
    | 'token_rotated'
    | 'sub_rotated'
    | 'settings_updated'
    | 'worker_exported'
    | 'ip_probe';
  severity: 'info' | 'warning' | 'critical';
  sourceIp: string;
  message: string;
}

export interface SystemSettings {
  domain: string;
  workerUrl: string;
  proxyIp: string;
  dohProvider: string;
  subscriptionSecret: string;
  d1DatabaseId: string;
  antiProbeDecoy: boolean;
  webrtcBlock: boolean;
  strictIpMask: boolean;
  stripClientHeaders: boolean;
  decoyTitle: string;
}

export interface D1StatusResult {
  databaseId: string;
  bindingName: string;
  restApiConfigured: boolean;
  connected: boolean;
  tablesReady: boolean;
  tokenCountInD1: number | null;
  checkedAt: string;
  message: string;
}

export interface DashboardState {
  settings: SystemSettings;
  tokens: ProxyToken[];
  cleanIps: CleanIpEntry[];
  securityLogs: SecurityLogEntry[];
  securityPosture: {
    authAlgorithm: string;
    sessionCipher: string;
    rateLimitWindowMinutes: number;
    maxFailedAttempts: number;
    activeLockouts: number;
    headersEnforced: string[];
  };
}

export interface ProbeResult {
  target: string;
  port: number;
  reachable: boolean;
  latencyMs: number | null;
  tlsProtocol: string | null;
  cipher: string | null;
  checkedAt: string;
  error?: string;
}

export interface IpAuditResult {
  egressIp: string;
  countryCode: string;
  colo: string;
  httpVersion: string;
  tlsVersion: string;
  headersDetectedOnRequest: string[];
  iranIpExposed: boolean;
  checkedAt: string;
}
