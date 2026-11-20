import { useMemo, useState, type FormEvent } from 'react';
import {
  Check,
  Copy,
  Download,
  Plus,
  QrCode,
  RefreshCw,
  Shield,
  Trash2,
} from 'lucide-react';
import {
  createProxyToken,
  deleteProxyToken,
  fetchV2RayExport,
  rotateProxyToken,
  rotateSubscriptionSecret,
  updateProxyToken,
} from '../lib/api.ts';
import {
  buildIncySingBoxConfig,
  buildProxyUri,
  buildRawUriList,
} from '../lib/proxyGenerators.ts';
import type {
  DashboardState,
  ProxyProtocol,
  ProxyToken,
  TransportType,
} from '../types.ts';
import { QrModal } from './QrModal.tsx';

interface TokensPanelProps {
  dashboard: DashboardState;
  onUpdate: (next: DashboardState) => void;
}

const CF_PORTS = [443, 2053, 2083, 2087, 2096, 8443];

export function TokensPanel({ dashboard, onUpdate }: TokensPanelProps) {
  const [filterProtocol, setFilterProtocol] = useState<'all' | ProxyProtocol>('all');
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState('');
  const [newProtocol, setNewProtocol] = useState<ProxyProtocol>('vless');
  const [newTransport, setNewTransport] = useState<TransportType>('ws');
  const [newCleanIp, setNewCleanIp] = useState(dashboard.cleanIps[0]?.ip || '104.16.132.229');
  const [newPort, setNewPort] = useState(443);
  const [newFingerprint, setNewFingerprint] = useState<'chrome' | 'firefox' | 'safari' | 'random'>('chrome');
  const [newFragment, setNewFragment] = useState(true);

  const [busyId, setBusyId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [qrTarget, setQrTarget] = useState<{ title: string; subtitle: string; value: string } | null>(
    null
  );

  const originUrl = typeof window !== 'undefined' ? window.location.origin : `https://${dashboard.settings.domain}`;
  const v2raySubUrl = `${originUrl}/sub/${dashboard.settings.subscriptionSecret}?format=v2ray`;
  const incySubUrl = `${originUrl}/sub/${dashboard.settings.subscriptionSecret}?format=incy`;

  const filteredTokens = useMemo(() => {
    if (filterProtocol === 'all') return dashboard.tokens;
    return dashboard.tokens.filter((t) => t.protocol === filterProtocol);
  }, [dashboard.tokens, filterProtocol]);

  const copyText = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId((curr) => (curr === id ? null : curr)), 1800);
    } catch {
      setErrorMsg('مرورگر اجازه دسترسی به کلیپ‌بورد را نداد.');
    }
  };

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    setBusyId('create');
    setErrorMsg(null);
    try {
      const res = await createProxyToken({
        name: newName.trim() || `Arash-${newProtocol.toUpperCase()}`,
        protocol: newProtocol,
        cleanIp: newCleanIp,
        port: newPort,
        transport: newProtocol === 'vless' ? newTransport : 'ws',
        fingerprint: newFingerprint,
        tlsFragmentEnabled: newFragment,
      });
      onUpdate(res.dashboard);
      setNewName('');
      setShowCreate(false);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'خطا در ساخت توکن');
    } finally {
      setBusyId(null);
    }
  };

  const handleToggle = async (token: ProxyToken) => {
    setBusyId(token.id);
    setErrorMsg(null);
    try {
      const res = await updateProxyToken(token.id, { enabled: !token.enabled });
      onUpdate(res.dashboard);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'خطا در تغییر وضعیت توکن');
    } finally {
      setBusyId(null);
    }
  };

  const handleRotate = async (token: ProxyToken) => {
    setBusyId(token.id);
    setErrorMsg(null);
    try {
      const res = await rotateProxyToken(token.id);
      onUpdate(res.dashboard);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'خطا در چرخش کلید توکن');
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (token: ProxyToken) => {
    setBusyId(token.id);
    setErrorMsg(null);
    try {
      const res = await deleteProxyToken(token.id);
      onUpdate(res.dashboard);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'خطا در حذف توکن');
    } finally {
      setBusyId(null);
    }
  };

  const handleRotateSub = async () => {
    setBusyId('sub-rotate');
    setErrorMsg(null);
    try {
      const res = await rotateSubscriptionSecret();
      onUpdate(res.dashboard);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'خطا در بازتولید لینک اشتراک');
    } finally {
      setBusyId(null);
    }
  };

  const handleDownloadXrayJson = async (token: ProxyToken) => {
    setBusyId(token.id);
    try {
      const res = await fetchV2RayExport(token.id);
      const blob = new Blob([res.content], { type: 'application/json;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = res.filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'خطا در دانلود فایل Xray JSON');
    } finally {
      setBusyId(null);
    }
  };

  const handleDownloadIncyJson = () => {
    const content = buildIncySingBoxConfig(dashboard.tokens, dashboard.settings);
    const blob = new Blob([content], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incy-${dashboard.settings.domain}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Subscription Links Bar */}
      <section className="rounded-xl border border-[#1E293B] bg-[#111622] p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-[#E6EDF3]">
              لینک اشتراک هوشمند و اتصال مستقیم برای INCY و V2Ray
            </h2>
            <p className="mt-1 text-xs text-[#94A3B8]">
              برای رفع قطعی و خطای <span dir="ltr" className="font-mono text-[#CBD5E1]">No such host is known</span> در برنامه INCY هنگام اتصال از ایران، توکن‌ها را مستقیماً کپی و در بخش Add Content جای‌گذاری کنید (بدون نیاز به DNS).
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => copyText('direct-raw-incy', buildRawUriList(dashboard.tokens))}
              className="flex h-9 items-center gap-1.5 rounded-lg bg-emerald-600 px-3.5 text-xs font-semibold text-white transition-colors hover:bg-emerald-500 whitespace-nowrap shrink-0"
            >
              {copiedId === 'direct-raw-incy' ? (
                <Check className="h-3.5 w-3.5" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
              <span>
                {copiedId === 'direct-raw-incy'
                  ? 'کپی شد! در INCY پیست کنید'
                  : 'کپی مستقیم توکن‌ها برای INCY (آفلاین)'}
              </span>
            </button>
            <button
              type="button"
              onClick={handleDownloadIncyJson}
              className="flex h-9 items-center gap-1.5 rounded-lg border border-[#1E293B] bg-[#090D14] px-3.5 text-xs font-medium text-[#CBD5E1] transition-colors hover:bg-[#1A2233] whitespace-nowrap shrink-0"
            >
              <Download className="h-3.5 w-3.5" />
              <span>دانلود JSON آفلاین INCY</span>
            </button>
            <button
              type="button"
              onClick={handleRotateSub}
              disabled={busyId === 'sub-rotate'}
              className="flex h-9 items-center gap-2 rounded-lg border border-[#1E293B] bg-[#090D14] px-3.5 text-xs font-medium text-[#CBD5E1] transition-colors hover:border-amber-500/40 hover:text-amber-300 disabled:opacity-50 whitespace-nowrap shrink-0"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${busyId === 'sub-rotate' ? 'animate-spin' : ''}`} />
              <span>بازتولید توکن اشتراک</span>
            </button>
          </div>
        </div>

        <div className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="flex items-center justify-between gap-3">
              <span className="text-xs font-medium text-[#E6EDF3]">
                اشتراک V2Ray / v2rayNG / Hiddify (Base64)
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() =>
                    setQrTarget({
                      title: 'QR اشتراک V2Ray',
                      subtitle: 'اسکن در v2rayNG، v2rayN یا Nekoray',
                      value: v2raySubUrl,
                    })
                  }
                  className="flex h-8 items-center gap-1.5 rounded-md border border-[#1E293B] px-2.5 text-xs text-[#CBD5E1] transition-colors hover:bg-[#1A2233] whitespace-nowrap shrink-0"
                >
                  <QrCode className="h-3.5 w-3.5" />
                  <span>QR</span>
                </button>
                <button
                  type="button"
                  onClick={() => copyText('sub-v2ray', v2raySubUrl)}
                  className="flex h-8 items-center gap-1.5 rounded-md bg-emerald-600 px-3 text-xs font-medium text-white transition-colors hover:bg-emerald-500 whitespace-nowrap shrink-0"
                >
                  {copiedId === 'sub-v2ray' ? (
                    <Check className="h-3.5 w-3.5" />
                  ) : (
                    <Copy className="h-3.5 w-3.5" />
                  )}
                  <span>{copiedId === 'sub-v2ray' ? 'کپی شد' : 'کپی لینک'}</span>
                </button>
              </div>
            </div>
            <div dir="ltr" className="mt-2.5 truncate font-mono text-xs text-[#94A3B8]">
              {v2raySubUrl}
            </div>
          </div>

          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="flex items-center justify-between gap-3">
              <span className="text-xs font-medium text-[#E6EDF3]">
                پروفایل مستقیم INCY / Sing-box (JSON Remote)
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() =>
                    setQrTarget({
                      title: 'QR اشتراک INCY / Sing-box',
                      subtitle: 'اسکن در برنامه INCY یا کلاینت‌های Sing-box',
                      value: incySubUrl,
                    })
                  }
                  className="flex h-8 items-center gap-1.5 rounded-md border border-[#1E293B] px-2.5 text-xs text-[#CBD5E1] transition-colors hover:bg-[#1A2233] whitespace-nowrap shrink-0"
                >
                  <QrCode className="h-3.5 w-3.5" />
                  <span>QR</span>
                </button>
                <button
                  type="button"
                  onClick={() => copyText('sub-incy', incySubUrl)}
                  className="flex h-8 items-center gap-1.5 rounded-md bg-emerald-600 px-3 text-xs font-medium text-white transition-colors hover:bg-emerald-500 whitespace-nowrap shrink-0"
                >
                  {copiedId === 'sub-incy' ? (
                    <Check className="h-3.5 w-3.5" />
                  ) : (
                    <Copy className="h-3.5 w-3.5" />
                  )}
                  <span>{copiedId === 'sub-incy' ? 'کپی شد' : 'کپی لینک'}</span>
                </button>
              </div>
            </div>
            <div dir="ltr" className="mt-2.5 truncate font-mono text-xs text-[#94A3B8]">
              {incySubUrl}
            </div>
          </div>
        </div>
      </section>

      {errorMsg && (
        <div
          role="alert"
          className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-xs text-red-300"
        >
          {errorMsg}
        </div>
      )}

      {/* Tokens Toolbar & Create Form */}
      <section className="rounded-xl border border-[#1E293B] bg-[#111622] p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-4">
            <h2 className="text-base font-semibold text-[#E6EDF3]">
              توکن‌های اتصال ({filteredTokens.length})
            </h2>
            <div className="flex items-center gap-1 rounded-lg border border-[#1E293B] bg-[#090D14] p-1">
              {(['all', 'vless', 'trojan', 'vmess'] as const).map((proto) => (
                <button
                  key={proto}
                  type="button"
                  onClick={() => setFilterProtocol(proto)}
                  className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                    filterProtocol === proto
                      ? 'bg-[#1E293B] text-[#E6EDF3]'
                      : 'text-[#94A3B8] hover:text-[#E6EDF3]'
                  }`}
                >
                  {proto === 'all' ? 'همه پروتکل‌ها' : proto.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          <button
            type="button"
            onClick={() => setShowCreate((prev) => !prev)}
            className="flex h-10 items-center gap-2 rounded-lg bg-emerald-600 px-4 text-xs font-semibold text-white transition-colors hover:bg-emerald-500 whitespace-nowrap shrink-0"
          >
            <Plus className="h-4 w-4" />
            <span>{showCreate ? 'بستن فرم' : 'ایجاد توکن جدید'}</span>
          </button>
        </div>

        {showCreate && (
          <form
            onSubmit={handleCreate}
            className="mt-6 grid grid-cols-1 gap-4 border-t border-[#1E293B] pt-6 sm:grid-cols-2 lg:grid-cols-3"
          >
            <div>
              <label className="block text-xs font-medium text-[#CBD5E1]">نام پروفایل</label>
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="مثال: همراه اول بدون قطعی"
                className="mt-1.5 h-10 w-full rounded-lg border border-[#1E293B] bg-[#090D14] px-3 text-xs text-[#E6EDF3] focus:border-emerald-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-[#CBD5E1]">پروتکل</label>
              <select
                value={newProtocol}
                onChange={(e) => setNewProtocol(e.target.value as ProxyProtocol)}
                className="mt-1.5 h-10 w-full rounded-lg border border-[#1E293B] bg-[#090D14] px-3 font-mono text-xs text-[#E6EDF3] focus:border-emerald-500 focus:outline-none"
              >
                <option value="vless">VLESS (پیشنهادی برای Cloudflare)</option>
                <option value="trojan">Trojan TLS</option>
                <option value="vmess">VMess TLS</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#CBD5E1]">آی‌پی تمیز (Clean IP)</label>
              <select
                value={newCleanIp}
                onChange={(e) => setNewCleanIp(e.target.value)}
                dir="ltr"
                className="mt-1.5 h-10 w-full rounded-lg border border-[#1E293B] bg-[#090D14] px-3 font-mono text-xs text-[#E6EDF3] focus:border-emerald-500 focus:outline-none"
              >
                {dashboard.cleanIps.map((c) => (
                  <option key={c.ip} value={c.ip}>
                    {c.ip} ({c.label})
                  </option>
                ))}
                <option value={dashboard.settings.domain}>{dashboard.settings.domain} (دامنه مستقیم)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#CBD5E1]">پورت کلودفلر (TLS)</label>
              <select
                value={newPort}
                onChange={(e) => setNewPort(Number(e.target.value))}
                dir="ltr"
                className="mt-1.5 h-10 w-full rounded-lg border border-[#1E293B] bg-[#090D14] px-3 font-mono text-xs text-[#E6EDF3] focus:border-emerald-500 focus:outline-none"
              >
                {CF_PORTS.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#CBD5E1]">بستر انتقال و اثرانگشت TLS</label>
              <div className="mt-1.5 grid grid-cols-2 gap-2">
                <select
                  value={newProtocol === 'vless' ? newTransport : 'ws'}
                  disabled={newProtocol !== 'vless'}
                  onChange={(e) => setNewTransport(e.target.value as TransportType)}
                  dir="ltr"
                  className="h-10 rounded-lg border border-[#1E293B] bg-[#090D14] px-2.5 font-mono text-xs text-[#E6EDF3] disabled:opacity-50"
                >
                  <option value="ws">WebSocket</option>
                  <option value="grpc">gRPC</option>
                </select>
                <select
                  value={newFingerprint}
                  onChange={(e) =>
                    setNewFingerprint(e.target.value as 'chrome' | 'firefox' | 'safari' | 'random')
                  }
                  dir="ltr"
                  className="h-10 rounded-lg border border-[#1E293B] bg-[#090D14] px-2.5 font-mono text-xs text-[#E6EDF3]"
                >
                  <option value="chrome">uTLS: Chrome</option>
                  <option value="safari">uTLS: Safari</option>
                  <option value="firefox">uTLS: Firefox</option>
                  <option value="random">uTLS: Random</option>
                </select>
              </div>
            </div>

            <div className="flex items-end justify-between gap-4">
              <label className="flex h-10 cursor-pointer items-center gap-2.5 text-xs text-[#CBD5E1]">
                <input
                  type="checkbox"
                  checked={newFragment}
                  onChange={(e) => setNewFragment(e.target.checked)}
                  className="h-4 w-4 rounded border-[#334155] bg-[#090D14] accent-emerald-500"
                />
                <span>فعال‌سازی TLS Fragment (ضد فیلترینگ ایران)</span>
              </label>

              <button
                type="submit"
                disabled={busyId === 'create'}
                className="h-10 rounded-lg bg-emerald-600 px-5 text-xs font-semibold text-white transition-colors hover:bg-emerald-500 disabled:opacity-50 whitespace-nowrap shrink-0"
              >
                {busyId === 'create' ? 'در حال ایجاد...' : 'ساخت توکن'}
              </button>
            </div>
          </form>
        )}

        {/* Token List */}
        <div className="mt-6 divide-y divide-[#1E293B] border-t border-[#1E293B]">
          {filteredTokens.length === 0 ? (
            <div className="py-10 text-center text-sm text-[#94A3B8]">
              هیچ توکنی برای این فیلتر یافت نشد. از دکمه «ایجاد توکن جدید» استفاده کنید.
            </div>
          ) : (
            filteredTokens.map((token) => {
              const uri = buildProxyUri(token);
              const isBusy = busyId === token.id;

              return (
                <div key={token.id} className="py-5 first:pt-5 last:pb-1">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-3">
                        <h3 className="text-sm font-semibold text-[#E6EDF3]">{token.name}</h3>
                        <span
                          className={`text-xs font-medium ${
                            token.enabled ? 'text-emerald-400' : 'text-[#64748B]'
                          }`}
                        >
                          {token.enabled ? 'فعال و آماده اتصال' : 'غیرفعال'}
                        </span>
                      </div>

                      <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-[#94A3B8]">
                        <span dir="ltr" className="font-mono font-medium text-[#CBD5E1]">
                          {token.protocol.toUpperCase()}
                        </span>
                        <span aria-hidden="true">·</span>
                        <span dir="ltr" className="font-mono">
                          {token.cleanIp}:{token.port}
                        </span>
                        <span aria-hidden="true">·</span>
                        <span dir="ltr" className="font-mono">
                          SNI: {token.sni}
                        </span>
                        <span aria-hidden="true">·</span>
                        <span dir="ltr" className="font-mono">
                          {token.transport.toUpperCase()} / {token.fingerprint}
                        </span>
                        {token.tlsFragmentEnabled && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span className="text-emerald-400/90">
                              TLS Fragment ({token.fragmentLength})
                            </span>
                          </>
                        )}
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        onClick={() => copyText(token.id, uri)}
                        className="flex h-9 items-center gap-1.5 rounded-lg bg-emerald-600 px-3.5 text-xs font-medium text-white transition-colors hover:bg-emerald-500 whitespace-nowrap shrink-0"
                      >
                        {copiedId === token.id ? (
                          <Check className="h-3.5 w-3.5" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                        <span>{copiedId === token.id ? 'کپی شد' : 'کپی توکن'}</span>
                      </button>

                      <button
                        type="button"
                        onClick={() =>
                          setQrTarget({
                            title: token.name,
                            subtitle: `${token.protocol.toUpperCase()} · قابل اسکن در V2Ray و INCY`,
                            value: uri,
                          })
                        }
                        className="flex h-9 items-center gap-1.5 rounded-lg border border-[#1E293B] bg-[#090D14] px-3 text-xs font-medium text-[#CBD5E1] transition-colors hover:bg-[#1A2233] whitespace-nowrap shrink-0"
                      >
                        <QrCode className="h-3.5 w-3.5" />
                        <span>QR</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => handleDownloadXrayJson(token)}
                        disabled={isBusy}
                        className="flex h-9 items-center gap-1.5 rounded-lg border border-[#1E293B] bg-[#090D14] px-3 text-xs font-medium text-[#CBD5E1] transition-colors hover:bg-[#1A2233] whitespace-nowrap shrink-0"
                        title="دانلود کانفیگ JSON با TLS Fragment برای V2Ray"
                      >
                        <Download className="h-3.5 w-3.5" />
                        <span>Xray JSON</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => handleRotate(token)}
                        disabled={isBusy}
                        className="flex h-9 items-center gap-1.5 rounded-lg border border-[#1E293B] bg-[#090D14] px-3 text-xs font-medium text-[#CBD5E1] transition-colors hover:border-amber-500/40 hover:text-amber-300 whitespace-nowrap shrink-0"
                        title="تغییر UUID و مسیر WebSocket برای مقابله با مسدودسازی"
                      >
                        <RefreshCw className={`h-3.5 w-3.5 ${isBusy ? 'animate-spin' : ''}`} />
                        <span>چرخش کلید</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => handleToggle(token)}
                        disabled={isBusy}
                        className="flex h-9 items-center gap-1.5 rounded-lg border border-[#1E293B] bg-[#090D14] px-3 text-xs font-medium text-[#CBD5E1] transition-colors hover:bg-[#1A2233] whitespace-nowrap shrink-0"
                      >
                        <Shield className="h-3.5 w-3.5" />
                        <span>{token.enabled ? 'توقف' : 'فعال‌سازی'}</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => handleDelete(token)}
                        disabled={isBusy}
                        className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#1E293B] bg-[#090D14] text-[#94A3B8] transition-colors hover:border-red-500/40 hover:text-red-400 shrink-0"
                        aria-label={`حذف ${token.name}`}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>

                  <div
                    dir="ltr"
                    className="mt-3 truncate rounded-lg border border-[#1E293B] bg-[#090D14] px-3.5 py-2.5 font-mono text-xs text-[#94A3B8]"
                  >
                    {uri}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </section>

      {qrTarget && (
        <QrModal
          title={qrTarget.title}
          subtitle={qrTarget.subtitle}
          value={qrTarget.value}
          onClose={() => setQrTarget(null)}
        />
      )}
    </div>
  );
}
