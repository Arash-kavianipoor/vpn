import { useState, type FormEvent } from 'react';
import { Activity, CheckCircle2, GlobeLock, RefreshCw, Zap } from 'lucide-react';
import {
  probeAllCleanIps,
  probeEndpoint,
  runIpAudit,
  updateProxyToken,
} from '../lib/api.ts';
import type { DashboardState, IpAuditResult, ProbeResult } from '../types.ts';

interface NetworkAuditPanelProps {
  dashboard: DashboardState;
  onUpdate: (next: DashboardState) => void;
}

export function NetworkAuditPanel({ dashboard, onUpdate }: NetworkAuditPanelProps) {
  const [customTarget, setCustomTarget] = useState(dashboard.settings.domain);
  const [customPort, setCustomPort] = useState(443);
  const [probingAll, setProbingAll] = useState(false);
  const [probingCustom, setProbingCustom] = useState(false);
  const [customResult, setCustomResult] = useState<ProbeResult | null>(null);

  const [auditingIp, setAuditingIp] = useState(false);
  const [ipAudit, setIpAudit] = useState<IpAuditResult | null>(null);
  const [applyingIp, setApplyingIp] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleProbeAll = async () => {
    setProbingAll(true);
    setError(null);
    try {
      const res = await probeAllCleanIps();
      onUpdate(res.dashboard);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'خطا در بررسی آی‌پی‌های کلودفلر');
    } finally {
      setProbingAll(false);
    }
  };

  const handleProbeCustom = async (e: FormEvent) => {
    e.preventDefault();
    if (!customTarget.trim()) return;
    setProbingCustom(true);
    setError(null);
    try {
      const res = await probeEndpoint(customTarget.trim(), customPort, dashboard.settings.domain);
      setCustomResult(res.probe);
      onUpdate(res.dashboard);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'خطا در تست اتصال');
    } finally {
      setProbingCustom(false);
    }
  };

  const handleIpAudit = async () => {
    setAuditingIp(true);
    setError(null);
    try {
      const result = await runIpAudit();
      setIpAudit(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'خطا در بررسی IP خروجی');
    } finally {
      setAuditingIp(false);
    }
  };

  const handleApplyCleanIp = async (ip: string) => {
    setApplyingIp(ip);
    setError(null);
    setMessage(null);
    try {
      let latestDashboard = dashboard;
      for (const token of dashboard.tokens) {
        const res = await updateProxyToken(token.id, { cleanIp: ip });
        latestDashboard = res.dashboard;
      }
      onUpdate(latestDashboard);
      setMessage(`آی‌پی تمیز ${ip} روی تمام توکن‌های فعال اعمال شد.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'خطا در اعمال آی‌پی تمیز');
    } finally {
      setApplyingIp(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Real Egress IP Leak Audit */}
      <section className="rounded-xl border border-[#1E293B] bg-[#111622] p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-[#E6EDF3]">
              آزمون زنده مخفی‌سازی IP و بررسی نشت آی‌پی ایران
            </h2>
            <p className="mt-1 text-xs leading-6 text-[#94A3B8]">
              آی‌پی خروجی سرور و هدرهای HTTP دریافتی را از طریق شبکه کلودفلر استعلام می‌گیرد تا از عدم افشای آی‌پی ایران اطمینان حاصل شود.
            </p>
          </div>
          <button
            type="button"
            onClick={handleIpAudit}
            disabled={auditingIp}
            className="flex h-10 items-center gap-2 rounded-lg bg-emerald-600 px-4 text-xs font-semibold text-white transition-colors hover:bg-emerald-500 disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <GlobeLock className="h-4 w-4" />
            <span>{auditingIp ? 'در حال بررسی زنده...' : 'اجرای آزمون نشت IP'}</span>
          </button>
        </div>

        {ipAudit && (
          <div className="mt-5 grid grid-cols-1 gap-4 border-t border-[#1E293B] pt-5 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
              <div className="text-xs text-[#94A3B8]">آی‌پی خروجی مشاهده‌شده</div>
              <div dir="ltr" className="mt-1.5 font-mono text-sm font-semibold text-[#E6EDF3]">
                {ipAudit.egressIp}
              </div>
            </div>
            <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
              <div className="text-xs text-[#94A3B8]">موقعیت کشور و مرکز کلودفلر</div>
              <div dir="ltr" className="mt-1.5 font-mono text-sm font-semibold text-[#E6EDF3]">
                {ipAudit.countryCode} · {ipAudit.colo}
              </div>
            </div>
            <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
              <div className="text-xs text-[#94A3B8]">پروتکل امنیتی اتصال</div>
              <div dir="ltr" className="mt-1.5 font-mono text-sm font-semibold text-[#E6EDF3]">
                {ipAudit.tlsVersion} · {ipAudit.httpVersion}
              </div>
            </div>
            <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
              <div className="text-xs text-[#94A3B8]">وضعیت افشای IP ایران</div>
              <div
                className={`mt-1.5 flex items-center gap-1.5 text-sm font-semibold ${
                  ipAudit.iranIpExposed ? 'text-red-400' : 'text-emerald-400'
                }`}
              >
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                <span>
                  {ipAudit.iranIpExposed ? 'هشدار: آی‌پی ایران قابل مشاهده است' : 'مخفی (امن)'}
                </span>
              </div>
            </div>
          </div>
        )}
      </section>

      {error && (
        <div
          role="alert"
          className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-xs text-red-300"
        >
          {error}
        </div>
      )}

      {message && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-xs text-emerald-300">
          {message}
        </div>
      )}

      {/* Custom Domain / IP TLS Handshake Tester */}
      <section className="rounded-xl border border-[#1E293B] bg-[#111622] p-6">
        <h3 className="text-sm font-semibold text-[#E6EDF3]">
          تست دست‌دهی TLS (Handshake) برای دامنه{' '}
          <span dir="ltr" className="font-mono text-emerald-400">
            {dashboard.settings.domain}
          </span>{' '}
          یا IP دلخواه
        </h3>

        <form onSubmit={handleProbeCustom} className="mt-4 flex flex-wrap items-end gap-3">
          <div className="min-w-[240px] flex-1">
            <label className="block text-xs text-[#94A3B8]">دامنه یا IP هدف</label>
            <input
              type="text"
              dir="ltr"
              value={customTarget}
              onChange={(e) => setCustomTarget(e.target.value)}
              placeholder="Arashproxysystem.ir"
              className="mt-1.5 h-10 w-full rounded-lg border border-[#1E293B] bg-[#090D14] px-3.5 font-mono text-xs text-[#E6EDF3] focus:border-emerald-500 focus:outline-none"
            />
          </div>
          <div className="w-28">
            <label className="block text-xs text-[#94A3B8]">پورت</label>
            <input
              type="number"
              dir="ltr"
              value={customPort}
              onChange={(e) => setCustomPort(Number(e.target.value) || 443)}
              className="mt-1.5 h-10 w-full rounded-lg border border-[#1E293B] bg-[#090D14] px-3 font-mono text-xs text-[#E6EDF3] focus:border-emerald-500 focus:outline-none"
            />
          </div>
          <button
            type="submit"
            disabled={probingCustom}
            className="flex h-10 items-center gap-2 rounded-lg border border-[#1E293B] bg-[#090D14] px-4 text-xs font-medium text-[#E6EDF3] transition-colors hover:border-emerald-500/50 disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <Activity className="h-4 w-4 text-emerald-400" />
            <span>{probingCustom ? 'در حال سنجش...' : 'اجرای تست TLS'}</span>
          </button>
        </form>

        {customResult && (
          <div className="mt-4 flex flex-wrap items-center gap-4 rounded-lg border border-[#1E293B] bg-[#090D14] px-4 py-3 text-xs">
            <span className={customResult.reachable ? 'font-semibold text-emerald-400' : 'font-semibold text-amber-400'}>
              {customResult.reachable ? 'پاسخ‌گو و آماده اتصال' : 'عدم دسترسی'}
            </span>
            <span aria-hidden="true">·</span>
            <span dir="ltr" className="font-mono text-[#CBD5E1]">
              {customResult.target}:{customResult.port}
            </span>
            {customResult.latencyMs !== null && (
              <>
                <span aria-hidden="true">·</span>
                <span dir="ltr" className="font-mono tabular-nums text-[#E6EDF3]">
                  {customResult.latencyMs} ms
                </span>
              </>
            )}
            {customResult.tlsProtocol && (
              <>
                <span aria-hidden="true">·</span>
                <span dir="ltr" className="font-mono text-[#94A3B8]">
                  {customResult.tlsProtocol} ({customResult.cipher})
                </span>
              </>
            )}
            {customResult.error && (
              <span dir="ltr" className="font-mono text-red-400">
                {customResult.error}
              </span>
            )}
          </div>
        )}
      </section>

      {/* Clean IP Benchmark Table */}
      <section className="rounded-xl border border-[#1E293B] bg-[#111622] p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-semibold text-[#E6EDF3]">
              بانک آی‌پی‌های تمیز کلودفلر (Clean IP Anycast)
            </h3>
            <p className="mt-1 text-xs text-[#94A3B8]">
              آی‌پی با کمترین پینگ را انتخاب و با یک کلیک روی تمام توکن‌های V2Ray و INCY اعمال کنید.
            </p>
          </div>
          <button
            type="button"
            onClick={handleProbeAll}
            disabled={probingAll}
            className="flex h-9 items-center gap-2 rounded-lg bg-emerald-600 px-4 text-xs font-medium text-white transition-colors hover:bg-emerald-500 disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${probingAll ? 'animate-spin' : ''}`} />
            <span>{probingAll ? 'در حال سنجش همه...' : 'تست پینگ همه آی‌پی‌ها'}</span>
          </button>
        </div>

        <div className="mt-5 overflow-x-auto">
          <table className="w-full text-right text-xs">
            <thead>
              <tr className="border-b border-[#1E293B] text-[#94A3B8]">
                <th className="pb-3 font-medium">آی‌پی لبه کلودفلر</th>
                <th className="pb-3 font-medium">شرح نود</th>
                <th className="pb-3 font-medium">منطقه</th>
                <th className="pb-3 font-medium">وضعیت</th>
                <th className="pb-3 font-medium text-left">تأخیر (TLS RTT)</th>
                <th className="pb-3 font-medium text-left">عملیات</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]">
              {dashboard.cleanIps.map((item) => (
                <tr key={item.ip} className="transition-colors hover:bg-[#161D2C]">
                  <td dir="ltr" className="py-3 text-right font-mono font-medium text-[#E6EDF3]">
                    {item.ip}
                  </td>
                  <td className="py-3 text-[#CBD5E1]">{item.label}</td>
                  <td className="py-3 text-[#94A3B8]">{item.region}</td>
                  <td className="py-3">
                    {item.reachable === null ? (
                      <span className="text-[#64748B]">تست‌نشده</span>
                    ) : item.reachable ? (
                      <span className="font-medium text-emerald-400">در دسترس</span>
                    ) : (
                      <span className="font-medium text-red-400">قطع</span>
                    )}
                  </td>
                  <td dir="ltr" className="py-3 text-left font-mono tabular-nums text-[#E6EDF3]">
                    {item.lastLatencyMs !== null ? `${item.lastLatencyMs} ms` : '—'}
                  </td>
                  <td className="py-3 text-left">
                    <button
                      type="button"
                      onClick={() => handleApplyCleanIp(item.ip)}
                      disabled={applyingIp === item.ip}
                      className="inline-flex h-8 items-center gap-1.5 rounded-md border border-[#1E293B] bg-[#090D14] px-3 text-xs font-medium text-[#CBD5E1] transition-colors hover:border-emerald-500/50 hover:text-emerald-300 disabled:opacity-50 whitespace-nowrap shrink-0"
                    >
                      <Zap className="h-3 w-3" />
                      <span>{applyingIp === item.ip ? 'در حال اعمال...' : 'اعمال روی توکن‌ها'}</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
