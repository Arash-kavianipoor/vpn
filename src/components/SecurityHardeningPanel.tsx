import { useState, type FormEvent } from 'react';
import { Lock, Save } from 'lucide-react';
import { updateSystemSettings } from '../lib/api.ts';
import type { DashboardState } from '../types.ts';

interface SecurityHardeningPanelProps {
  dashboard: DashboardState;
  onUpdate: (next: DashboardState) => void;
}

export function SecurityHardeningPanel({ dashboard, onUpdate }: SecurityHardeningPanelProps) {
  const [domain, setDomain] = useState(dashboard.settings.domain);
  const [proxyIp, setProxyIp] = useState(dashboard.settings.proxyIp);
  const [dohProvider, setDohProvider] = useState(dashboard.settings.dohProvider);
  const [decoyTitle, setDecoyTitle] = useState(dashboard.settings.decoyTitle);
  const [d1DatabaseId, setD1DatabaseId] = useState(
    dashboard.settings.d1DatabaseId || 'a16983d7-1da3-4555-a1aa-f5730bccfcae'
  );
  const [antiProbeDecoy, setAntiProbeDecoy] = useState(dashboard.settings.antiProbeDecoy);
  const [webrtcBlock, setWebrtcBlock] = useState(dashboard.settings.webrtcBlock);
  const [strictIpMask, setStrictIpMask] = useState(dashboard.settings.strictIpMask);
  const [stripClientHeaders, setStripClientHeaders] = useState(
    dashboard.settings.stripClientHeaders
  );

  const [saving, setSaving] = useState(false);
  const [savedNotice, setSavedNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSave = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSavedNotice(null);
    setError(null);
    try {
      const res = await updateSystemSettings({
        domain: domain.trim(),
        workerUrl: `https://${domain.trim()}`,
        proxyIp: proxyIp.trim(),
        dohProvider: dohProvider.trim(),
        decoyTitle: decoyTitle.trim(),
        d1DatabaseId: d1DatabaseId.trim(),
        antiProbeDecoy,
        webrtcBlock,
        strictIpMask,
        stripClientHeaders,
      });
      onUpdate(res.dashboard);
      setSavedNotice('تنظیمات امنیتی با موفقیت ذخیره و در تمام توکن‌ها همگام‌سازی شد.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'خطا در ذخیره تنظیمات');
    } finally {
      setSaving(false);
    }
  };

  const formatTime = (iso: string) => {
    try {
      return new Intl.DateTimeFormat('fa-IR', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        month: '2-digit',
        day: '2-digit',
      }).format(new Date(iso));
    } catch {
      return iso;
    }
  };

  return (
    <div className="space-y-6">
      {/* Core Security & Anti-Leak Configuration */}
      <section className="rounded-xl border border-[#1E293B] bg-[#111622] p-6">
        <div className="flex items-center gap-2.5">
          <Lock className="h-4 w-4 text-emerald-400" />
          <h2 className="text-base font-semibold text-[#E6EDF3]">
            سخت‌سازی امنیتی و تنظیمات ضدنشت IP
          </h2>
        </div>

        <form onSubmit={handleSave} className="mt-6 space-y-6">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-xs font-medium text-[#CBD5E1]">
                دامنه اختصاصی کلودفلر (SNI &amp; Host)
              </label>
              <input
                type="text"
                dir="ltr"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                className="mt-1.5 h-10 w-full rounded-lg border border-[#1E293B] bg-[#090D14] px-3.5 font-mono text-xs text-[#E6EDF3] focus:border-emerald-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-[#CBD5E1]">
                آی‌پی رله خروجی ورکر (PROXYIP غیرایرانی)
              </label>
              <input
                type="text"
                dir="ltr"
                value={proxyIp}
                onChange={(e) => setProxyIp(e.target.value)}
                className="mt-1.5 h-10 w-full rounded-lg border border-[#1E293B] bg-[#090D14] px-3.5 font-mono text-xs text-[#E6EDF3] focus:border-emerald-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-[#CBD5E1]">
                سرویس DNS-over-HTTPS (جلوگیری از نشت DNS ایران)
              </label>
              <select
                value={dohProvider}
                onChange={(e) => setDohProvider(e.target.value)}
                dir="ltr"
                className="mt-1.5 h-10 w-full rounded-lg border border-[#1E293B] bg-[#090D14] px-3 font-mono text-xs text-[#E6EDF3] focus:border-emerald-500 focus:outline-none"
              >
                <option value="https://1.1.1.1/dns-query">Cloudflare DoH (1.1.1.1)</option>
                <option value="https://8.8.8.8/dns-query">Google DoH (8.8.8.8)</option>
                <option value="https://dns.quad9.net/dns-query">Quad9 Secure DoH</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#CBD5E1]">
                عنوان صفحه فریب ضداسکن (Anti-Probe Decoy)
              </label>
              <input
                type="text"
                dir="ltr"
                value={decoyTitle}
                onChange={(e) => setDecoyTitle(e.target.value)}
                className="mt-1.5 h-10 w-full rounded-lg border border-[#1E293B] bg-[#090D14] px-3.5 font-mono text-xs text-[#E6EDF3] focus:border-emerald-500 focus:outline-none"
              />
            </div>

            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-[#CBD5E1]">
                شناسه دیتابیس کلودفلر (Cloudflare D1 Database ID)
              </label>
              <input
                type="text"
                dir="ltr"
                value={d1DatabaseId}
                onChange={(e) => setD1DatabaseId(e.target.value)}
                className="mt-1.5 h-10 w-full rounded-lg border border-[#1E293B] bg-[#090D14] px-3.5 font-mono text-xs text-[#E6EDF3] focus:border-emerald-500 focus:outline-none"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 border-t border-[#1E293B] pt-5 sm:grid-cols-2">
            <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-[#1E293B] bg-[#090D14] p-3.5">
              <input
                type="checkbox"
                checked={stripClientHeaders}
                onChange={(e) => setStripClientHeaders(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded accent-emerald-500"
              />
              <div>
                <div className="text-xs font-semibold text-[#E6EDF3]">
                  حذف هدرهای افشاگر IP کاربر
                </div>
                <div className="mt-1 text-xs text-[#94A3B8]">
                  حذف کامل CF-Connecting-IP، X-Forwarded-For و X-Real-IP در خروجی ورکر.
                </div>
              </div>
            </label>

            <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-[#1E293B] bg-[#090D14] p-3.5">
              <input
                type="checkbox"
                checked={webrtcBlock}
                onChange={(e) => setWebrtcBlock(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded accent-emerald-500"
              />
              <div>
                <div className="text-xs font-semibold text-[#E6EDF3]">
                  مسدودسازی نشت WebRTC و STUN
                </div>
                <div className="mt-1 text-xs text-[#94A3B8]">
                  بستن پورت‌های کشف IP محلی در فایل‌های خروجی INCY و V2Ray.
                </div>
              </div>
            </label>

            <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-[#1E293B] bg-[#090D14] p-3.5">
              <input
                type="checkbox"
                checked={antiProbeDecoy}
                onChange={(e) => setAntiProbeDecoy(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded accent-emerald-500"
              />
              <div>
                <div className="text-xs font-semibold text-[#E6EDF3]">
                  صفحه فریب برای اسکنرهای فیلترینگ
                </div>
                <div className="mt-1 text-xs text-[#94A3B8]">
                  نمایش وب‌سایت استاتیک معمولی هنگام باز کردن دامنه در مرورگر یا اسکن فعال.
                </div>
              </div>
            </label>

            <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-[#1E293B] bg-[#090D14] p-3.5">
              <input
                type="checkbox"
                checked={strictIpMask}
                onChange={(e) => setStrictIpMask(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded accent-emerald-500"
              />
              <div>
                <div className="text-xs font-semibold text-[#E6EDF3]">
                  تونل سراسری اجباری (بدون استثنای IP ایران)
                </div>
                <div className="mt-1 text-xs text-[#94A3B8]">
                  عبور ۱۰۰٪ برنامه‌های متصل از پروکسی کلودفلر برای عدم افشای آی‌پی ایران.
                </div>
              </div>
            </label>
          </div>

          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2.5 text-xs text-red-300">
              {error}
            </div>
          )}

          {savedNotice && (
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2.5 text-xs text-emerald-300">
              {savedNotice}
            </div>
          )}

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={saving}
              className="flex h-10 items-center gap-2 rounded-lg bg-emerald-600 px-5 text-xs font-semibold text-white transition-colors hover:bg-emerald-500 disabled:opacity-50 whitespace-nowrap shrink-0"
            >
              <Save className="h-4 w-4" />
              <span>{saving ? 'در حال ذخیره...' : 'ذخیره تنظیمات امنیتی'}</span>
            </button>
          </div>
        </form>
      </section>

      {/* Active Defense Posture */}
      <section className="rounded-xl border border-[#1E293B] bg-[#111622] p-6">
        <h3 className="text-sm font-semibold text-[#E6EDF3]">سپرهای دفاعی فعال سرور</h3>
        <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="text-xs text-[#94A3B8]">الگوریتم رمزعبور</div>
            <div dir="ltr" className="mt-1 font-mono text-xs font-semibold text-[#E6EDF3]">
              {dashboard.securityPosture.authAlgorithm}
            </div>
          </div>
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="text-xs text-[#94A3B8]">امضای نشست کاربری</div>
            <div dir="ltr" className="mt-1 font-mono text-xs font-semibold text-[#E6EDF3]">
              {dashboard.securityPosture.sessionCipher}
            </div>
          </div>
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="text-xs text-[#94A3B8]">قفل Brute-Force</div>
            <div className="mt-1 font-mono tabular-nums text-xs font-semibold text-[#E6EDF3]">
              {dashboard.securityPosture.maxFailedAttempts} خطا /{' '}
              {dashboard.securityPosture.rateLimitWindowMinutes} دقیقه
            </div>
          </div>
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="text-xs text-[#94A3B8]">IPهای مسدودشده فعلی</div>
            <div className="mt-1 font-mono tabular-nums text-xs font-semibold text-[#E6EDF3]">
              {dashboard.securityPosture.activeLockouts}
            </div>
          </div>
        </div>
      </section>

      {/* Security Audit Log Table */}
      <section className="rounded-xl border border-[#1E293B] bg-[#111622] p-6">
        <h3 className="text-sm font-semibold text-[#E6EDF3]">گزارش رویدادهای امنیتی (Audit Log)</h3>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-right text-xs">
            <thead>
              <tr className="border-b border-[#1E293B] text-[#94A3B8]">
                <th className="pb-3 font-medium">زمان</th>
                <th className="pb-3 font-medium">سطح</th>
                <th className="pb-3 font-medium">آدرس مبدا</th>
                <th className="pb-3 font-medium">شرح رویداد</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]">
              {dashboard.securityLogs.map((log) => (
                <tr key={log.id} className="hover:bg-[#161D2C]">
                  <td className="py-3 font-mono tabular-nums text-[#94A3B8] whitespace-nowrap">
                    {formatTime(log.timestamp)}
                  </td>
                  <td className="py-3 whitespace-nowrap">
                    <span
                      className={`font-medium ${
                        log.severity === 'critical'
                          ? 'text-red-400'
                          : log.severity === 'warning'
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                      }`}
                    >
                      {log.severity === 'critical'
                        ? 'بحرانی'
                        : log.severity === 'warning'
                          ? 'هشدار'
                          : 'عادی'}
                    </span>
                  </td>
                  <td dir="ltr" className="py-3 text-right font-mono text-[#CBD5E1] whitespace-nowrap">
                    {log.sourceIp}
                  </td>
                  <td className="py-3 text-[#E6EDF3]">{log.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
