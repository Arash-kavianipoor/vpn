import { useMemo, useState } from 'react';
import { Check, Copy, Download } from 'lucide-react';
import { buildIncySingBoxConfig, buildXrayFragmentConfig } from '../lib/proxyGenerators.ts';
import type { DashboardState } from '../types.ts';

interface IncyV2RayExportPanelProps {
  dashboard: DashboardState;
}

export function IncyV2RayExportPanel({ dashboard }: IncyV2RayExportPanelProps) {
  const [mode, setMode] = useState<'incy' | 'v2ray'>('incy');
  const [selectedTokenId, setSelectedTokenId] = useState<string>(
    dashboard.tokens[0]?.id || ''
  );
  const [copied, setCopied] = useState(false);

  const selectedToken = useMemo(
    () => dashboard.tokens.find((t) => t.id === selectedTokenId) || dashboard.tokens[0],
    [dashboard.tokens, selectedTokenId]
  );

  const configText = useMemo(() => {
    if (mode === 'incy') {
      return buildIncySingBoxConfig(dashboard.tokens, dashboard.settings);
    }
    if (!selectedToken) {
      return '// ابتدا یک توکن فعال ایجاد کنید.';
    }
    return buildXrayFragmentConfig(selectedToken, dashboard.settings);
  }, [mode, dashboard.tokens, dashboard.settings, selectedToken]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(configText);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Ignore
    }
  };

  const handleDownload = () => {
    const filename =
      mode === 'incy'
        ? `incy-${dashboard.settings.domain}.json`
        : `v2ray-fragment-${selectedToken?.protocol || 'vless'}-${dashboard.settings.domain}.json`;
    const blob = new Blob([configText], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-[#1E293B] bg-[#111622] p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-[#E6EDF3]">
              خروجی پیشرفته INCY و V2Ray (با محافظت ضدنشت IP ایران)
            </h2>
            <p className="mt-1 text-xs leading-6 text-[#94A3B8]">
              تمام ترافیک DNS از طریق DoH رمزنگاری‌شده عبور می‌کند، پورت‌های STUN/WebRTC برای جلوگیری از لو رفتن IP مسدود هستند و تمام برنامه‌ها از تونل امن عبور می‌کنند.
            </p>
          </div>

          <div className="flex items-center gap-1 rounded-lg border border-[#1E293B] bg-[#090D14] p-1">
            <button
              type="button"
              onClick={() => setMode('incy')}
              className={`rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                mode === 'incy'
                  ? 'bg-emerald-600 text-white'
                  : 'text-[#94A3B8] hover:text-[#E6EDF3]'
              }`}
            >
              پروفایل INCY (Sing-box)
            </button>
            <button
              type="button"
              onClick={() => setMode('v2ray')}
              className={`rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                mode === 'v2ray'
                  ? 'bg-emerald-600 text-white'
                  : 'text-[#94A3B8] hover:text-[#E6EDF3]'
              }`}
            >
              کانفیگ V2Ray / Xray Fragment
            </button>
          </div>
        </div>

        <div className="mt-5 grid grid-cols-1 gap-4 border-t border-[#1E293B] pt-5 md:grid-cols-3">
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="text-xs font-semibold text-[#E6EDF3]">۱. تونل کامل DNS-over-HTTPS</div>
            <p className="mt-1 text-xs leading-5 text-[#94A3B8]">
              درخواست‌های DNS مستقیم از سرور{' '}
              <span dir="ltr" className="font-mono text-[#CBD5E1]">
                {dashboard.settings.dohProvider}
              </span>{' '}
              از داخل پروکسی رد می‌شوند تا ISP ایران دامنه‌ها را نبیند.
            </p>
          </div>
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="text-xs font-semibold text-[#E6EDF3]">۲. مسدودسازی نشت WebRTC / STUN</div>
            <p className="mt-1 text-xs leading-5 text-[#94A3B8]">
              ترافیک STUN و پورت‌های 3478/19302 مسدود می‌شوند تا مرورگر و برنامه‌های صوتی نتوانند IP واقعی ایران را فاش کنند.
            </p>
          </div>
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="text-xs font-semibold text-[#E6EDF3]">۳. تکه‌سازی TLS (Anti-DPI)</div>
            <p className="mt-1 text-xs leading-5 text-[#94A3B8]">
              پکت‌های TLS Hello خرد می‌شوند تا سیستم فیلترینگ اپراتورهای ایران نتواند SNI{' '}
              <span dir="ltr" className="font-mono text-[#CBD5E1]">
                {dashboard.settings.domain}
              </span>{' '}
              را مسدود کند.
            </p>
          </div>
        </div>

        {mode === 'v2ray' && dashboard.tokens.length > 0 && (
          <div className="mt-5 flex flex-wrap items-center gap-3">
            <label htmlFor="xray-token-select" className="text-xs font-medium text-[#CBD5E1]">
              انتخاب توکن برای Xray Fragment:
            </label>
            <select
              id="xray-token-select"
              value={selectedToken?.id || ''}
              onChange={(e) => setSelectedTokenId(e.target.value)}
              className="h-9 rounded-lg border border-[#1E293B] bg-[#090D14] px-3 text-xs text-[#E6EDF3] focus:border-emerald-500 focus:outline-none"
            >
              {dashboard.tokens.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.protocol.toUpperCase()})
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
          <span className="text-xs text-[#94A3B8]">
            {mode === 'incy'
              ? 'فایل JSON کامل برای ایمپورت مستقیم در برنامه INCY یا کلاینت‌های Sing-box'
              : 'فایل JSON برای ایمپورت در v2rayN / v2rayNG (گزینه Import Custom Config)'}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleDownload}
              className="flex h-9 items-center gap-1.5 rounded-lg border border-[#1E293B] bg-[#090D14] px-3.5 text-xs font-medium text-[#CBD5E1] transition-colors hover:bg-[#1A2233] whitespace-nowrap shrink-0"
            >
              <Download className="h-3.5 w-3.5" />
              <span>دانلود فایل JSON</span>
            </button>
            <button
              type="button"
              onClick={handleCopy}
              className="flex h-9 items-center gap-1.5 rounded-lg bg-emerald-600 px-4 text-xs font-medium text-white transition-colors hover:bg-emerald-500 whitespace-nowrap shrink-0"
            >
              {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copied ? 'کپی شد' : 'کپی JSON'}</span>
            </button>
          </div>
        </div>

        <pre
          dir="ltr"
          className="mt-4 max-h-[480px] overflow-auto rounded-lg border border-[#1E293B] bg-[#090D14] p-4 font-mono text-xs leading-6 text-[#CBD5E1]"
        >
          <code>{configText}</code>
        </pre>
      </section>
    </div>
  );
}
