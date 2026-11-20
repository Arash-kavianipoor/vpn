import { useEffect, useState } from 'react';
import { Check, Copy, Database, Download, RefreshCw } from 'lucide-react';
import { fetchD1Status, fetchWorkerScript, syncD1Database } from '../lib/api.ts';
import {
  buildCloudflareWorkerScript,
  buildD1SchemaSql,
  buildWranglerToml,
} from '../lib/proxyGenerators.ts';
import type { D1StatusResult, DashboardState } from '../types.ts';

interface WorkerDeployPanelProps {
  dashboard: DashboardState;
  onUpdate: (next: DashboardState) => void;
}

type CodeTab = 'worker' | 'wrangler' | 'schema';

export function WorkerDeployPanel({ dashboard, onUpdate }: WorkerDeployPanelProps) {
  const [activeCodeTab, setActiveCodeTab] = useState<CodeTab>('worker');
  const [workerScript, setWorkerScript] = useState(() =>
    buildCloudflareWorkerScript(dashboard.tokens, dashboard.settings)
  );
  const [copied, setCopied] = useState(false);
  const [syncing, setSyncing] = useState(false);

  const [d1Status, setD1Status] = useState<D1StatusResult | null>(null);
  const [checkingD1, setCheckingD1] = useState(false);
  const [syncingD1, setSyncingD1] = useState(false);
  const [d1Feedback, setD1Feedback] = useState<string | null>(null);
  const [d1Error, setD1Error] = useState<string | null>(null);

  useEffect(() => {
    setWorkerScript(buildCloudflareWorkerScript(dashboard.tokens, dashboard.settings));
  }, [dashboard.tokens, dashboard.settings]);

  useEffect(() => {
    let active = true;
    fetchD1Status()
      .then((res) => {
        if (active) setD1Status(res);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [dashboard.settings.d1DatabaseId]);

  const wranglerToml = buildWranglerToml(dashboard.settings);
  const schemaSql = buildD1SchemaSql(dashboard.tokens, dashboard.settings);

  const activeContent =
    activeCodeTab === 'worker'
      ? workerScript
      : activeCodeTab === 'wrangler'
        ? wranglerToml
        : schemaSql;

  const activeFilename =
    activeCodeTab === 'worker'
      ? 'worker/index.js'
      : activeCodeTab === 'wrangler'
        ? 'wrangler.toml'
        : 'schema.sql';

  const handleSyncFromServer = async () => {
    setSyncing(true);
    try {
      const res = await fetchWorkerScript();
      setWorkerScript(res.script);
      onUpdate(res.dashboard);
    } finally {
      setSyncing(false);
    }
  };

  const handleCheckD1 = async () => {
    setCheckingD1(true);
    setD1Error(null);
    setD1Feedback(null);
    try {
      const res = await fetchD1Status();
      setD1Status(res);
    } catch (err) {
      setD1Error(err instanceof Error ? err.message : 'خطا در بررسی وضعیت D1');
    } finally {
      setCheckingD1(false);
    }
  };

  const handleSyncD1 = async () => {
    setSyncingD1(true);
    setD1Error(null);
    setD1Feedback(null);
    try {
      const res = await syncD1Database();
      onUpdate(res.dashboard);
      setD1Feedback(
        `جداول و ${res.syncedTokens} توکن با موفقیت در دیتابیس کلودفلر D1 (${res.databaseId}) ذخیره شدند.`
      );
      const status = await fetchD1Status();
      setD1Status(status);
    } catch (err) {
      setD1Error(err instanceof Error ? err.message : 'خطا در همگام‌سازی D1');
    } finally {
      setSyncingD1(false);
    }
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(activeContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Ignore
    }
  };

  const handleDownload = () => {
    const blob = new Blob([activeContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = activeFilename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Cloudflare D1 Connection Panel */}
      <section className="rounded-xl border border-[#1E293B] bg-[#111622] p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-[#1E293B] bg-[#090D14] text-emerald-400">
              <Database className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-[#E6EDF3]">
                اتصال به دیتابیس کلودفلر (Cloudflare D1)
              </h2>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-[#94A3B8]">
                <span>Database ID:</span>
                <span dir="ltr" className="font-mono font-medium text-emerald-400">
                  {dashboard.settings.d1DatabaseId || 'a16983d7-1da3-4555-a1aa-f5730bccfcae'}
                </span>
                <span aria-hidden="true">·</span>
                <span>Binding:</span>
                <span dir="ltr" className="font-mono text-[#CBD5E1]">
                  DB
                </span>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleCheckD1}
              disabled={checkingD1}
              className="flex h-9 items-center gap-1.5 rounded-lg border border-[#1E293B] bg-[#090D14] px-3.5 text-xs font-medium text-[#CBD5E1] transition-colors hover:bg-[#1A2233] disabled:opacity-50 whitespace-nowrap shrink-0"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${checkingD1 ? 'animate-spin' : ''}`} />
              <span>بررسی اتصال D1</span>
            </button>
            <button
              type="button"
              onClick={handleSyncD1}
              disabled={syncingD1}
              className="flex h-9 items-center gap-1.5 rounded-lg bg-emerald-600 px-4 text-xs font-semibold text-white transition-colors hover:bg-emerald-500 disabled:opacity-50 whitespace-nowrap shrink-0"
            >
              <Database className="h-3.5 w-3.5" />
              <span>{syncingD1 ? 'در حال همگام‌سازی...' : 'ساخت جداول و همگام‌سازی با D1'}</span>
            </button>
          </div>
        </div>

        {d1Status && (
          <div className="mt-4 rounded-lg border border-[#1E293B] bg-[#090D14] p-4 text-xs leading-6">
            <div className="flex flex-wrap items-center gap-3">
              <span
                className={`font-semibold ${
                  d1Status.connected ? 'text-emerald-400' : 'text-amber-400'
                }`}
              >
                {d1Status.connected ? 'متصل به کلودفلر D1' : 'آماده اتصال Worker Binding'}
              </span>
              {d1Status.tokenCountInD1 !== null && (
                <>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono tabular-nums text-[#CBD5E1]">
                    توکن‌های داخل D1: {d1Status.tokenCountInD1}
                  </span>
                </>
              )}
            </div>
            <p className="mt-1.5 text-[#94A3B8]">{d1Status.message}</p>
          </div>
        )}

        {d1Feedback && (
          <div className="mt-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2.5 text-xs text-emerald-300">
            {d1Feedback}
          </div>
        )}

        {d1Error && (
          <div className="mt-3 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2.5 text-xs text-red-300">
            {d1Error}
          </div>
        )}
      </section>

      {/* Deployment Guide */}
      <section className="rounded-xl border border-[#1E293B] bg-[#111622] p-6">
        <h3 className="text-sm font-semibold text-[#E6EDF3]">
          راه‌اندازی روی دامنه{' '}
          <span dir="ltr" className="font-mono text-emerald-400">
            {dashboard.settings.domain}
          </span>{' '}
          و رفع خطای لینک اشتراک (<span className="font-mono">/sub/</span>)
        </h3>
        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-4">
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="font-mono text-xs font-semibold text-emerald-400">01</div>
            <div className="mt-2 text-xs font-semibold text-[#E6EDF3]">ساخت خودکار جداول D1</div>
            <p className="mt-1.5 text-xs leading-5 text-[#94A3B8]">
              ورکر <span className="font-mono text-[#CBD5E1]">worker/index.js</span> بدون نیاز به هاست جداگانه، جداول دیتابیس{' '}
              <span dir="ltr" className="font-mono text-[#CBD5E1]">a16983d7...</span> را خودکار می‌سازد.
            </p>
          </div>
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="font-mono text-xs font-semibold text-emerald-400">02</div>
            <div className="mt-2 text-xs font-semibold text-[#E6EDF3]">هماهنگی نام ورکر در wrangler.toml</div>
            <p className="mt-1.5 text-xs leading-5 text-[#94A3B8]">
              خط اول <span className="font-mono text-[#CBD5E1]">wrangler.toml</span> باید دقیقاً هم‌نام ورکر شما (مثلاً{' '}
              <span className="font-mono text-[#CBD5E1]">vpn</span>) و اتصال D1 با نام{' '}
              <span className="font-mono text-[#CBD5E1]">DB</span> فعال باشد.
            </p>
          </div>
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="font-mono text-xs font-semibold text-emerald-400">03</div>
            <div className="mt-2 text-xs font-semibold text-[#E6EDF3]">اتصال Custom Domain بدون هاست</div>
            <p className="mt-1.5 text-xs leading-5 text-[#94A3B8]">
              در تنظیمات ورکر فعال بخش Domains &amp; Routes دامنه{' '}
              <span dir="ltr" className="font-mono text-[#CBD5E1]">{dashboard.settings.domain}</span>{' '}
              را به‌عنوان Custom Domain ثبت کنید تا Error 522/523 برطرف شود.
            </p>
          </div>
          <div className="rounded-lg border border-[#1E293B] bg-[#090D14] p-4">
            <div className="font-mono text-xs font-semibold text-emerald-400">04</div>
            <div className="mt-2 text-xs font-semibold text-[#E6EDF3]">تنظیم PROXYIP</div>
            <p className="mt-1.5 text-xs leading-5 text-[#94A3B8]">
              متغیر محیطی <span className="font-mono text-[#CBD5E1]">PROXYIP</span> برابر{' '}
              <span dir="ltr" className="font-mono text-[#CBD5E1]">{dashboard.settings.proxyIp}</span>{' '}
              تنظیم شده است تا IP ایران مخفی بماند.
            </p>
          </div>
        </div>
      </section>

      {/* Tabbed Source Code Viewer */}
      <section className="rounded-xl border border-[#1E293B] bg-[#111622] p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-1 rounded-lg border border-[#1E293B] bg-[#090D14] p-1">
            {(
              [
                { id: 'worker', label: 'worker/index.js (Full-Stack + /sub)' },
                { id: 'wrangler', label: 'wrangler.toml (D1 + Assets)' },
                { id: 'schema', label: 'schema.sql (جداول D1)' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveCodeTab(tab.id)}
                className={`rounded-md px-3 py-1.5 font-mono text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  activeCodeTab === tab.id
                    ? 'bg-[#1E293B] text-[#E6EDF3]'
                    : 'text-[#94A3B8] hover:text-[#E6EDF3]'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {activeCodeTab === 'worker' && (
              <button
                type="button"
                onClick={handleSyncFromServer}
                disabled={syncing}
                className="flex h-9 items-center gap-1.5 rounded-lg border border-[#1E293B] bg-[#090D14] px-3 text-xs font-medium text-[#CBD5E1] transition-colors hover:bg-[#1A2233] whitespace-nowrap shrink-0"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${syncing ? 'animate-spin' : ''}`} />
                <span>به‌روزرسانی کد</span>
              </button>
            )}
            <button
              type="button"
              onClick={handleDownload}
              className="flex h-9 items-center gap-1.5 rounded-lg border border-[#1E293B] bg-[#090D14] px-3 text-xs font-medium text-[#CBD5E1] transition-colors hover:bg-[#1A2233] whitespace-nowrap shrink-0"
            >
              <Download className="h-3.5 w-3.5" />
              <span>دانلود {activeFilename}</span>
            </button>
            <button
              type="button"
              onClick={handleCopy}
              className="flex h-9 items-center gap-1.5 rounded-lg bg-emerald-600 px-4 text-xs font-medium text-white transition-colors hover:bg-emerald-500 whitespace-nowrap shrink-0"
            >
              {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copied ? 'کپی شد' : 'کپی کد'}</span>
            </button>
          </div>
        </div>

        <pre
          dir="ltr"
          className="mt-4 max-h-[500px] overflow-auto rounded-lg border border-[#1E293B] bg-[#090D14] p-4 font-mono text-xs leading-6 text-[#CBD5E1]"
        >
          <code>{activeContent}</code>
        </pre>
      </section>
    </div>
  );
}
