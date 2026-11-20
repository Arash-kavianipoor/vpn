import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  CloudCog,
  FileCode2,
  KeyRound,
  LogOut,
  Menu,
  ShieldCheck,
  X,
} from 'lucide-react';
import { IncyV2RayExportPanel } from './components/IncyV2RayExportPanel.tsx';
import { LoginView } from './components/LoginView.tsx';
import { NetworkAuditPanel } from './components/NetworkAuditPanel.tsx';
import { SecurityHardeningPanel } from './components/SecurityHardeningPanel.tsx';
import { TokensPanel } from './components/TokensPanel.tsx';
import { WorkerDeployPanel } from './components/WorkerDeployPanel.tsx';
import { checkSession, fetchDashboard, getStoredToken, logout } from './lib/api.ts';
import type { DashboardState } from './types.ts';

type NavTab = 'tokens' | 'worker' | 'export' | 'network' | 'security';

const NAV_ITEMS: Array<{ id: NavTab; label: string; icon: typeof KeyRound }> = [
  { id: 'tokens', label: 'توکن‌های VLESS و V2Ray', icon: KeyRound },
  { id: 'worker', label: 'ورکر کلودفلر', icon: CloudCog },
  { id: 'export', label: 'خروجی INCY و Fragment', icon: FileCode2 },
  { id: 'network', label: 'آی‌پی تمیز و تست نشت', icon: Activity },
  { id: 'security', label: 'تنظیمات ضدنفوذ', icon: ShieldCheck },
];

export default function App() {
  const [authChecking, setAuthChecking] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);
  const [username, setUsername] = useState('Arash');
  const [dashboard, setDashboard] = useState<DashboardState | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<NavTab>('tokens');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const loadConsoleData = useCallback(async () => {
    setLoadError(null);
    try {
      const data = await fetchDashboard();
      setDashboard(data);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'خطا در دریافت اطلاعات سرور');
    }
  }, []);

  useEffect(() => {
    let mounted = true;
    const init = async () => {
      if (!getStoredToken()) {
        if (mounted) {
          setAuthenticated(false);
          setAuthChecking(false);
        }
        return;
      }
      const session = await checkSession();
      if (!mounted) return;
      if (session.authenticated) {
        setAuthenticated(true);
        setUsername(session.username || 'Arash');
        await loadConsoleData();
      } else {
        setAuthenticated(false);
      }
      setAuthChecking(false);
    };
    init();
    return () => {
      mounted = false;
    };
  }, [loadConsoleData]);

  const handleLoginSuccess = async (loggedUser: string) => {
    setUsername(loggedUser);
    setAuthenticated(true);
    await loadConsoleData();
  };

  const handleLogout = async () => {
    await logout();
    setAuthenticated(false);
    setDashboard(null);
  };

  if (authChecking) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#090D14] text-sm text-[#94A3B8]">
        در حال بررسی نشست امنیتی...
      </div>
    );
  }

  if (!authenticated) {
    return <LoginView onSuccess={handleLoginSuccess} />;
  }

  const activeNavLabel = NAV_ITEMS.find((item) => item.id === activeTab)?.label || '';
  const activeTokensCount = dashboard ? dashboard.tokens.filter((t) => t.enabled).length : 0;

  return (
    <div className="min-h-screen bg-[#090D14] text-[#E6EDF3] flex">
      {/* Desktop Sidebar */}
      <aside className="hidden w-[264px] shrink-0 flex-col border-l border-[#1E293B] bg-[#0B1019] lg:flex">
        <div className="border-b border-[#1E293B] px-6 py-5">
          <div dir="ltr" className="text-right font-mono text-base font-bold text-[#E6EDF3]">
            {dashboard?.settings.domain || 'Arashproxysystem.ir'}
          </div>
          <div className="mt-1 text-xs text-[#94A3B8]">
            کاربر مدیر: <span className="font-mono text-[#CBD5E1]">{username}</span>
          </div>
        </div>

        <nav className="flex-1 space-y-1 p-3" aria-label="منوی اصلی">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveTab(item.id)}
                className={`flex h-11 w-full items-center gap-3 rounded-lg px-3.5 text-xs font-medium transition-colors whitespace-nowrap ${
                  isActive
                    ? 'bg-[#161E2E] text-emerald-400'
                    : 'text-[#94A3B8] hover:bg-[#111622] hover:text-[#E6EDF3]'
                }`}
              >
                <Icon className="h-4 w-4 shrink-0" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="border-t border-[#1E293B] p-4 text-xs leading-5 text-[#64748B]">
          مخفی‌سازی کامل آی‌پی ایران از طریق شبکه کلودفلر و تونل DoH فعال است.
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          <div
            className="fixed inset-0 bg-black/70"
            onClick={() => setMobileMenuOpen(false)}
            aria-hidden="true"
          />
          <aside className="relative z-10 flex w-72 flex-col border-l border-[#1E293B] bg-[#0B1019]">
            <div className="flex items-center justify-between border-b border-[#1E293B] px-5 py-4">
              <span dir="ltr" className="font-mono text-sm font-bold text-[#E6EDF3]">
                {dashboard?.settings.domain || 'Arashproxysystem.ir'}
              </span>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#1E293B] text-[#94A3B8]"
                aria-label="بستن منو"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <nav className="flex-1 space-y-1 p-3">
              {NAV_ITEMS.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setActiveTab(item.id);
                      setMobileMenuOpen(false);
                    }}
                    className={`flex h-11 w-full items-center gap-3 rounded-lg px-3.5 text-xs font-medium transition-colors ${
                      isActive
                        ? 'bg-[#161E2E] text-emerald-400'
                        : 'text-[#94A3B8] hover:bg-[#111622] hover:text-[#E6EDF3]'
                    }`}
                  >
                    <Icon className="h-4 w-4 shrink-0" />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </nav>
          </aside>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Top Bar Contract: Context Breadcrumb + Single Primary Logout Action */}
        <header className="sticky top-0 z-30 border-b border-[#1E293B] bg-[#0B1019]/95 backdrop-blur-xs">
          <div className="mx-auto flex max-w-6xl items-center justify-between gap-8 px-6 py-3.5">
            <div className="flex min-w-0 items-center gap-3">
              <button
                type="button"
                onClick={() => setMobileMenuOpen(true)}
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-[#1E293B] text-[#CBD5E1] lg:hidden"
                aria-label="باز کردن منو"
              >
                <Menu className="h-4 w-4" />
              </button>
              <div className="flex items-center gap-2 text-xs sm:text-sm truncate">
                <span dir="ltr" className="font-mono font-semibold text-[#E6EDF3]">
                  {dashboard?.settings.domain || 'Arashproxysystem.ir'}
                </span>
                <span className="text-[#475569]">/</span>
                <span className="font-medium text-[#94A3B8] truncate">{activeNavLabel}</span>
              </div>
            </div>

            <button
              type="button"
              onClick={handleLogout}
              className="flex h-9 items-center gap-2 rounded-lg border border-[#1E293B] bg-[#111622] px-3.5 text-xs font-medium text-[#CBD5E1] transition-colors hover:border-red-500/40 hover:text-red-300 whitespace-nowrap shrink-0"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span>خروج امن</span>
            </button>
          </div>
        </header>

        <main className="mx-auto w-full max-w-6xl flex-1 px-6 py-6">
          {loadError ? (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-6 text-sm text-red-300">
              {loadError}
              <button
                type="button"
                onClick={loadConsoleData}
                className="mr-4 underline hover:text-white"
              >
                تلاش مجدد
              </button>
            </div>
          ) : !dashboard ? (
            <div className="space-y-4">
              <div className="h-24 rounded-xl border border-[#1E293B] bg-[#111622]" />
              <div className="h-64 rounded-xl border border-[#1E293B] bg-[#111622]" />
            </div>
          ) : (
            <div className="space-y-6">
              {/* Overview Metrics Strip */}
              <section
                aria-label="خلاصه وضعیت سامانه"
                className="grid grid-cols-1 gap-4 rounded-xl border border-[#1E293B] bg-[#111622] p-5 sm:grid-cols-2 lg:grid-cols-4"
              >
                <div>
                  <div className="text-xs text-[#94A3B8]">توکن‌های فعال V2Ray / INCY</div>
                  <div className="mt-1.5 font-mono tabular-nums text-lg font-semibold text-[#E6EDF3]">
                    {activeTokensCount} <span className="text-xs font-normal text-[#94A3B8]">از {dashboard.tokens.length}</span>
                  </div>
                </div>
                <div>
                  <div className="text-xs text-[#94A3B8]">دامنه و SNI ورکر</div>
                  <div dir="ltr" className="mt-1.5 text-right font-mono text-sm font-semibold text-emerald-400">
                    {dashboard.settings.domain}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-[#94A3B8]">رله مخفی‌ساز (PROXYIP)</div>
                  <div dir="ltr" className="mt-1.5 text-right font-mono tabular-nums text-sm font-semibold text-[#E6EDF3]">
                    {dashboard.settings.proxyIp}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-[#94A3B8]">سیاست نشت آی‌پی ایران</div>
                  <div className="mt-1.5 text-sm font-semibold text-emerald-400">
                    {dashboard.settings.strictIpMask && dashboard.settings.stripClientHeaders
                      ? 'مسدودسازی کامل نشت'
                      : 'حالت سفارشی'}
                  </div>
                </div>
              </section>

              {activeTab === 'tokens' && (
                <TokensPanel dashboard={dashboard} onUpdate={setDashboard} />
              )}
              {activeTab === 'worker' && (
                <WorkerDeployPanel dashboard={dashboard} onUpdate={setDashboard} />
              )}
              {activeTab === 'export' && <IncyV2RayExportPanel dashboard={dashboard} />}
              {activeTab === 'network' && (
                <NetworkAuditPanel dashboard={dashboard} onUpdate={setDashboard} />
              )}
              {activeTab === 'security' && (
                <SecurityHardeningPanel dashboard={dashboard} onUpdate={setDashboard} />
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
