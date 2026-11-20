import { useState, type FormEvent } from 'react';
import { Eye, EyeOff, Lock } from 'lucide-react';
import { login } from '../lib/api.ts';

interface LoginViewProps {
  onSuccess: (username: string) => void;
}

export function LoginView({ onSuccess }: LoginViewProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError('نام کاربری و رمز عبور را وارد کنید.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await login(username.trim(), password);
      onSuccess(res.username);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'خطا در احراز هویت');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-[#090D14] px-4 py-8 text-[#E6EDF3]">
      <div className="w-full max-w-sm rounded-xl border border-[#1E293B] bg-[#111622] p-7">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-[#1E293B] bg-[#090D14] text-emerald-400">
            <Lock className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-[#E6EDF3]">ورود</h1>
            <p dir="ltr" className="mt-0.5 font-mono text-xs text-[#94A3B8]">
              Arashproxysystem.ir
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="mt-6 space-y-4" autoComplete="off">
          <div>
            <label
              htmlFor="login-username"
              className="block text-xs font-medium text-[#CBD5E1]"
            >
              نام کاربری
            </label>
            <input
              id="login-username"
              type="text"
              dir="ltr"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              required
              className="mt-2 h-11 w-full rounded-lg border border-[#1E293B] bg-[#090D14] px-3.5 font-mono text-sm text-[#E6EDF3] placeholder-[#475569] transition-colors focus:border-emerald-500 focus:outline-none"
            />
          </div>

          <div>
            <label
              htmlFor="login-password"
              className="block text-xs font-medium text-[#CBD5E1]"
            >
              رمز عبور
            </label>
            <div className="relative mt-2">
              <input
                id="login-password"
                type={showPassword ? 'text' : 'password'}
                dir="ltr"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                className="h-11 w-full rounded-lg border border-[#1E293B] bg-[#090D14] pl-11 pr-3.5 font-mono text-sm text-[#E6EDF3] placeholder-[#475569] transition-colors focus:border-emerald-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setShowPassword((prev) => !prev)}
                className="absolute left-2 top-1/2 flex h-8 w-8 -translate-y-1/2 items-center justify-center rounded-md text-[#94A3B8] transition-colors hover:text-[#E6EDF3]"
                aria-label={showPassword ? 'مخفی کردن رمز عبور' : 'نمایش رمز عبور'}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-lg border border-red-500/30 bg-red-500/10 px-3.5 py-2.5 text-xs leading-5 text-red-300"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="flex h-11 w-full items-center justify-center rounded-lg bg-emerald-600 px-5 text-sm font-semibold text-white transition-colors hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-60 focus-visible:outline-2 focus-visible:outline-emerald-400"
          >
            {loading ? 'در حال بررسی...' : 'ورود'}
          </button>
        </form>
      </div>
    </div>
  );
}
