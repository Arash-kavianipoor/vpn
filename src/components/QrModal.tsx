import { useEffect, useState } from 'react';
import QRCode from 'qrcode';
import { Check, Copy, X } from 'lucide-react';

interface QrModalProps {
  title: string;
  subtitle: string;
  value: string;
  onClose: () => void;
}

export function QrModal({ title, subtitle, value, onClose }: QrModalProps) {
  const [qrDataUrl, setQrDataUrl] = useState<string>('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let active = true;
    QRCode.toDataURL(value, {
      width: 280,
      margin: 2,
      color: {
        dark: '#090D14',
        light: '#FFFFFF',
      },
      errorCorrectionLevel: 'M',
    })
      .then((url) => {
        if (active) setQrDataUrl(url);
      })
      .catch(() => {
        if (active) setQrDataUrl('');
      });
    return () => {
      active = false;
    };
  }, [value]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Fallback ignored
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-labelledby="qr-modal-title"
    >
      <div className="w-full max-w-md rounded-xl border border-[#1E293B] bg-[#111622] p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h3 id="qr-modal-title" className="text-base font-semibold text-[#E6EDF3]">
              {title}
            </h3>
            <p className="mt-1 text-xs text-[#94A3B8]">{subtitle}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-[#1E293B] text-[#94A3B8] transition-colors hover:bg-[#1A2233] hover:text-[#E6EDF3] focus-visible:outline-2 focus-visible:outline-emerald-500"
            aria-label="بستن پنجره"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-6 flex flex-col items-center justify-center rounded-lg border border-[#1E293B] bg-[#090D14] p-5">
          {qrDataUrl ? (
            <img
              src={qrDataUrl}
              alt={`کد QR برای ${title}`}
              className="h-56 w-56 rounded-lg bg-white p-2"
              referrerPolicy="no-referrer"
            />
          ) : (
            <div className="flex h-56 w-56 items-center justify-center rounded-lg bg-[#111622] text-xs text-[#94A3B8]">
              در حال تولید کد QR...
            </div>
          )}
        </div>

        <div className="mt-4">
          <div
            dir="ltr"
            className="max-h-24 overflow-y-auto break-all rounded-lg border border-[#1E293B] bg-[#090D14] p-3 font-mono text-xs text-[#94A3B8]"
          >
            {value}
          </div>
        </div>

        <div className="mt-5 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="h-10 rounded-lg border border-[#1E293B] px-4 text-xs font-medium text-[#CBD5E1] transition-colors hover:bg-[#1A2233] whitespace-nowrap shrink-0"
          >
            بستن
          </button>
          <button
            type="button"
            onClick={handleCopy}
            className="flex h-10 items-center gap-2 rounded-lg bg-emerald-600 px-4 text-xs font-medium text-white transition-colors hover:bg-emerald-500 whitespace-nowrap shrink-0"
          >
            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            <span>{copied ? 'کپی شد' : 'کپی لینک اتصال'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
