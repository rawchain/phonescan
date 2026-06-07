"use client";

import { useState, useCallback, useRef, useEffect } from "react";
import dynamic from "next/dynamic";
import type { LookupResult, IpLookupResult, EmailLookupResult, UsernameResult, UrlScanResult, Mode, Depth, RiskLevel } from "@/lib/phone";
import { REPORT_CATEGORIES } from "@/lib/reportCategories";

const IpMap    = dynamic(() => import("@/components/IpMap"),    { ssr: false });
const PhoneMap = dynamic(() => import("@/components/PhoneMap"), { ssr: false });

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const EXAMPLE_NUMBERS = [
  { label: "+1 (800) 275-2273", number: "+18002752273", note: "Apple Support" },
  { label: "+44 20 7946 0958", number: "+442079460958", note: "UK landline" },
  { label: "+1 (900) 555-0199", number: "+19005550199", note: "Premium-rate" },
  { label: "+61 1800 080 267", number: "+61180008026", note: "AU toll-free" },
  { label: "+49 30 12345678", number: "+493012345678", note: "Berlin" },
];

const EXAMPLE_IPS = [
  { label: "8.8.8.8",    note: "Google DNS"      },
  { label: "1.1.1.1",    note: "Cloudflare DNS"  },
  { label: "google.com", note: "Google"           },
  { label: "github.com", note: "GitHub"           },
];

const MODES: { id: TabId; label: string; placeholder: string }[] = [
  { id: "consumer", label: "📞 SCAM CHECK",   placeholder: "+1 555 123 4567  or  +44 7700 900000" },
  { id: "blue",     label: "📞 PHONE",        placeholder: "+1 800 555 0199  or  +49 30 12345678" },
  { id: "red",      label: "🌐 IP LOOKUP",    placeholder: "IP address or domain (e.g. 8.8.8.8)" },
  { id: "email",    label: "✉️ EMAIL",        placeholder: "user@example.com" },
  { id: "username", label: "🔍 USERNAME",     placeholder: "@username  (letters, numbers, _ - .)" },
  { id: "urlscan",  label: "🔗 URL SCAN",     placeholder: "https://example.com/path?query=1" },
];

const EXAMPLE_EMAILS = [
  { label: "test@gmail.com",       note: "Free provider" },
  { label: "info@apple.com",       note: "Corporate" },
  { label: "user@mailinator.com",  note: "Disposable" },
];

const EXAMPLE_USERNAMES = [
  { label: "torvalds",    note: "Linus Torvalds" },
  { label: "sama",        note: "Sam Altman" },
  { label: "rawchain",    note: "PhoneScan creator" },
];

const EXAMPLE_URLS = [
  { label: "https://google.com",          note: "Legitimate" },
  { label: "https://bit.ly/3example",     note: "Shortened" },
  { label: "http://malware.testing.gov",  note: "Safe test" },
];

const DEPTHS: { id: Depth; label: string }[] = [
  { id: "quick",    label: "QUICK"      },
  { id: "standard", label: "STANDARD"   },
  { id: "deep",     label: "DEEP OSINT" },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Tab type extends Mode with additional lookup types
type TabId = Mode | "email" | "username" | "urlscan";

type AnyResult = LookupResult | IpLookupResult | EmailLookupResult | UsernameResult | UrlScanResult;
type HistoryEntry = AnyResult & { queriedAt: string };

interface ReportSummary {
  count: number;
  categories: Array<{ name: string; count: number }>;
  latest: string | null;
}

// ---------------------------------------------------------------------------
// localStorage helpers — safe in SSR / try-catch guarded
// ---------------------------------------------------------------------------

const HISTORY_KEY = "phonescan_history";

function loadHistory(): HistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? (JSON.parse(raw) as HistoryEntry[]) : [];
  } catch { return []; }
}

function saveHistory(entries: HistoryEntry[]): void {
  if (typeof window === "undefined") return;
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(entries)); } catch {}
}

function clearHistory(): void {
  if (typeof window === "undefined") return;
  try { localStorage.removeItem(HISTORY_KEY); } catch {}
}

type FlagSeverity = "danger" | "warning" | "safe" | "info";

const DANGER_WORDS = [
  "scam","fraud","malicious","reported","dangerous","illegal",
  "phishing","vishing","smishing","blacklist","blacklisted",
  "criminal","threatening","extortion","impersonat","tor","malware",
];
const WARNING_WORDS = [
  "premium","voip","unknown","unverified","spoofable","caution",
  "potential","risk","suspicious","unconfirmed","questionable",
  "unusual","offshore","anonymous","untraceable","vpn","proxy","hosting","datacenter",
];

function classifyFlag(flag: string): FlagSeverity {
  const lower = flag.toLowerCase();
  if (DANGER_WORDS.some(w => lower.includes(w)))  return "danger";
  if (WARNING_WORDS.some(w => lower.includes(w))) return "warning";
  return "safe";
}

const FLAG_CONFIG: Record<FlagSeverity, { icon: string; cls: string; labelCls: string; label: string }> = {
  danger:  { icon: "🔴", cls: "border-[rgba(255,60,90,0.2)]  bg-[rgba(255,60,90,0.06)]",    labelCls: "text-[#ff3c5a]", label: "DANGER"  },
  warning: { icon: "🟡", cls: "border-[rgba(255,184,0,0.2)]  bg-[rgba(255,184,0,0.06)]",    labelCls: "text-[#ffb800]", label: "WARNING" },
  safe:    { icon: "🟢", cls: "border-[rgba(0,255,136,0.15)] bg-[rgba(0,255,136,0.04)]",    labelCls: "text-[#00ff88]", label: "SAFE"    },
  info:    { icon: "ℹ️",  cls: "border-[rgba(100,150,255,0.2)] bg-[rgba(100,150,255,0.05)]", labelCls: "text-[#6496ff]", label: "INFO"    },
};

function riskColour(risk: RiskLevel) {
  switch (risk) {
    case "High":   return { text: "text-[#ff3c5a]", border: "border-[rgba(255,60,90,0.4)]",   bg: "bg-[rgba(255,60,90,0.08)]",   icon: "🚨", label: "HIGH RISK"    };
    case "Medium": return { text: "text-[#ffb800]", border: "border-[rgba(255,184,0,0.4)]",   bg: "bg-[rgba(255,184,0,0.08)]",   icon: "⚠️", label: "MEDIUM RISK"  };
    case "Low":    return { text: "text-[#00ff88]", border: "border-[rgba(0,255,136,0.3)]",   bg: "bg-[rgba(0,255,136,0.06)]",   icon: "✅", label: "LOW RISK"     };
    default:       return { text: "text-[#6496ff]", border: "border-[rgba(100,150,255,0.3)]", bg: "bg-[rgba(100,150,255,0.06)]", icon: "❓", label: "UNKNOWN RISK" };
  }
}

function flagEmoji(countryCode: string | null): string {
  if (!countryCode || countryCode.length !== 2) return "🌐";
  return countryCode
    .toUpperCase()
    .split("")
    .map(c => String.fromCodePoint(0x1f1e0 + c.charCodeAt(0) - 65))
    .join("");
}

function isValidIpOrDomain(s: string): boolean {
  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) return true;
  // IPv6
  if (/^[0-9a-fA-F:]{2,45}$/.test(s)) return true;
  // Domain — letters, digits, dots, hyphens, at least one char
  if (/^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,252}[a-zA-Z0-9]$/.test(s)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Shared micro-components
// ---------------------------------------------------------------------------

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="font-mono text-[10px] tracking-[3px] text-[var(--muted)] mb-2.5 uppercase">
      {"// "}{children}
    </div>
  );
}

function InfoCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-[#070910] border border-[var(--border)] rounded-sm px-3.5 py-3 overflow-hidden">
      <div className="font-mono text-[10px] tracking-[2px] text-[var(--muted)] mb-1.5 uppercase">{label}</div>
      <div className="font-head font-semibold text-[15px] text-white truncate leading-tight" title={value}>{value}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Copy / Share
// ---------------------------------------------------------------------------

function useCopyButton(getText: () => string) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const copy = useCallback(() => {
    navigator.clipboard.writeText(getText()).then(() => {
      setCopied(true);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 2000);
    });
  }, [getText]);
  return { copied, copy };
}

function CopyBtn({ label, getText }: { label: string; getText: () => string }) {
  const { copied, copy } = useCopyButton(getText);
  return (
    <button
      onClick={copy}
      className={`font-mono text-[11px] tracking-[2px] px-3 py-1.5 border rounded-sm transition-all duration-150 ${
        copied
          ? "border-[var(--accent)] text-[var(--accent)]"
          : "border-[var(--border)] text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
      }`}
    >
      {copied ? "✓ COPIED" : label}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Analysis expander
// ---------------------------------------------------------------------------

function AnalysisExpander({ text }: { text: string }) {
  const [open, setOpen] = useState(false);
  const ref  = useRef<HTMLDivElement>(null);
  const [h, setH] = useState(0);

  useEffect(() => {
    if (ref.current) setH(ref.current.scrollHeight);
  }, [text]);

  const clean = text.replace(/\{[^}]*"risk"[^}]*\}\s*$/, "").trim();
  const paras = clean.split(/\n{2,}/).map(p => p.replace(/\n/g, " ").trim()).filter(Boolean);

  // Strip markdown from a string (headings, bold, italic, inline code)
  function stripMd(s: string): string {
    return s
      .replace(/^#{1,6}\s+/g, "")
      .replace(/\*\*([^*]+)\*\*/g, "$1")
      .replace(/\*([^*]+)\*/g, "$1")
      .replace(/`([^`]+)`/g, "$1")
      .trim();
  }

  // Find first paragraph that isn't a heading line, clean it, take first sentence
  const rawPreview = paras.find(p => !/^#{1,6}\s/.test(p)) ?? paras[0] ?? clean;
  const cleanPreview = stripMd(rawPreview);
  const preview = cleanPreview.match(/^[^.!?]+[.!?]/)?.[0]?.trim() ?? cleanPreview.slice(0, 120);

  return (
    <div className="border border-[var(--border)] rounded-sm overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-4 py-3 bg-[#070910] hover:bg-[#0d1117] transition-colors text-left"
      >
        <span className="font-mono text-[11px] tracking-[2px] text-[var(--accent)] flex items-center gap-2">
          <span className={`transition-transform duration-300 inline-block ${open ? "rotate-90" : ""}`}>▶</span>
          {"// FULL AI ANALYSIS"}
        </span>
        <span className="font-mono text-[10px] text-[var(--muted)]">
          {open ? "COLLAPSE" : `${paras.length} SECTION${paras.length !== 1 ? "S" : ""}`}
        </span>
      </button>

      {!open && (
        <div className="relative px-4 py-2.5 bg-[var(--surface)]">
          <p className="font-mono text-[11px] text-[var(--muted)] truncate pr-8 leading-relaxed">{preview}</p>
          <div className="absolute inset-y-0 right-0 w-12 bg-gradient-to-l from-[#0f1318] to-transparent pointer-events-none" />
        </div>
      )}

      <div style={{ height: open ? h : 0, transition: "height 280ms cubic-bezier(0.4,0,0.2,1)", overflow: "hidden" }}>
        <div ref={ref} className="px-4 py-4 bg-[var(--surface)] space-y-3 border-t border-[var(--border)]">
          {paras.map((p, i) => (
            <p key={i} className="font-mono text-[12px] text-[var(--text)] leading-relaxed">{p}</p>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Flags list (shared)
// ---------------------------------------------------------------------------

function FlagsList({ flags }: { flags: string[] }) {
  if (flags.length === 0) return null;
  return (
    <div>
      <SectionLabel>RISK INDICATORS</SectionLabel>
      <div className="flex flex-col gap-1.5">
        {flags.map((flag, i) => {
          const sev = classifyFlag(flag);
          const cfg = FLAG_CONFIG[sev];
          return (
            <div
              key={i}
              className={`flex items-start gap-3 px-3.5 py-2.5 border rounded-sm text-[14px] font-head leading-snug ${cfg.cls}`}
            >
              <span className="shrink-0 text-base leading-none mt-px">{cfg.icon}</span>
              <span className="flex-1 min-w-0 text-[var(--text)]">{flag}</span>
              <span className={`shrink-0 font-mono text-[9px] tracking-[2px] self-center ${cfg.labelCls}`}>
                {cfg.label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Score bar (shared between phone + IP result cards)
// ---------------------------------------------------------------------------

function ScoreBar({ label, score, lowGood }: { label: string; score: number | null; lowGood?: boolean }) {
  if (score === null) return null;
  const pct = Math.min(100, Math.max(0, score));
  const colour = lowGood
    ? (pct <= 20 ? "#00ff41" : pct <= 60 ? "#ffb800" : "#ff3c5a")
    : (pct >= 61 ? "#ff3c5a" : pct >= 31 ? "#ffb800" : "#00ff41");
  return (
    <div>
      <div className="flex justify-between mb-1.5">
        <span className="font-mono text-[10px] tracking-[2px] text-[var(--muted)] uppercase">{label}</span>
        <span className="font-mono text-[11px] tracking-[1px]" style={{ color: colour }}>{score}/100</span>
      </div>
      <div className="h-[6px] bg-[#070910] rounded-full border border-[var(--border)] overflow-hidden">
        <div className="h-full rounded-full transition-all duration-700"
          style={{ width: `${pct}%`, background: colour, boxShadow: `0 0 6px ${colour}` }} />
      </div>
      <div className="flex justify-between mt-1">
        <span className="font-mono text-[9px] text-[var(--muted)]">CLEAN</span>
        <span className="font-mono text-[9px] text-[var(--muted)]">MALICIOUS</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Phone result card
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Community report form
// ---------------------------------------------------------------------------

function ReportForm({
  number,
  onSuccess,
  onCancel,
  initialCategory,
}: {
  number: string;
  onSuccess: (category: string, newTotal: number) => void;
  onCancel: () => void;
  initialCategory?: string;
}) {
  const [category, setCategory] = useState(initialCategory ?? "");
  const [comment,  setComment]  = useState("");
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState<string | null>(null);

  async function submit() {
    if (!category) { setError("Please select a category."); return; }
    setLoading(true); setError(null);
    try {
      const res = await fetch("/api/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ number, category, comment }),
      });
      const data = await res.json() as { error?: string; total_reports?: number };
      if (!res.ok) { setError(data.error ?? "Failed to submit."); return; }
      onSuccess(category, data.total_reports ?? 0);
    } catch {
      setError("Network error — please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="border border-[rgba(255,184,0,0.25)] bg-[rgba(255,184,0,0.04)] rounded-sm px-4 py-4 space-y-3">
      <div className="font-mono text-[10px] tracking-[3px] text-[#ffb800]">{"// REPORT THIS NUMBER"}</div>

      {/* Category */}
      <div>
        <select
          value={category}
          onChange={e => setCategory(e.target.value)}
          className="w-full bg-[#070910] border border-[var(--border)] rounded-sm font-mono text-[12px] text-white px-3 py-2 outline-none"
          style={{ appearance: "none" }}
        >
          <option value="">Select category…</option>
          {REPORT_CATEGORIES.map(c => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
      </div>

      {/* Comment */}
      <textarea
        value={comment}
        onChange={e => setComment(e.target.value.slice(0, 200))}
        placeholder="Optional comment (max 200 chars)…"
        rows={2}
        className="w-full bg-[#070910] border border-[var(--border)] rounded-sm font-mono text-[12px] text-white px-3 py-2 outline-none resize-none placeholder:text-[var(--muted)]"
      />
      <div className="font-mono text-[9px] text-[var(--muted)] text-right">{comment.length}/200</div>

      {error && (
        <div className="font-mono text-[11px] text-[#ff3c5a]">⚠ {error}</div>
      )}

      <div className="flex gap-2">
        <button
          onClick={submit}
          disabled={loading || !category}
          className="font-head font-bold text-[12px] tracking-[2px] px-4 py-2 rounded-sm text-black disabled:opacity-40 transition-all"
          style={{ background: "var(--accent)" }}
        >
          {loading ? "SUBMITTING…" : "SUBMIT REPORT"}
        </button>
        <button
          onClick={onCancel}
          className="font-mono text-[11px] tracking-[2px] px-4 py-2 border border-[var(--border)] rounded-sm text-[var(--muted)] hover:text-white transition-all"
        >
          CANCEL
        </button>
      </div>
    </div>
  );
}

const HIGH_RISK_VOIP_CARRIERS = ["Google", "Twilio", "Bandwidth", "Vonage", "Telnyx", "Skype", "TextNow"];

function getLocalTime(timezone: string): { time: string; isOddHours: boolean } {
  try {
    const fmt = new Intl.DateTimeFormat("en-US", {
      timeZone: timezone,
      hour: "numeric",
      minute: "2-digit",
      hour12: true,
    });
    const timeStr = fmt.format(new Date());
    const hourFmt = new Intl.DateTimeFormat("en-US", { timeZone: timezone, hour: "numeric", hour12: false });
    const hour = parseInt(hourFmt.format(new Date()), 10);
    // Odd hours = 9pm (21) to 7am (6)
    const isOddHours = hour >= 21 || hour < 7;
    return { time: timeStr, isOddHours };
  } catch {
    return { time: "—", isOddHours: false };
  }
}

function ResultCard({ result }: { result: LookupResult }) {
  const displayNum    = result.parsed.internationalFormat ?? result.parsed.raw;
  const cleanAnalysis = result.raw.replace(/\{[^}]*"risk"[^}]*\}\s*$/, "").trim();
  const rc = riskColour(result.risk);

  const lineType  = result.line_type_verified ?? result.parsed.type;
  const isVoip    = lineType === "voip";
  const carrier   = result.carrier ?? null;
  const isHighRiskVoip = isVoip && carrier
    ? HIGH_RISK_VOIP_CARRIERS.some(v => carrier.toLowerCase().includes(v.toLowerCase()))
    : false;
  const isInvalid = result.number_valid === false;

  // Local time in caller's timezone
  const localTime = result.caller_timezone ? getLocalTime(result.caller_timezone) : null;

  // Community reports state
  const [community,    setCommunity]   = useState<ReportSummary | null>(null);
  const [showForm,     setShowForm]    = useState(false);
  const [submitMsg,    setSubmitMsg]   = useState<string | null>(null);

  const lookupNumber = result.parsed.e164 ?? result.parsed.raw;

  useEffect(() => {
    if (!lookupNumber) return;
    fetch(`/api/report?number=${encodeURIComponent(lookupNumber)}`)
      .then(r => r.json())
      .then((d: ReportSummary) => setCommunity(d))
      .catch(() => {});
  }, [lookupNumber]);

  function handleReportSuccess(category: string, newTotal: number) {
    setShowForm(false);
    setSubmitMsg(`✓ Reported as ${category} — thank you`);
    // Update community count optimistically
    setCommunity(prev => {
      if (!prev) return { count: newTotal, categories: [{ name: category, count: 1 }], latest: new Date().toISOString() };
      const existing = prev.categories.find(c => c.name === category);
      const updated = existing
        ? prev.categories.map(c => c.name === category ? { ...c, count: c.count + 1 } : c)
        : [...prev.categories, { name: category, count: 1 }];
      return { count: newTotal, categories: updated.sort((a, b) => b.count - a.count), latest: new Date().toISOString() };
    });
    setTimeout(() => setSubmitMsg(null), 3000);
  }

  const getReport = useCallback(() =>
    ["PhoneScan Report", `${displayNum} — ${result.risk} Risk`, result.summary, "",
     "Findings:", ...result.flags.map(f => `• ${f}`), "", "Analysis:", cleanAnalysis].join("\n"),
    [result] // eslint-disable-line react-hooks/exhaustive-deps
  );
  const getShare = useCallback(() => {
    const q = encodeURIComponent(result.parsed.e164 ?? result.parsed.raw);
    return `https://phonescan-gamma.vercel.app/?q=${q}&mode=${result.mode}`;
  },
    [result] // eslint-disable-line react-hooks/exhaustive-deps
  );

  const metaItems = [
    { label: "NUMBER",     value: displayNum },
    { label: "COUNTRY",    value: result.parsed.region ?? "—" },
    { label: "CODE",       value: result.parsed.country ?? "—" },
    { label: "LINE TYPE",  value: lineType.toUpperCase() },
    { label: "CARRIER",    value: carrier ?? "Unknown" },
    { label: "LOCATION",   value: result.number_location || result.parsed.region || "—" },
    { label: "LOCAL TIME", value: localTime?.time ?? "—" },
    { label: "E.164",      value: result.parsed.e164 ?? "—" },
    { label: "VALID",      value: (result.number_valid ?? result.parsed.valid) ? "YES ✓" : "NO ✗" },
    { label: "DEPTH",      value: result.depth.toUpperCase() },
    { label: "MODE",       value: result.mode.toUpperCase() },
  ];

  return (
    <div className="border border-[var(--border)] rounded-sm bg-[var(--surface)] overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-[var(--border)]">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="font-mono text-[10px] tracking-[3px] text-[var(--muted)] mb-1.5">
              ANALYSIS COMPLETE
              <span className="ml-2 px-1.5 py-0.5 border border-[var(--border)] rounded-sm text-[9px]">libphonenumber · numverify · groq</span>
              {/* Community report badge */}
              {community !== null && community.count > 0 && (
                <span
                  className="ml-2 px-1.5 py-0.5 border rounded-sm text-[9px] tracking-[1px]"
                  style={{ borderColor: "rgba(255,184,0,0.4)", background: "rgba(255,184,0,0.08)", color: "#ffb800" }}
                >
                  🚩 {community.count} community {community.count === 1 ? "report" : "reports"}
                </span>
              )}
            </div>
            <div className="font-mono text-xl tracking-[2px] break-all" style={{ color: "var(--accent)" }}>{displayNum}</div>
            {/* Carrier + VOIP badge */}
            {carrier && (
              <div className="flex items-center gap-2 mt-1 flex-wrap">
                <span
                  className="font-mono text-[12px]"
                  style={{ color: isHighRiskVoip ? "#ff3c5a" : isVoip ? "#ffb800" : "var(--muted)" }}
                >
                  {carrier}
                </span>
                {isHighRiskVoip && (
                  <span
                    className="font-mono text-[9px] tracking-[2px] px-2 py-0.5 border rounded-sm"
                    style={{ borderColor: "rgba(255,60,90,0.4)", background: "rgba(255,60,90,0.1)", color: "#ff3c5a" }}
                  >
                    ⚠ HIGH RISK VOIP
                  </span>
                )}
                {isVoip && !isHighRiskVoip && (
                  <span
                    className="font-mono text-[9px] tracking-[2px] px-2 py-0.5 border rounded-sm"
                    style={{ borderColor: "rgba(255,184,0,0.4)", background: "rgba(255,184,0,0.08)", color: "#ffb800" }}
                  >
                    ⚠️ VOIP
                  </span>
                )}
              </div>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0 mt-1">
            <CopyBtn label="COPY"     getText={getReport} />
            <CopyBtn label="🔗 LINK"  getText={getShare}  />
          </div>
        </div>
      </div>

      <div className="px-6 py-5 space-y-5">
        {/* Invalid number banner */}
        {isInvalid && (
          <div className="flex items-center gap-3 px-4 py-3 border border-[rgba(255,60,90,0.4)] bg-[rgba(255,60,90,0.08)] rounded-sm">
            <span className="text-xl leading-none">⚠️</span>
            <div>
              <div className="font-head font-bold tracking-[2px] text-[#ff3c5a] text-[15px]">INVALID NUMBER</div>
              <div className="font-head text-[13px] text-[var(--muted)] mt-0.5">
                NumVerify could not validate this number. It may be fictitious, unallocated, or incorrectly formatted.
              </div>
            </div>
          </div>
        )}

        {/* Risk banner */}
        <div className={`flex items-center gap-4 px-5 py-4 border rounded-sm ${rc.bg} ${rc.border}`}>
          <span className="text-3xl leading-none">{rc.icon}</span>
          <div>
            <div className={`font-head font-bold text-xl tracking-[2px] ${rc.text}`}>{rc.label}</div>
            <div className="font-head text-[14px] text-[var(--text)] mt-0.5 leading-snug">{result.summary}</div>
          </div>
        </div>

        {/* Confirmed spam banner */}
        {result.is_spam_confirmed && (
          <div className="flex items-center gap-3 px-4 py-3 border border-[rgba(255,60,90,0.4)] bg-[rgba(255,60,90,0.08)] rounded-sm">
            <span className="text-xl leading-none shrink-0">⚠️</span>
            <div>
              <div className="font-head font-bold tracking-[2px] text-[#ff3c5a] text-[15px]">CONFIRMED SPAM</div>
              <div className="font-head text-[13px] text-[var(--muted)] mt-0.5">
                This number has been confirmed as spam by community databases.
              </div>
            </div>
          </div>
        )}

        {/* Spam score bar */}
        {result.spam_score !== null && (
          <div className="bg-[#070910] border border-[var(--border)] rounded-sm px-4 py-4 space-y-3">
            <ScoreBar label="SPAM SCORE" score={result.spam_score} lowGood />
            <div className="flex flex-wrap gap-4">
              {result.external_reports != null && result.external_reports > 0 && (
                <span className="font-mono text-[10px] text-[var(--muted)]">
                  {result.external_reports} community {result.external_reports === 1 ? "report" : "reports"}
                </span>
              )}
              {result.last_reported && (
                <span className="font-mono text-[10px] text-[var(--muted)]">
                  Last reported: {new Date(result.last_reported).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
                </span>
              )}
            </div>
          </div>
        )}

        {/* Community flagged banner */}
        {community !== null && community.count >= 3 && (
          <div className="flex items-start gap-3 px-4 py-3 border border-[rgba(255,60,90,0.4)] bg-[rgba(255,60,90,0.07)] rounded-sm">
            <span className="text-xl leading-none shrink-0">⚠️</span>
            <div className="min-w-0">
              <div className="font-head font-bold tracking-[2px] text-[#ff3c5a] text-[14px]">COMMUNITY FLAGGED</div>
              <div className="flex flex-wrap gap-1.5 mt-1.5">
                {community.categories.map(c => (
                  <span
                    key={c.name}
                    className="font-mono text-[9px] tracking-[1px] px-2 py-0.5 border rounded-sm"
                    style={{ borderColor: "rgba(255,60,90,0.3)", background: "rgba(255,60,90,0.06)", color: "#ff3c5a" }}
                  >
                    {c.name} ×{c.count}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Community category pills (when flagged < 3) */}
        {community !== null && community.count > 0 && community.count < 3 && (
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px] text-[var(--muted)]">COMMUNITY:</span>
            {community.categories.map(c => (
              <span
                key={c.name}
                className="font-mono text-[9px] tracking-[1px] px-2 py-0.5 border rounded-sm"
                style={{ borderColor: "rgba(255,184,0,0.3)", background: "rgba(255,184,0,0.06)", color: "#ffb800" }}
              >
                {c.name} ×{c.count}
              </span>
            ))}
          </div>
        )}

        {/* Meta grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {metaItems.map(({ label, value }) =>
            label === "LOCAL TIME" && localTime ? (
              <div key="LOCAL TIME" className="bg-[#070910] border border-[var(--border)] rounded-sm px-3.5 py-3 overflow-hidden">
                <div className="font-mono text-[10px] tracking-[2px] text-[var(--muted)] mb-1.5 uppercase">LOCAL TIME</div>
                <div className="font-head font-semibold text-[15px] text-white truncate leading-tight">{localTime.time}</div>
                {localTime.isOddHours && (
                  <span
                    className="font-mono text-[8px] tracking-[1px] px-1.5 py-0.5 border rounded-sm mt-1 inline-block"
                    style={{ borderColor: "rgba(255,184,0,0.4)", background: "rgba(255,184,0,0.08)", color: "#ffb800" }}
                  >
                    🌙 Odd hours
                  </span>
                )}
              </div>
            ) : label === "CARRIER" ? (
              <div key="CARRIER" className="bg-[#070910] border border-[var(--border)] rounded-sm px-3.5 py-3 overflow-hidden">
                <div className="font-mono text-[10px] tracking-[2px] text-[var(--muted)] mb-1.5 uppercase">CARRIER</div>
                <div className="font-head font-semibold text-[15px] text-white truncate leading-tight" title={value}>
                  {value}
                </div>
                {(isVoip || isHighRiskVoip) && (
                  <span
                    className="font-mono text-[8px] tracking-[1px] px-1.5 py-0.5 border rounded-sm mt-1 inline-block"
                    style={isHighRiskVoip
                      ? { borderColor: "rgba(255,60,90,0.4)", background: "rgba(255,60,90,0.1)", color: "#ff3c5a" }
                      : { borderColor: "rgba(255,184,0,0.4)", background: "rgba(255,184,0,0.08)", color: "#ffb800" }}
                  >
                    {isHighRiskVoip ? "⚠ HIGH RISK VOIP" : "⚠️ VOIP"}
                  </span>
                )}
              </div>
            ) : (
              <InfoCell key={label} label={label} value={value} />
            )
          )}
        </div>

        <FlagsList flags={result.flags} />

        {/* Approximate region map */}
        {(result.number_location || result.parsed.region) && (
          <div>
            <SectionLabel>APPROXIMATE REGION</SectionLabel>
            <div className="rounded-sm overflow-hidden border border-[var(--border)]">
              <PhoneMap location={result.number_location || result.parsed.region!} />
            </div>
          </div>
        )}

        <div>
          <SectionLabel>AI INTELLIGENCE REPORT</SectionLabel>
          <AnalysisExpander text={result.raw} />
        </div>

        {/* Report this number */}
        {submitMsg ? (
          <div className="font-mono text-[12px] text-[#00ff88] opacity-80">{submitMsg}</div>
        ) : showForm ? (
          <ReportForm
            number={lookupNumber}
            onSuccess={handleReportSuccess}
            onCancel={() => setShowForm(false)}
            initialCategory={result.is_spam_confirmed ? "Scam Call" : undefined}
          />
        ) : (
          <button
            onClick={() => setShowForm(true)}
            className="font-mono text-[11px] tracking-[2px] text-[var(--muted)] hover:text-[#ffb800] transition-colors"
          >
            🚩 Report this number
          </button>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// IP result card
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Abuse reports
// ---------------------------------------------------------------------------

interface AbuseReport {
  reportedAt: string;
  comment: string;
  categories: string[];
  reporterCountryCode: string;
}

function AbuseReports({ reports }: { reports: AbuseReport[] }) {
  const [expanded, setExpanded] = useState(false);

  // "no reports" state — reports array exists but is empty (AbuseIPDB responded)
  if (reports.length === 0) {
    return (
      <div className="border border-[var(--border)] rounded-sm bg-[#070910] px-4 py-3">
        <span className="font-mono text-[10px] tracking-[3px] text-[#00ff88] opacity-70">
          {"// NO ABUSE REPORTS IN LAST 90 DAYS"}
        </span>
      </div>
    );
  }

  const visible = expanded ? reports : reports.slice(0, 5);

  return (
    <div>
      <SectionLabel>RECENT ABUSE REPORTS</SectionLabel>
      <div className="border border-[var(--border)] rounded-sm overflow-hidden divide-y divide-[var(--border)]">
        {visible.map((r, i) => {
          const date = new Date(r.reportedAt);
          const dateStr = date.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
          const flag = flagEmoji(r.reporterCountryCode);
          return (
            <div key={i} className="px-4 py-3 bg-[#070910] space-y-2">
              <div className="flex items-center gap-3 flex-wrap">
                <span className="font-mono text-[10px] text-[var(--muted)]">{dateStr}</span>
                <span className="text-sm leading-none">{flag}</span>
                {r.categories.map(cat => (
                  <span
                    key={cat}
                    className="font-mono text-[9px] tracking-[1px] px-2 py-0.5 border rounded-sm"
                    style={{ borderColor: "rgba(255,184,0,0.3)", background: "rgba(255,184,0,0.08)", color: "#ffb800" }}
                  >
                    {cat}
                  </span>
                ))}
              </div>
              <p className="font-mono text-[11px] text-[var(--text)] leading-relaxed">
                {r.comment
                  ? (r.comment.length > 80 ? r.comment.slice(0, 80) + "…" : r.comment)
                  : <span className="text-[var(--muted)]">No comment provided</span>
                }
              </p>
            </div>
          );
        })}
      </div>
      {reports.length > 5 && (
        <button
          onClick={() => setExpanded(v => !v)}
          className="font-mono text-[10px] tracking-[2px] text-[var(--accent)] opacity-60 hover:opacity-100 transition-opacity mt-2"
        >
          {expanded ? "← Show fewer" : `Show all ${reports.length} reports →`}
        </button>
      )}
    </div>
  );
}

function IndicatorPill({ label, active, colour }: { label: string; active: boolean; colour: string }) {
  return (
    <div
      className={`font-mono text-[10px] tracking-[2px] px-3 py-1.5 border rounded-sm transition-all ${active ? "" : "opacity-25"}`}
      style={active
        ? { borderColor: `${colour}55`, background: `${colour}12`, color: colour }
        : { borderColor: "var(--border)", color: "var(--muted)" }}
    >
      {active ? "● " : "○ "}{label}
    </div>
  );
}

const SAFE_INFRA_KEYWORDS = ["cloudflare", "google", "amazon", "microsoft", "apple", "fastly", "akamai"];

function isSafeInfraProvider(result: IpLookupResult): boolean {
  const haystack = [result.isp, result.org, result.whois_org].filter(Boolean).join(" ").toLowerCase();
  return SAFE_INFRA_KEYWORDS.some(k => haystack.includes(k));
}

function IpResultCard({ result }: { result: IpLookupResult }) {
  const rc = riskColour(result.risk);
  const flag = flagEmoji(result.countryCode);
  const locationStr = [result.city, result.region, result.country].filter(Boolean).join(", ") || "Unknown";
  const safeInfra = isSafeInfraProvider(result);
  const showVpn = result.is_vpn && !safeInfra;

  const getReport = useCallback(() =>
    [
      "PhoneScan IP Report",
      `${result.ip} — ${result.risk} Risk`,
      result.summary, "",
      `Location: ${locationStr}`,
      result.reverse_dns    ? `Reverse DNS: ${result.reverse_dns}` : null,
      result.isp            ? `ISP: ${result.isp}` : null,
      result.asn            ? `ASN: ${result.asn}` : null,
      result.whois_org      ? `WHOIS Org: ${result.whois_org}` : null,
      `VPN: ${result.is_vpn} | Proxy: ${result.is_proxy} | Tor: ${result.is_tor} | Hosting: ${result.is_hosting}`,
      result.abuse_confidence_score != null ? `AbuseIPDB: ${result.abuse_confidence_score}/100 (${result.abuse_total_reports} reports)` : null,
      result.threat_score !== null  ? `GetIPIntel Threat: ${result.threat_score}/100` : null,
      "", "Findings:", ...result.flags.map(f => `• ${f}`),
      "", "Analysis:", result.raw.replace(/\{[^}]*"risk"[^}]*\}\s*$/, "").trim(),
    ].filter(s => s !== null).join("\n"),
    [result] // eslint-disable-line react-hooks/exhaustive-deps
  );
  const getShare = useCallback(() => {
    const q = encodeURIComponent(result.original_input ?? result.ip);
    return `https://phonescan-gamma.vercel.app/?q=${q}&mode=red`;
  },
    [result] // eslint-disable-line react-hooks/exhaustive-deps
  );

  const metaItems = [
    { label: "IP ADDRESS",    value: result.ip },
    { label: "COUNTRY",       value: result.country ?? "—" },
    { label: "CITY",          value: result.city ?? "—" },
    { label: "REGION",        value: result.region ?? "—" },
    { label: "ISP",           value: result.isp ?? "—" },
    { label: "ASN",           value: result.asn ?? "—" },
    { label: "WHOIS ORG",     value: result.whois_org ?? "—" },
    { label: "NETWORK",       value: result.whois_network_name ?? "—" },
    { label: "TIMEZONE",      value: result.timezone ? result.timezone.split("/").pop()!.replace(/_/g, " ") : "—" },
    { label: "USAGE TYPE",    value: result.abuse_usage_type ?? "—" },
    { label: "ABUSE REPORTS", value: result.abuse_total_reports != null ? String(result.abuse_total_reports) : "—" },
    { label: "DEPTH",         value: result.depth.toUpperCase() },
  ];

  return (
    <div className="border border-[var(--border)] rounded-sm bg-[var(--surface)] overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-[var(--border)]">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="font-mono text-[10px] tracking-[3px] text-[var(--muted)] mb-1.5">
              IP ANALYSIS COMPLETE
              <span className="ml-2 px-1.5 py-0.5 border border-[var(--border)] rounded-sm text-[9px]">
                ip-api · ipapi.is · abuseipdb · greynoise · groq
              </span>
            </div>
            <div className="font-mono text-xl tracking-[2px] break-all" style={{ color: "var(--accent)" }}>{result.ip}</div>
            {result.original_input !== result.resolved_ip && (
              <div className="font-mono text-[11px] text-[var(--accent)] opacity-70 mt-0.5">
                ↳ resolved from {result.original_input}
              </div>
            )}
            {result.reverse_dns && (
              <div className="font-mono text-[11px] text-[var(--accent)] opacity-50 mt-0.5 break-all">
                ↳ {result.reverse_dns}
              </div>
            )}
            <div className="font-mono text-[12px] text-[var(--muted)] mt-1">{flag} {locationStr}</div>
          </div>
          <div className="flex items-center gap-2 shrink-0 mt-1">
            <CopyBtn label="COPY"     getText={getReport} />
            <CopyBtn label="🔗 LINK"  getText={getShare}  />
          </div>
        </div>
      </div>

      <div className="px-6 py-5 space-y-5">

        {/* Risk banner */}
        <div className={`flex items-center gap-4 px-5 py-4 border rounded-sm ${rc.bg} ${rc.border}`}>
          <span className="text-3xl leading-none">{rc.icon}</span>
          <div>
            <div className={`font-head font-bold text-xl tracking-[2px] ${rc.text}`}>{rc.label}</div>
            <div className="font-head text-[14px] text-[var(--text)] mt-0.5 leading-snug">{result.summary}</div>
          </div>
        </div>

        {/* Map */}
        {result.lat !== null && result.lon !== null && (
          <div className="overflow-hidden rounded-sm border border-[var(--border)]">
            <div className="font-mono text-[10px] tracking-[3px] text-[var(--muted)] px-4 py-2 border-b border-[var(--border)] bg-[#070910]">
              {"// APPROXIMATE LOCATION · "}{result.city ?? "UNKNOWN"}{result.region ? `, ${result.region}` : ""}{result.country ? ` · ${result.country}` : ""}
            </div>
            <IpMap lat={result.lat} lon={result.lon} city={result.city} region={result.region} country={result.country} />
          </div>
        )}

        {/* Reputation pills */}
        <div>
          <SectionLabel>REPUTATION SIGNALS</SectionLabel>
          <div className="flex flex-wrap gap-2">
            <IndicatorPill label="VPN"           active={showVpn}                 colour="#ffb800" />
            <IndicatorPill label="PROXY"         active={result.is_proxy}         colour="#ffb800" />
            <IndicatorPill label="TOR"           active={result.is_tor}           colour="#ff3c5a" />
            <IndicatorPill label="HOSTING / DC"  active={result.is_hosting}       colour="#6496ff" />
          </div>
        </div>

        {/* Score bars */}
        {(result.abuse_confidence_score !== null || result.threat_score !== null) && (
          <div className="bg-[#070910] border border-[var(--border)] rounded-sm px-4 py-4 space-y-4">
            {result.abuse_confidence_score !== null && (
              <div>
                <ScoreBar label="AbuseIPDB Confidence" score={result.abuse_confidence_score} lowGood />
                <div className="flex gap-4 mt-2 flex-wrap">
                  {result.abuse_total_reports != null && (
                    <span className="font-mono text-[10px] text-[var(--muted)]">
                      {result.abuse_total_reports} reports
                    </span>
                  )}
                  {result.abuse_last_reported && (
                    <span className="font-mono text-[10px] text-[var(--muted)]">
                      last: {new Date(result.abuse_last_reported).toLocaleDateString()}
                    </span>
                  )}
                  {result.whois_abuse_email && (
                    <a
                      href={`mailto:${result.whois_abuse_email}`}
                      className="font-mono text-[10px] text-[var(--accent)] opacity-70 hover:opacity-100 transition-opacity"
                    >
                      abuse: {result.whois_abuse_email}
                    </a>
                  )}
                </div>
              </div>
            )}
            {result.threat_score !== null && (
              <ScoreBar label="GetIPIntel Threat Score" score={result.threat_score} lowGood />
            )}
          </div>
        )}

        {/* Abuse reports */}
        <AbuseReports reports={result.abuse_reports} />

        {/* Info grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {metaItems.map(({ label, value }) => (
            <InfoCell key={label} label={label} value={value} />
          ))}
        </div>

        {/* Hosted domains (reverse IP lookup) */}
        {result.hosted_domains && result.hosted_domains.length > 0 && (
          <div>
            <SectionLabel>HOSTED DOMAINS ON THIS IP ({result.hosted_domains.length})</SectionLabel>
            <div className="border border-[var(--border)] rounded-sm bg-[#070910] p-3">
              <div className="flex flex-wrap gap-1.5">
                {result.hosted_domains.map(d => (
                  <span
                    key={d}
                    className="font-mono text-[10px] tracking-[1px] px-2 py-0.5 border rounded-sm"
                    style={{ borderColor: "rgba(100,150,255,0.25)", background: "rgba(100,150,255,0.06)", color: "#6496ff" }}
                  >
                    {d}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Open ports (nmap) */}
        {result.open_ports && result.open_ports.length > 0 && (
          <div>
            <SectionLabel>OPEN PORTS ({result.open_ports.length})</SectionLabel>
            <div className="border border-[var(--border)] rounded-sm bg-[#070910] overflow-hidden">
              <div className="divide-y divide-[var(--border)]">
                {result.open_ports.map(p => (
                  <div key={p.port} className="flex items-center gap-4 px-4 py-2 flex-wrap">
                    <span className="font-mono text-[13px] font-bold" style={{ color: "var(--accent)", minWidth: "4rem" }}>{p.port}/{p.protocol}</span>
                    <span className="font-mono text-[11px] text-white">{p.service}</span>
                    <span
                      className="font-mono text-[9px] tracking-[2px] px-2 py-0.5 border rounded-sm ml-auto"
                      style={{ borderColor: "rgba(0,255,65,0.3)", background: "rgba(0,255,65,0.06)", color: "var(--accent)" }}
                    >
                      {p.state.toUpperCase()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Flags */}
        <FlagsList flags={result.flags} />

        {/* AI analysis */}
        <div>
          <SectionLabel>AI INTELLIGENCE REPORT</SectionLabel>
          <AnalysisExpander text={result.raw} />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Email result card
// ---------------------------------------------------------------------------

function EmailIndicator({ label, active, colour, inverse }: { label: string; active: boolean; colour: string; inverse?: boolean }) {
  const isAlert = inverse ? !active : active;
  return (
    <div
      className={`font-mono text-[10px] tracking-[1px] px-3 py-2 border rounded-sm flex items-center gap-1.5 ${isAlert ? "" : "opacity-30"}`}
      style={isAlert
        ? { borderColor: `${colour}55`, background: `${colour}12`, color: colour }
        : { borderColor: "var(--border)", color: "var(--muted)" }}
    >
      <span>{isAlert ? "●" : "○"}</span>
      <span>{label}</span>
    </div>
  );
}

function EmailResultCard({ result }: { result: EmailLookupResult }) {
  const rc = riskColour(result.risk);

  const getReport = useCallback(() =>
    [
      "PhoneScan Email Report",
      `${result.email} — ${result.risk} Risk`,
      result.summary, "",
      `Domain: ${result.domain}`,
      `Disposable: ${result.is_disposable ? "YES" : "No"}`,
      `Free Provider: ${result.is_free_provider ? "Yes" : "No"}`,
      `Blacklisted: ${result.blacklisted ? "YES" : "No"}`,
      `Credentials Leaked: ${result.credentials_leaked ? "YES" : "No"}`,
      `Data Breach: ${result.data_breach ? "YES" : "No"}`,
      `Malicious Activity: ${result.malicious_activity ? "YES" : "No"}`,
      result.profiles.length > 0 ? `Profiles: ${result.profiles.join(", ")}` : null,
      "", "Findings:", ...result.flags.map(f => `• ${f}`),
      "", "Analysis:", result.raw.replace(/\{[^}]*"risk"[^}]*\}\s*$/, "").trim(),
    ].filter(s => s !== null).join("\n"),
    [result] // eslint-disable-line react-hooks/exhaustive-deps
  );
  const getShare = useCallback(() => {
    const q = encodeURIComponent(result.email);
    return `https://phonescan-gamma.vercel.app/?q=${q}&mode=email`;
  },
    [result] // eslint-disable-line react-hooks/exhaustive-deps
  );

  const metaItems = [
    { label: "EMAIL",        value: result.email },
    { label: "DOMAIN",       value: result.domain },
    { label: "REPUTATION",   value: result.domain_reputation ?? "—" },
    { label: "REFERENCES",   value: String(result.references) },
    { label: "DEPTH",        value: result.depth.toUpperCase() },
  ];

  return (
    <div className="border border-[var(--border)] rounded-sm bg-[var(--surface)] overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-[var(--border)]">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="font-mono text-[10px] tracking-[3px] text-[var(--muted)] mb-1.5">
              EMAIL ANALYSIS COMPLETE
              <span className="ml-2 px-1.5 py-0.5 border border-[var(--border)] rounded-sm text-[9px]">
                emailrep.io · groq
              </span>
            </div>
            <div className="font-mono text-xl tracking-[2px] break-all" style={{ color: "var(--accent)" }}>
              {result.email}
            </div>
            <div className="font-mono text-[12px] text-[var(--muted)] mt-0.5">
              {result.domain}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0 mt-1">
            <CopyBtn label="COPY"     getText={getReport} />
            <CopyBtn label="🔗 LINK"  getText={getShare}  />
          </div>
        </div>
      </div>

      <div className="px-6 py-5 space-y-5">
        {/* Risk banner */}
        <div className={`flex items-center gap-4 px-5 py-4 border rounded-sm ${rc.bg} ${rc.border}`}>
          <span className="text-3xl leading-none">{rc.icon}</span>
          <div>
            <div className={`font-head font-bold text-xl tracking-[2px] ${rc.text}`}>{rc.label}</div>
            <div className="font-head text-[14px] text-[var(--text)] mt-0.5 leading-snug">{result.summary}</div>
          </div>
        </div>

        {/* Threat indicators */}
        <div>
          <SectionLabel>THREAT INDICATORS</SectionLabel>
          <div className="flex flex-wrap gap-2">
            <EmailIndicator label="DISPOSABLE"          active={result.is_disposable}      colour="#ff3c5a" />
            <EmailIndicator label="BLACKLISTED"         active={result.blacklisted}         colour="#ff3c5a" />
            <EmailIndicator label="MALICIOUS ACTIVITY"  active={result.malicious_activity}  colour="#ff3c5a" />
            <EmailIndicator label="CREDENTIALS LEAKED"  active={result.credentials_leaked}  colour="#ffb800" />
            <EmailIndicator label="DATA BREACH"         active={result.data_breach}         colour="#ffb800" />
            <EmailIndicator label="SPOOFABLE DOMAIN"    active={result.spoofable}           colour="#ffb800" />
            <EmailIndicator label="FREE PROVIDER"       active={result.is_free_provider}    colour="#6496ff" />
            <EmailIndicator label="SUSPICIOUS"          active={result.suspicious}          colour="#ffb800" />
          </div>
        </div>

        {/* Meta grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
          {metaItems.map(({ label, value }) => (
            <InfoCell key={label} label={label} value={value} />
          ))}
        </div>

        {/* DNS infrastructure */}
        <div>
          <SectionLabel>EMAIL INFRASTRUCTURE</SectionLabel>
          <div className="space-y-2">
            {/* MX, SPF, DMARC status pills */}
            <div className="flex flex-wrap gap-2">
              <EmailIndicator label="MX RECORDS"    active={result.has_mx}          colour="#00ff88" />
              <EmailIndicator label="DELIVERABLE"   active={result.deliverable === true} colour="#00ff88" />
              <EmailIndicator label="SPF ENFORCED"  active={result.spf_enforced}    colour="#00ff88" />
              <EmailIndicator label="DMARC ENFORCED" active={result.dmarc_enforced} colour="#00ff88" />
              <EmailIndicator label="SPOOFABLE"     active={result.spoofable}        colour="#ffb800" />
            </div>
            {/* MX records list */}
            {result.mx_records.length > 0 && (
              <div className="border border-[var(--border)] rounded-sm bg-[#070910] p-3">
                <div className="font-mono text-[9px] tracking-[3px] text-[var(--muted)] mb-2">MX RECORDS</div>
                <div className="flex flex-col gap-1">
                  {result.mx_records.map(mx => (
                    <span key={mx} className="font-mono text-[11px] text-[var(--accent)]">{mx}</span>
                  ))}
                </div>
              </div>
            )}
            {/* SPF / DMARC records */}
            {(result.spf_record || result.dmarc_record) && (
              <div className="border border-[var(--border)] rounded-sm bg-[#070910] p-3 space-y-2">
                {result.spf_record && (
                  <div>
                    <div className="font-mono text-[9px] tracking-[3px] text-[var(--muted)] mb-1">SPF</div>
                    <div className="font-mono text-[10px] text-[var(--text)] break-all leading-relaxed">{result.spf_record}</div>
                  </div>
                )}
                {result.dmarc_record && (
                  <div>
                    <div className="font-mono text-[9px] tracking-[3px] text-[var(--muted)] mb-1">DMARC</div>
                    <div className="font-mono text-[10px] text-[var(--text)] break-all leading-relaxed">{result.dmarc_record}</div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Domain age */}
        {(result.domain_age_days !== null || result.domain_created || result.domain_registrar) && (
          <div>
            <SectionLabel>DOMAIN INTELLIGENCE</SectionLabel>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {result.domain_age_days !== null && (
                <InfoCell label="DOMAIN AGE" value={`${result.domain_age_days} days (${Math.floor(result.domain_age_days / 365)}y)`} />
              )}
              {result.domain_created && (
                <InfoCell label="REGISTERED" value={result.domain_created.slice(0, 10)} />
              )}
              {result.domain_registrar && (
                <InfoCell label="REGISTRAR" value={result.domain_registrar} />
              )}
              {result.new_domain && (
                <div className="col-span-full px-3 py-2 border border-[rgba(255,60,90,0.35)] bg-[rgba(255,60,90,0.07)] rounded-sm">
                  <span className="font-mono text-[10px] tracking-[2px] text-[#ff3c5a]">⚠ NEW DOMAIN — elevated phishing risk</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Activity */}
        {(result.first_seen || result.last_seen) && (
          <div className="grid grid-cols-2 gap-2">
            {result.first_seen && <InfoCell label="FIRST SEEN" value={result.first_seen} />}
            {result.last_seen  && <InfoCell label="LAST SEEN"  value={result.last_seen}  />}
          </div>
        )}

        {/* Social profiles */}
        {result.profiles.length > 0 && (
          <div>
            <SectionLabel>LINKED PROFILES</SectionLabel>
            <div className="flex flex-wrap gap-2">
              {result.profiles.map(p => (
                <span
                  key={p}
                  className="font-mono text-[10px] tracking-[1px] px-2.5 py-1 border rounded-sm capitalize"
                  style={{ borderColor: "rgba(0,255,65,0.25)", background: "rgba(0,255,65,0.05)", color: "var(--accent)" }}
                >
                  {p}
                </span>
              ))}
            </div>
          </div>
        )}

        <FlagsList flags={result.flags} />

        <div>
          <SectionLabel>AI INTELLIGENCE REPORT</SectionLabel>
          <AnalysisExpander text={result.raw} />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Username result card
// ---------------------------------------------------------------------------

const CATEGORY_COLOURS: Record<string, string> = {
  Dev:             "#6496ff",
  Community:       "#00ff88",
  "Crypto/Security": "#ffb800",
  Gaming:          "#ff6b6b",
  Identity:        "#c084fc",
  Streaming:       "#ff8c00",
};

function UsernameResultCard({ result }: { result: UsernameResult }) {
  const rc = riskColour(result.risk);

  const getReport = useCallback(() =>
    [
      "PhoneScan Username Report",
      `@${result.username} — ${result.risk} Risk`,
      result.summary, "",
      `Found on (${result.found.length}/${result.checked}): ${result.found.map(f => f.platform).join(", ") || "none"}`,
      result.found.length > 0 ? "\nProfile links:" : null,
      ...result.found.map(f => `  ${f.platform}: ${f.url}`),
      "", "Findings:", ...result.flags.map(f => `• ${f}`),
      "", "Analysis:", result.raw.replace(/\{[^}]*"risk"[^}]*\}\s*$/, "").trim(),
    ].filter(s => s !== null).join("\n"),
    [result] // eslint-disable-line react-hooks/exhaustive-deps
  );
  const getShare = useCallback(() =>
    `https://phonescan-gamma.vercel.app/?q=${encodeURIComponent(result.username)}&mode=username`,
    [result] // eslint-disable-line react-hooks/exhaustive-deps
  );

  // Group found platforms by category
  const byCategory = result.found.reduce<Record<string, typeof result.found>>((acc, p) => {
    (acc[p.category] ??= []).push(p);
    return acc;
  }, {});

  return (
    <div className="border border-[var(--border)] rounded-sm bg-[var(--surface)] overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-[var(--border)]">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="font-mono text-[10px] tracking-[3px] text-[var(--muted)] mb-1.5">
              USERNAME OSINT COMPLETE
              <span className="ml-2 px-1.5 py-0.5 border border-[var(--border)] rounded-sm text-[9px]">
                {result.checked} platforms · groq
              </span>
            </div>
            <div className="font-mono text-xl tracking-[2px] break-all" style={{ color: "var(--accent)" }}>
              @{result.username}
            </div>
            <div className="font-mono text-[12px] text-[var(--muted)] mt-0.5">
              Found on {result.found.length} of {result.checked} platforms
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0 mt-1">
            <CopyBtn label="COPY"    getText={getReport} />
            <CopyBtn label="🔗 LINK" getText={getShare}  />
          </div>
        </div>
      </div>

      <div className="px-6 py-5 space-y-5">
        {/* Risk banner */}
        <div className={`flex items-center gap-4 px-5 py-4 border rounded-sm ${rc.bg} ${rc.border}`}>
          <span className="text-3xl leading-none">{rc.icon}</span>
          <div>
            <div className={`font-head font-bold text-xl tracking-[2px] ${rc.text}`}>{rc.label}</div>
            <div className="font-head text-[14px] text-[var(--text)] mt-0.5 leading-snug">{result.summary}</div>
          </div>
        </div>

        {/* Platform presence grouped by category */}
        {result.found.length > 0 && (
          <div>
            <SectionLabel>PLATFORMS FOUND ({result.found.length})</SectionLabel>
            <div className="space-y-3">
              {Object.entries(byCategory).map(([cat, platforms]) => (
                <div key={cat}>
                  <div
                    className="font-mono text-[9px] tracking-[3px] mb-1.5"
                    style={{ color: CATEGORY_COLOURS[cat] ?? "var(--muted)" }}
                  >
                    {cat.toUpperCase()}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {platforms.map(p => (
                      <a
                        key={p.platform}
                        href={p.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="font-mono text-[10px] tracking-[1px] px-3 py-1.5 border rounded-sm transition-all hover:opacity-90"
                        style={{
                          borderColor: `${CATEGORY_COLOURS[cat] ?? "#6496ff"}44`,
                          background:  `${CATEGORY_COLOURS[cat] ?? "#6496ff"}0d`,
                          color:        CATEGORY_COLOURS[cat] ?? "#6496ff",
                        }}
                      >
                        ↗ {p.platform}
                      </a>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Not found list */}
        {result.not_found.length > 0 && (
          <div>
            <SectionLabel>NOT FOUND ({result.not_found.length})</SectionLabel>
            <div className="flex flex-wrap gap-1.5">
              {result.not_found.map(n => (
                <span
                  key={n}
                  className="font-mono text-[9px] tracking-[1px] px-2 py-0.5 border rounded-sm opacity-40"
                  style={{ borderColor: "var(--border)", color: "var(--muted)" }}
                >
                  {n}
                </span>
              ))}
            </div>
          </div>
        )}

        <FlagsList flags={result.flags} />

        <div>
          <SectionLabel>AI INTELLIGENCE REPORT</SectionLabel>
          <AnalysisExpander text={result.raw} />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// URL scan result card
// ---------------------------------------------------------------------------

function UrlScanResultCard({ result }: { result: UrlScanResult }) {
  const rc = riskColour(result.risk);

  const getReport = useCallback(() =>
    [
      "PhoneScan URL Report",
      `${result.url} — ${result.risk} Risk`,
      result.summary, "",
      `Domain: ${result.domain}`,
      result.resolved_ip ? `Resolved IP: ${result.resolved_ip}` : null,
      `URLhaus status: ${result.urlhaus_status}`,
      result.urlhaus_threat ? `Threat: ${result.urlhaus_threat}` : null,
      result.urlhaus_tags.length > 0 ? `Tags: ${result.urlhaus_tags.join(", ")}` : null,
      `Malware: ${result.is_malware ? "YES" : "No"} | Phishing: ${result.is_phishing ? "YES" : "No"} | Shortened: ${result.is_shortened ? "Yes" : "No"}`,
      "", "Findings:", ...result.flags.map(f => `• ${f}`),
      "", "Analysis:", result.raw.replace(/\{[^}]*"risk"[^}]*\}\s*$/, "").trim(),
    ].filter(s => s !== null).join("\n"),
    [result] // eslint-disable-line react-hooks/exhaustive-deps
  );
  const getShare = useCallback(() =>
    `https://phonescan-gamma.vercel.app/?q=${encodeURIComponent(result.url)}&mode=urlscan`,
    [result] // eslint-disable-line react-hooks/exhaustive-deps
  );

  const uhColour =
    result.urlhaus_status === "online"   ? "#ff3c5a" :
    result.urlhaus_status === "offline"  ? "#ffb800" :
    result.urlhaus_status === "not_found"? "#00ff88" : "var(--muted)";

  const uhLabel =
    result.urlhaus_status === "online"    ? "⚠ ONLINE THREAT"   :
    result.urlhaus_status === "offline"   ? "OFFLINE (was threat)" :
    result.urlhaus_status === "not_found" ? "CLEAN (not in DB)"  : "UNKNOWN";

  return (
    <div className="border border-[var(--border)] rounded-sm bg-[var(--surface)] overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-[var(--border)]">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="font-mono text-[10px] tracking-[3px] text-[var(--muted)] mb-1.5">
              URL THREAT ANALYSIS COMPLETE
              <span className="ml-2 px-1.5 py-0.5 border border-[var(--border)] rounded-sm text-[9px]">
                urlhaus · dns · groq
              </span>
            </div>
            <div className="font-mono text-[14px] tracking-[1px] break-all" style={{ color: "var(--accent)" }}>
              {result.url}
            </div>
            <div className="font-mono text-[11px] text-[var(--muted)] mt-0.5">
              {result.domain}{result.resolved_ip ? ` · ${result.resolved_ip}` : ""}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0 mt-1">
            <CopyBtn label="COPY"    getText={getReport} />
            <CopyBtn label="🔗 LINK" getText={getShare}  />
          </div>
        </div>
      </div>

      <div className="px-6 py-5 space-y-5">
        {/* Risk banner */}
        <div className={`flex items-center gap-4 px-5 py-4 border rounded-sm ${rc.bg} ${rc.border}`}>
          <span className="text-3xl leading-none">{rc.icon}</span>
          <div>
            <div className={`font-head font-bold text-xl tracking-[2px] ${rc.text}`}>{rc.label}</div>
            <div className="font-head text-[14px] text-[var(--text)] mt-0.5 leading-snug">{result.summary}</div>
          </div>
        </div>

        {/* Threat indicators */}
        <div>
          <SectionLabel>THREAT INDICATORS</SectionLabel>
          <div className="flex flex-wrap gap-2">
            <EmailIndicator label="MALWARE"        active={result.is_malware}  colour="#ff3c5a" />
            <EmailIndicator label="PHISHING"       active={result.is_phishing} colour="#ff3c5a" />
            <EmailIndicator label="SHORTENED URL"  active={result.is_shortened} colour="#ffb800" />
          </div>
        </div>

        {/* Redirect chain */}
        {result.redirect_chain.length > 0 && (
          <div>
            <SectionLabel>REDIRECT CHAIN ({result.redirect_chain.length} HOP{result.redirect_chain.length !== 1 ? "S" : ""})</SectionLabel>
            <div className="border border-[rgba(255,184,0,0.25)] rounded-sm bg-[#070910] p-3 space-y-1.5">
              <div className="flex items-start gap-2">
                <span className="font-mono text-[9px] tracking-[2px] text-[var(--muted)] shrink-0 mt-0.5">START</span>
                <span className="font-mono text-[10px] text-[var(--text)] break-all">{result.url}</span>
              </div>
              {result.redirect_chain.map((hop, i) => (
                <div key={i} className="flex items-start gap-2">
                  <span className="font-mono text-[9px] tracking-[2px] text-[#ffb800] shrink-0 mt-0.5">→ HOP {i + 1}</span>
                  <span className="font-mono text-[10px] text-white break-all">{hop}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Threat databases */}
        <div>
          <SectionLabel>THREAT DATABASE RESULTS</SectionLabel>
          <div className="space-y-2">
            {/* URLhaus */}
            <div className="bg-[#070910] border border-[var(--border)] rounded-sm px-4 py-3 flex flex-wrap items-center gap-4">
              <div>
                <div className="font-mono text-[9px] tracking-[3px] text-[var(--muted)] mb-1">URLHAUS</div>
                <div className="font-mono text-[12px] tracking-[1px]" style={{ color: uhColour }}>{uhLabel}</div>
              </div>
              {result.urlhaus_threat && (
                <div>
                  <div className="font-mono text-[9px] tracking-[3px] text-[var(--muted)] mb-1">THREAT TYPE</div>
                  <div className="font-mono text-[12px] text-[#ff3c5a]">{result.urlhaus_threat}</div>
                </div>
              )}
              {result.urlhaus_tags.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {result.urlhaus_tags.map(tag => (
                    <span
                      key={tag}
                      className="font-mono text-[9px] tracking-[1px] px-2 py-0.5 border rounded-sm"
                      style={{ borderColor: "rgba(255,60,90,0.35)", background: "rgba(255,60,90,0.08)", color: "#ff3c5a" }}
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              )}
            </div>
            {/* URLScan.io */}
            <div className="bg-[#070910] border border-[var(--border)] rounded-sm px-4 py-3 flex flex-wrap items-center gap-4">
              <div>
                <div className="font-mono text-[9px] tracking-[3px] text-[var(--muted)] mb-1">URLSCAN.IO</div>
                <div
                  className="font-mono text-[12px]"
                  style={{ color: result.urlscan_found ? (result.urlscan_categories.length > 0 ? "#ffb800" : "#00ff88") : "var(--muted)" }}
                >
                  {result.urlscan_found ? `FOUND IN DATABASE` : "Not in scan history"}
                </div>
              </div>
              {result.urlscan_categories.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {result.urlscan_categories.map(c => (
                    <span
                      key={c}
                      className="font-mono text-[9px] tracking-[1px] px-2 py-0.5 border rounded-sm"
                      style={{ borderColor: "rgba(255,184,0,0.35)", background: "rgba(255,184,0,0.08)", color: "#ffb800" }}
                    >
                      {c}
                    </span>
                  ))}
                  {result.urlscan_verdicts.map(v => (
                    <span
                      key={v}
                      className="font-mono text-[9px] tracking-[1px] px-2 py-0.5 border rounded-sm"
                      style={{ borderColor: "rgba(100,150,255,0.35)", background: "rgba(100,150,255,0.08)", color: "#6496ff" }}
                    >
                      {v}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Domain intel */}
        <div>
          <SectionLabel>DOMAIN INTELLIGENCE</SectionLabel>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            <InfoCell label="DOMAIN"      value={result.domain} />
            <InfoCell label="RESOLVED IP" value={result.resolved_ip ?? "—"} />
            <InfoCell label="DEPTH"       value={result.depth.toUpperCase()} />
            {result.domain_age_days !== null && (
              <InfoCell label="DOMAIN AGE" value={`${result.domain_age_days}d (${Math.floor(result.domain_age_days / 365)}y)`} />
            )}
            {result.domain_created && (
              <InfoCell label="REGISTERED" value={result.domain_created} />
            )}
            {result.domain_registrar && (
              <InfoCell label="REGISTRAR" value={result.domain_registrar} />
            )}
          </div>
          {/* New domain warning */}
          {result.domain_age_days !== null && result.domain_age_days < 30 && (
            <div className="mt-2 px-3 py-2 border border-[rgba(255,60,90,0.35)] bg-[rgba(255,60,90,0.07)] rounded-sm">
              <span className="font-mono text-[10px] tracking-[2px] text-[#ff3c5a]">⚠ DOMAIN LESS THAN 30 DAYS OLD — high phishing risk</span>
            </div>
          )}
        </div>

        {/* SSL certificate */}
        {(result.ssl_issuer || result.ssl_valid_to) && (
          <div>
            <SectionLabel>SSL / TLS CERTIFICATE</SectionLabel>
            <div className="border border-[var(--border)] rounded-sm bg-[#070910] px-4 py-3 grid grid-cols-2 sm:grid-cols-4 gap-3">
              {result.ssl_issuer && (
                <div>
                  <div className="font-mono text-[9px] tracking-[3px] text-[var(--muted)] mb-1">ISSUER</div>
                  <div className="font-mono text-[10px] text-white truncate" title={result.ssl_issuer}>{result.ssl_issuer}</div>
                </div>
              )}
              {result.ssl_valid_from && (
                <div>
                  <div className="font-mono text-[9px] tracking-[3px] text-[var(--muted)] mb-1">VALID FROM</div>
                  <div className="font-mono text-[10px] text-white">{result.ssl_valid_from}</div>
                </div>
              )}
              {result.ssl_valid_to && (
                <div>
                  <div className="font-mono text-[9px] tracking-[3px] text-[var(--muted)] mb-1">VALID TO</div>
                  <div className="font-mono text-[10px] text-white">{result.ssl_valid_to}</div>
                </div>
              )}
              {result.ssl_days_remaining !== null && (
                <div>
                  <div className="font-mono text-[9px] tracking-[3px] text-[var(--muted)] mb-1">EXPIRES IN</div>
                  <div
                    className="font-mono text-[12px] font-bold"
                    style={{ color: result.ssl_days_remaining < 0 ? "#ff3c5a" : result.ssl_days_remaining < 14 ? "#ffb800" : "#00ff88" }}
                  >
                    {result.ssl_days_remaining < 0 ? "EXPIRED" : `${result.ssl_days_remaining}d`}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Web history */}
        <div className="flex flex-wrap gap-3 items-center">
          <div
            className="font-mono text-[10px] tracking-[1px] px-3 py-2 border rounded-sm flex items-center gap-2"
            style={result.wayback_available
              ? { borderColor: "rgba(0,255,136,0.3)", background: "rgba(0,255,136,0.05)", color: "#00ff88" }
              : { borderColor: "var(--border)", color: "var(--muted)", opacity: 0.5 }}
          >
            <span>{result.wayback_available ? "●" : "○"}</span>
            <span>WAYBACK MACHINE {result.wayback_available ? `· first seen ${result.wayback_oldest_snapshot}` : "· no archive"}</span>
          </div>
        </div>

        <FlagsList flags={result.flags} />

        <div>
          <SectionLabel>AI THREAT ANALYSIS</SectionLabel>
          <AnalysisExpander text={result.raw} />
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

function HistoryPanel({
  history,
  onRestore,
  onClear,
  onExportCSV,
}: {
  history: HistoryEntry[];
  onRestore: (entry: HistoryEntry) => void;
  onClear: () => void;
  onExportCSV: () => void;
}) {
  const [cleared, setCleared] = useState(false);

  if (history.length === 0) return null;

  function handleClear() {
    onClear();
    setCleared(true);
    setTimeout(() => setCleared(false), 2000);
  }

  return (
    <div className="border border-[var(--border)] rounded-sm bg-[var(--surface)] overflow-hidden">
      <div className="px-5 py-3 border-b border-[var(--border)] flex items-center justify-between gap-2">
        <span className="font-mono text-[10px] tracking-[3px] text-[var(--muted)]">
          {"// RECENT LOOKUPS ("}{history.length}{")"}
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={onExportCSV}
            className="font-mono text-[9px] tracking-[2px] px-2.5 py-1 border border-[var(--border)] rounded-sm text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] transition-all"
          >
            ↓ CSV
          </button>
          <button
            onClick={handleClear}
            className={`font-mono text-[9px] tracking-[2px] px-2.5 py-1 border rounded-sm transition-all ${
              cleared
                ? "border-[var(--accent)] text-[var(--accent)]"
                : "border-[var(--border)] text-[var(--muted)] hover:border-[#ff3c5a] hover:text-[#ff3c5a]"
            }`}
          >
            {cleared ? "✓ CLEARED" : "CLEAR"}
          </button>
        </div>
      </div>
      <div className="divide-y divide-[var(--border)]">
        {history.map((entry, i) => {
          const rc = riskColour(entry.risk);
          const isIp    = "ip"       in entry && !("username" in entry) && !("url" in entry) && !("parsed" in entry);
          const isEmail = "email"    in entry && !("ip" in entry) && !("parsed" in entry) && !("username" in entry) && !("url" in entry);
          const isUser  = "username" in entry;
          const isUrl   = "url"      in entry && !("username" in entry) && !("email" in entry) && !("parsed" in entry);
          const displayVal = isIp
            ? (entry as IpLookupResult).ip
            : isEmail
              ? (entry as EmailLookupResult).email
              : isUser
                ? `@${(entry as UsernameResult).username}`
                : isUrl
                  ? (entry as UrlScanResult).url
                  : ((entry as LookupResult).parsed.internationalFormat ?? (entry as LookupResult).parsed.raw);
          const modeLabel = isIp ? "IP" : isEmail ? "EMAIL" : isUser ? "USERNAME" : isUrl ? "URL" : (entry as LookupResult).mode.toUpperCase();
          const icon = isIp ? "🌐" : isEmail ? "✉️" : isUser ? "🔍" : isUrl ? "🔗" : "📞";
          return (
            <button
              key={i}
              onClick={() => onRestore(entry)}
              className="w-full flex items-center justify-between px-5 py-2.5 hover:bg-[#0d1117] transition-colors text-left group"
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <span className="font-mono text-[10px] text-[var(--muted)]">{String(i + 1).padStart(2, "0")}</span>
                <span className="text-sm leading-none shrink-0">{icon}</span>
                <span className={`font-mono text-[13px] tracking-wide group-hover:text-[var(--accent)] transition-colors truncate ${rc.text}`}>
                  {displayVal}
                </span>
                <span className="font-mono text-[10px] text-[var(--muted)] shrink-0">{modeLabel}</span>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <span className={`font-mono text-[10px] tracking-[2px] px-2 py-0.5 border rounded-sm ${rc.text} ${rc.border}`}>
                  {entry.risk.toUpperCase()}
                </span>
                <span className="font-mono text-[10px] text-[var(--muted)]">{entry.queriedAt}</span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function Home() {
  const [number,    setNumber]    = useState("");
  const [mode,      setMode]      = useState<TabId>("consumer");
  const [depth,     setDepth]     = useState<Depth>("standard");
  const [loading,   setLoading]   = useState(false);
  const [result,    setResult]    = useState<AnyResult | null>(null);
  const [error,     setError]     = useState<string | null>(null);
  const [remaining, setRemaining] = useState<number | null>(null);
  const [history,   setHistory]   = useState<HistoryEntry[]>([]);
  const [resultKey, setResultKey] = useState(0);
  const [bulkMode,  setBulkMode]  = useState(false);
  const [bulkInput, setBulkInput] = useState("");
  const [bulkResults, setBulkResults] = useState<Array<{ target: string; risk: string; summary: string; error?: string }>>([]);
  const [bulkProgress, setBulkProgress] = useState<{ current: number; total: number } | null>(null);
  const inputRef       = useRef<HTMLInputElement>(null);
  const myIpRef        = useRef<string | null>(null);
  const hasAutoRunRef  = useRef(false);
  const hasUrlRunRef   = useRef(false);
  const canvasRef      = useRef<HTMLCanvasElement>(null);

  // Matrix rain background
  useEffect(() => {
    const canvas = canvasRef.current!;
    if (!canvas) return;
    const ctx = canvas.getContext("2d")!;
    if (!ctx) return;

    const CHARS =
      "ァアィイゥウェエォオカガキギクグケゲコゴサザシジスズセゼソゾタダチヂッツヅテデトドナニヌネノ" +
      "ハバパヒビピフブプヘベペホボポマミムメモャヤュユョヨラリルレロワヲン" +
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const FONT_SIZE = 14;
    const TRAIL     = 8;

    let cols: number[]   = [];
    let speeds: number[] = [];
    let animId: number;

    function resize() {
      canvas.width  = window.innerWidth;
      canvas.height = window.innerHeight;
      const numCols = Math.floor(canvas.width / FONT_SIZE);
      cols   = Array.from({ length: numCols }, () => Math.random() * canvas.height);
      speeds = Array.from({ length: numCols }, () => 0.4 + Math.random() * 1.4);
    }

    resize();
    window.addEventListener("resize", resize);

    function draw() {
      // Redraw opaque background each frame — no trailing glow buildup
      ctx.fillStyle = "#0a0c0f";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.font = `${FONT_SIZE}px "Share Tech Mono", monospace`;

      for (let i = 0; i < cols.length; i++) {
        for (let t = 0; t < TRAIL; t++) {
          const y = cols[i] - t * FONT_SIZE;
          if (y < -FONT_SIZE || y > canvas.height) continue;
          const ch = CHARS[Math.floor(Math.random() * CHARS.length)];
          // Head brightest (~0.055), trail fades to ~0.002
          const opacity = Math.max(0, 0.055 - t * 0.007);
          ctx.fillStyle = `rgba(0,255,65,${opacity.toFixed(3)})`;
          ctx.fillText(ch, i * FONT_SIZE, y);
        }
        cols[i] += speeds[i];
        if (cols[i] > canvas.height + TRAIL * FONT_SIZE) {
          cols[i]   = -FONT_SIZE;
          speeds[i] = 0.4 + Math.random() * 1.4;
        }
      }

      animId = requestAnimationFrame(draw);
    }

    draw();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", resize);
    };
  }, []);

  // Load history from localStorage after mount (avoids SSR hydration mismatch)
  useEffect(() => { setHistory(loadHistory()); }, []);

  // Read ?q= URL param on mount — auto-fill + auto-scan (enables shareable links)
  useEffect(() => {
    if (hasUrlRunRef.current) return;
    const params = new URLSearchParams(window.location.search);
    const q = params.get("q");
    const m = params.get("mode") as TabId | null;
    if (!q) return;
    hasUrlRunRef.current = true;
    const resolvedMode: TabId = (m && ["consumer","blue","red","email","username","urlscan"].includes(m)) ? m : "consumer";
    setMode(resolvedMode);
    setNumber(q);
    // Brief delay so state settles before lookup fires
    setTimeout(() => lookup(q), 100);
    // Clean URL without reloading
    window.history.replaceState({}, "", window.location.pathname);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const lookup = useCallback(async (raw?: string) => {
    const target = (raw ?? number).trim();
    if (!target) return;

    // Validation per mode
    if (mode === "red" && !isValidIpOrDomain(target)) {
      setError("Invalid input. Enter a valid IP address (e.g. 8.8.8.8) or domain (e.g. google.com).");
      return;
    }
    if (mode === "email" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(target)) {
      setError("Please enter a valid email address (e.g. user@example.com).");
      return;
    }
    if (mode === "username" && !/^@?[a-zA-Z0-9_.\-]{1,50}$/.test(target)) {
      setError("Invalid username format. Use letters, numbers, underscores, hyphens, and dots.");
      return;
    }

    setLoading(true); setError(null); setResult(null);
    try {
      const endpoint =
        mode === "red"      ? "/api/iplookup"  :
        mode === "email"    ? "/api/email"     :
        mode === "username" ? "/api/username"  :
        mode === "urlscan"  ? "/api/urlscan"   :
        "/api/lookup";
      const body =
        mode === "red"      ? { ip: target, depth }                    :
        mode === "email"    ? { email: target, depth }                  :
        mode === "username" ? { username: target, depth }               :
        mode === "urlscan"  ? { url: target, depth }                    :
        { number: target, mode, depth };

      const res  = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const rem = res.headers.get("X-RateLimit-Remaining");
      if (rem !== null) setRemaining(parseInt(rem, 10));
      const data = await res.json() as AnyResult;
      if (!res.ok) {
        const errData = data as unknown as { error?: string };
        setError(errData.error ?? "Something went wrong.");
        return;
      }
      setResult(data);
      setResultKey(k => k + 1);
      setHistory(prev => {
        const updated = [{ ...data, queriedAt: new Date().toLocaleTimeString() }, ...prev].slice(0, 20);
        saveHistory(updated);
        return updated;
      });
    } catch {
      setError("Network error — check your connection and try again.");
    } finally {
      setLoading(false);
    }
  }, [number, mode, depth]);

  const runBulk = useCallback(async () => {
    const lines = bulkInput.split("\n").map(l => l.trim()).filter(Boolean);
    if (!lines.length) return;
    setBulkResults([]);
    setBulkProgress({ current: 0, total: lines.length });
    for (let i = 0; i < lines.length; i++) {
      const target = lines[i];
      setBulkProgress({ current: i + 1, total: lines.length });
      const isIpLike = isValidIpOrDomain(target) && !/^\+/.test(target) && !/^\d{3}/.test(target);
      const isEmailLike = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(target);
      const endpoint = isEmailLike ? "/api/email" : isIpLike ? "/api/iplookup" : "/api/lookup";
      const body = isEmailLike ? { email: target, depth: "quick" }
        : isIpLike ? { ip: target, depth: "quick" }
        : { number: target, mode: "consumer", depth: "quick" };
      try {
        const res = await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        const data = await res.json() as AnyResult & { error?: string };
        if (!res.ok || data.error) {
          setBulkResults(prev => [...prev, { target, risk: "—", summary: data.error ?? "Error", error: data.error }]);
        } else {
          setBulkResults(prev => [...prev, { target, risk: data.risk, summary: data.summary }]);
        }
      } catch {
        setBulkResults(prev => [...prev, { target, risk: "—", summary: "Network error", error: "Network error" }]);
      }
      // Brief pause between requests to avoid rate limit
      if (i < lines.length - 1) await new Promise(r => setTimeout(r, 800));
    }
    setBulkProgress(null);
  }, [bulkInput]);

  const fetchMyIp = useCallback(async () => {
    try {
      const res = await fetch("https://api.ipify.org?format=json");
      const { ip } = await res.json() as { ip: string };
      setNumber(ip);
    } catch {
      setError("Could not detect your IP address.");
    }
  }, []);

  // Restore a history entry directly — no re-fetch
  const handleRestore = useCallback((entry: HistoryEntry) => {
    const isIp       = "ip"       in entry && !("username" in entry) && !("url" in entry) && !("parsed" in entry);
    const isEmail    = "email"    in entry && !("ip" in entry) && !("parsed" in entry) && !("username" in entry) && !("url" in entry);
    const isUsername = "username" in entry && !("ip" in entry) && !("parsed" in entry);
    const isUrl      = "url"      in entry && !("ip" in entry) && !("parsed" in entry) && !("username" in entry) && !("email" in entry);
    setResult(entry);
    setResultKey(k => k + 1);
    setError(null);
    if (isIp) {
      const ipEntry = entry as IpLookupResult;
      setMode("red");
      setNumber(ipEntry.original_input ?? ipEntry.ip);
    } else if (isEmail) {
      const emailEntry = entry as EmailLookupResult;
      setMode("email");
      setNumber(emailEntry.email);
    } else if (isUsername) {
      setMode("username");
      setNumber((entry as UsernameResult).username);
    } else if (isUrl) {
      setMode("urlscan");
      setNumber((entry as UrlScanResult).url);
    } else {
      const phoneEntry = entry as LookupResult;
      setMode(phoneEntry.mode);
      setNumber(phoneEntry.parsed.raw);
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  // Clear history from state + localStorage
  const handleClearHistory = useCallback(() => {
    setHistory([]);
    clearHistory();
  }, []);

  // Silently detect user's IP on mount for auto-fill later
  useEffect(() => {
    fetch("https://api.ipify.org?format=json")
      .then(r => r.json())
      .then(({ ip }: { ip: string }) => { myIpRef.current = ip; })
      .catch(() => {});
  }, []);

  // Auto-fill + auto-run when user first switches to IP mode with empty input
  useEffect(() => {
    if (mode === "red" && !number && myIpRef.current && !hasAutoRunRef.current) {
      hasAutoRunRef.current = true;
      const ip = myIpRef.current;
      setNumber(ip);
      lookup(ip);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode]);

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.key === "Enter" && document.activeElement === inputRef.current) lookup();
      // Ctrl+K / Cmd+K — focus input
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      }
      // Escape — clear result and blur
      if (e.key === "Escape") {
        setResult(null); setError(null);
        inputRef.current?.blur();
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [lookup]);

  const exportHistoryCSV = useCallback(() => {
    if (!history.length) return;
    const rows = [["Target","Type","Risk","Summary","Time"]];
    for (const entry of history) {
      const isIp    = "ip"    in entry && !("username" in entry) && !("url" in entry) && !("parsed" in entry);
      const isEmail = "email" in entry && !("ip" in entry) && !("parsed" in entry) && !("username" in entry) && !("url" in entry);
      const isUser  = "username" in entry;
      const isUrl   = "url" in entry && !("username" in entry) && !("email" in entry);
      const target  = isIp ? (entry as IpLookupResult).ip : isEmail ? (entry as EmailLookupResult).email : isUser ? (entry as UsernameResult).username : isUrl ? (entry as UrlScanResult).url : (entry as LookupResult).parsed.raw;
      const type    = isIp ? "IP" : isEmail ? "Email" : isUser ? "Username" : isUrl ? "URL" : (entry as LookupResult).mode;
      rows.push([target, type, entry.risk, `"${entry.summary.replace(/"/g, '""')}"`, entry.queriedAt]);
    }
    const csv = rows.map(r => r.join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `phonescan-history-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  }, [history]);

  return (
    <>
      {/* Matrix rain canvas — fixed behind everything */}
      <canvas
        ref={canvasRef}
        style={{
          position: "fixed",
          top: 0, left: 0,
          width: "100vw",
          height: "100vh",
          zIndex: 0,
          pointerEvents: "none",
          display: "block",
        }}
      />

      {/* Credit bar */}
      <div
        style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: "11px",
          fontWeight: 700,
          letterSpacing: "0.3em",
          color: "#00ff41",
          background: "rgba(0,255,65,0.04)",
          borderBottom: "1px solid rgba(0,255,65,0.2)",
          padding: "6px 0",
          textAlign: "center",
          width: "100%",
          position: "relative",
          zIndex: 1,
        }}
      >
        MADE BY RAWCHAIN &amp; RAIZEL
      </div>

      <div
        className="min-h-screen flex flex-col items-center px-4 py-10"
        style={{ position: "relative", zIndex: 1 }}
      >
      {/* Header */}
      <header className="text-center mb-8 w-full max-w-[700px]">
        <div className="font-mono text-[11px] tracking-[6px] text-[var(--accent)] opacity-70 mb-2">
          {"// PHONESCAN //"}
        </div>
        <h1
          className="font-head font-bold text-white tracking-[2px] leading-none"
          style={{ fontSize: "clamp(2rem,5vw,3.2rem)" }}
        >
          PHONE <span style={{ color: "var(--accent)", textShadow: "0 0 30px rgba(0,255,136,0.5)" }}>SCAN</span>
        </h1>
        <div className="font-mono text-[11px] tracking-[3px] text-[var(--muted)] mt-2">
          AI-POWERED PHONE &amp; IP INTELLIGENCE · POWERED BY GROQ
        </div>
        {remaining !== null && (
          <div className="font-mono text-[10px] tracking-[2px] text-[var(--muted)] mt-1.5 opacity-60">
            {remaining} LOOKUPS REMAINING TODAY
          </div>
        )}
      </header>

      {/* Tab bar — horizontal scroll on mobile */}
      <div className="flex w-full max-w-[700px] overflow-x-auto">
        {MODES.map((m, i) => (
          <button
            key={m.id}
            onClick={() => { setMode(m.id); setResult(null); setError(null); }}
            className={`shrink-0 py-3 px-3 font-head font-bold text-[11px] sm:text-[12px] tracking-[1px] sm:tracking-[2px] border transition-all duration-150 ${
              i === 0 ? "rounded-tl-sm" : "border-l-0"
            } ${
              mode === m.id
                ? "text-[var(--accent)] border-[var(--border)] bg-[var(--surface)]"
                : "text-[var(--muted)] border-[var(--border)] bg-[var(--surface)] hover:bg-[#141a22]"
            }`}
            style={mode === m.id ? { borderBottomColor: "rgba(10,12,15,0.85)", borderTopColor: "var(--accent)" } : {}}
          >
            {m.label}
          </button>
        ))}
        {/* GitHub link */}
        <a
          href="https://github.com/rawchain"
          target="_blank"
          rel="noreferrer"
          aria-label="GitHub"
          className="flex items-center px-3 border border-l-0 border-[var(--border)] bg-[var(--surface)] text-[var(--muted)] hover:text-white transition-colors shrink-0 ml-auto rounded-tr-sm"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
          </svg>
        </a>
      </div>

      {/* Main card */}
      <div className="w-full max-w-[700px] border border-[var(--border)] border-t-0 rounded-b-sm bg-[var(--surface)]">

        {/* Input section */}
        <div className="px-8 pt-7 pb-6 border-b border-[var(--border)]">
          <span className="font-mono text-[11px] tracking-[3px] text-[var(--accent)] block mb-3">
            {mode === "red"      ? "// ENTER IP ADDRESS OR DOMAIN"   :
             mode === "email"    ? "// ENTER EMAIL ADDRESS"          :
             mode === "username" ? "// ENTER USERNAME TO OSINT"      :
             mode === "urlscan"  ? "// ENTER URL TO ANALYSE"         :
                                   "// ENTER NUMBER (with country code)"}
          </span>
          {bulkMode ? (
            <div className="space-y-3">
              <textarea
                value={bulkInput}
                onChange={e => setBulkInput(e.target.value)}
                placeholder={`+1 800 555 0199\n+44 20 7946 0958\n8.8.8.8\nuser@gmail.com`}
                rows={5}
                className="w-full bg-[#070910] border border-[var(--border)] rounded-sm font-mono text-[13px] tracking-[1px] text-white px-4 py-3 outline-none resize-none placeholder:text-[var(--muted)] placeholder:text-[11px] transition-all"
                onFocus={e => { e.currentTarget.style.borderColor = "var(--accent)"; e.currentTarget.style.boxShadow = "0 0 0 1px var(--accent)"; }}
                onBlur={e => { e.currentTarget.style.borderColor = ""; e.currentTarget.style.boxShadow = ""; }}
              />
              <button
                onClick={runBulk}
                disabled={!bulkInput.trim() || bulkProgress !== null}
                className="font-head font-bold text-[14px] tracking-[3px] px-6 py-3 rounded-sm text-black w-full transition-all disabled:opacity-40"
                style={{ background: "#00c136" }}
              >
                {bulkProgress ? `SCANNING ${bulkProgress.current}/${bulkProgress.total}...` : "⚡ BULK SCAN"}
              </button>
              {/* Bulk results table */}
              {bulkResults.length > 0 && (
                <div className="border border-[var(--border)] rounded-sm overflow-hidden">
                  <div className="font-mono text-[10px] tracking-[3px] text-[var(--muted)] px-4 py-2 bg-[#070910] border-b border-[var(--border)]">
                    {"// BULK RESULTS"}
                  </div>
                  <div className="divide-y divide-[var(--border)]">
                    {bulkResults.map((r, i) => {
                      const rc = r.error ? { text: "text-[var(--muted)]", border: "" } : riskColour(r.risk as RiskLevel);
                      return (
                        <div key={i} className="px-4 py-2.5 bg-[#070910] flex items-start gap-3 flex-wrap">
                          <span className="font-mono text-[11px] text-[var(--muted)] shrink-0 w-5">{i + 1}</span>
                          <span className={`font-mono text-[12px] tracking-wide shrink-0 ${rc.text}`}>{r.target}</span>
                          {!r.error && (
                            <span className={`font-mono text-[10px] tracking-[2px] px-2 py-0.5 border rounded-sm shrink-0 ${rc.text} ${rc.border}`}>
                              {r.risk.toUpperCase()}
                            </span>
                          )}
                          <span className="font-mono text-[10px] text-[var(--muted)] flex-1 min-w-0 truncate">{r.summary}</span>
                        </div>
                      );
                    })}
                  </div>
                  {bulkProgress === null && (
                    <button
                      onClick={() => {
                        const text = bulkResults.map(r => `${r.target}\t${r.risk}\t${r.summary}`).join("\n");
                        navigator.clipboard.writeText(text);
                      }}
                      className="w-full font-mono text-[10px] tracking-[2px] text-[var(--muted)] hover:text-[var(--accent)] py-2 transition-colors border-t border-[var(--border)]"
                    >
                      COPY RESULTS AS TSV
                    </button>
                  )}
                </div>
              )}
            </div>
          ) : (
          <div className="flex gap-3">
            <input
              ref={inputRef}
              type={mode === "red" ? "text" : mode === "email" ? "email" : "tel"}
              value={number}
              onChange={e => setNumber(e.target.value)}
              placeholder={MODES.find(m => m.id === mode)?.placeholder ?? "+1 555 123 4567"}
              maxLength={mode === "red" ? 45 : 50}
              className="flex-1 bg-[#070910] border border-[var(--border)] rounded-sm font-mono text-[16px] tracking-[2px] text-white px-4 py-3.5 outline-none placeholder:text-[var(--muted)] placeholder:text-[13px] transition-all"
              onFocus={e => {
                e.currentTarget.style.borderColor = "var(--accent)";
                e.currentTarget.style.boxShadow   = "0 0 0 1px var(--accent), var(--glow)";
              }}
              onBlur={e => {
                e.currentTarget.style.borderColor = "";
                e.currentTarget.style.boxShadow   = "";
              }}
            />
            <button
              onClick={() => lookup()}
              disabled={loading || !number.trim()}
              className="font-head font-bold text-[14px] tracking-[3px] px-6 rounded-sm text-black whitespace-nowrap transition-all duration-150 disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ background: "#00c136" }}
              onMouseEnter={e => { if (!e.currentTarget.disabled) { e.currentTarget.style.background = "#00e63f"; e.currentTarget.style.boxShadow = "var(--glow)"; e.currentTarget.style.transform = "translateY(-1px)"; }}}
              onMouseLeave={e => { e.currentTarget.style.background = "#00c136"; e.currentTarget.style.boxShadow = ""; e.currentTarget.style.transform = ""; }}
            >
              {loading ? "SCANNING..." : "SCAN"}
            </button>
          </div>
          )}

          {/* Bulk toggle */}
          <div className="flex items-center gap-3 mt-3">
            <button
              onClick={() => { setBulkMode(v => !v); setBulkResults([]); setBulkProgress(null); }}
              className={`font-mono text-[10px] tracking-[2px] px-3 py-1 border rounded-sm transition-all ${
                bulkMode
                  ? "border-[var(--accent)] text-[var(--accent)] bg-[rgba(0,255,65,0.06)]"
                  : "border-[var(--border)] text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
              }`}
            >
              {bulkMode ? "✕ SINGLE MODE" : "⚡ BULK SCAN"}
            </button>
            {bulkMode && <span className="font-mono text-[10px] text-[var(--muted)]">paste one per line</span>}
          </div>

          {/* Depth selector */}
          <div className="flex items-center gap-3 mt-4">
            <span className="font-mono text-[10px] tracking-[2px] text-[var(--muted)]">DEPTH:</span>
            {DEPTHS.map(d => (
              <button
                key={d.id}
                onClick={() => setDepth(d.id)}
                className={`font-mono text-[10px] tracking-[2px] px-3 py-1 border rounded-sm transition-all ${
                  depth === d.id
                    ? "border-[var(--accent)] text-[var(--accent)]"
                    : "border-[var(--border)] text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
                }`}
              >
                {d.label}
              </button>
            ))}
          </div>

          {/* Example chips — phone */}
          {(mode === "consumer" || mode === "blue") && (
            <div className="flex flex-wrap items-center gap-2 mt-3">
              <span className="font-mono text-[10px] tracking-[2px] text-[var(--muted)]">TRY:</span>
              {EXAMPLE_NUMBERS.map(ex => (
                <button
                  key={ex.number}
                  onClick={() => { setNumber(ex.number); lookup(ex.number); }}
                  title={ex.note}
                  className="font-mono text-[10px] tracking-[1px] px-2.5 py-1 border border-[var(--border)] rounded-sm text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] transition-all"
                >
                  {ex.label}
                </button>
              ))}
            </div>
          )}

          {/* Example chips — username */}
          {mode === "username" && (
            <div className="flex flex-wrap items-center gap-2 mt-3">
              <span className="font-mono text-[10px] tracking-[2px] text-[var(--muted)]">TRY:</span>
              {EXAMPLE_USERNAMES.map(ex => (
                <button
                  key={ex.label}
                  onClick={() => { setNumber(ex.label); lookup(ex.label); }}
                  title={ex.note}
                  className="font-mono text-[10px] tracking-[1px] px-2.5 py-1 border border-[var(--border)] rounded-sm text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] transition-all"
                >
                  {ex.label}
                </button>
              ))}
            </div>
          )}

          {/* Example chips — URL */}
          {mode === "urlscan" && (
            <div className="flex flex-wrap items-center gap-2 mt-3">
              <span className="font-mono text-[10px] tracking-[2px] text-[var(--muted)]">TRY:</span>
              {EXAMPLE_URLS.map(ex => (
                <button
                  key={ex.label}
                  onClick={() => { setNumber(ex.label); lookup(ex.label); }}
                  title={ex.note}
                  className="font-mono text-[10px] tracking-[1px] px-2.5 py-1 border border-[var(--border)] rounded-sm text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] transition-all"
                >
                  {ex.label}
                </button>
              ))}
            </div>
          )}

          {/* Example chips — email */}
          {mode === "email" && (
            <div className="flex flex-wrap items-center gap-2 mt-3">
              <span className="font-mono text-[10px] tracking-[2px] text-[var(--muted)]">TRY:</span>
              {EXAMPLE_EMAILS.map(ex => (
                <button
                  key={ex.label}
                  onClick={() => { setNumber(ex.label); lookup(ex.label); }}
                  title={ex.note}
                  className="font-mono text-[10px] tracking-[1px] px-2.5 py-1 border border-[var(--border)] rounded-sm text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] transition-all"
                >
                  {ex.label}
                </button>
              ))}
            </div>
          )}

          {/* IP mode controls */}
          {mode === "red" && (
            <div className="flex flex-wrap items-center gap-2 mt-3">
              <span className="font-mono text-[10px] tracking-[2px] text-[var(--muted)]">TRY:</span>
              {EXAMPLE_IPS.map(ex => (
                <button
                  key={ex.label}
                  onClick={() => { setNumber(ex.label); lookup(ex.label); }}
                  title={ex.note}
                  className="font-mono text-[10px] tracking-[1px] px-2.5 py-1 border border-[var(--border)] rounded-sm text-[var(--muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] transition-all"
                >
                  {ex.label}
                </button>
              ))}
              <button
                onClick={fetchMyIp}
                className="font-mono text-[10px] tracking-[1px] px-2.5 py-1 border border-[rgba(0,255,136,0.3)] rounded-sm text-[var(--accent)] opacity-70 hover:opacity-100 hover:border-[var(--accent)] transition-all"
              >
                📍 WHAT&apos;S MY IP?
              </button>
            </div>
          )}

          <div className="font-mono text-[11px] text-[var(--muted)] mt-3 opacity-60">
            AI analysis powered by Groq · llama-3.3-70b-versatile ·{" "}
            <a href="https://github.com/rawchain" target="_blank" rel="noreferrer"
               className="text-[var(--accent)] opacity-70 hover:opacity-100 transition-opacity">
              github.com/rawchain
            </a>
          </div>
        </div>

        {/* Loading bar */}
        {loading && (
          <div className="px-8 py-8 text-center border-b border-[var(--border)]">
            <div className="h-[2px] bg-[var(--border)] rounded-sm overflow-hidden mb-3.5">
              <div
                className="h-full rounded-sm"
                style={{
                  background: "var(--accent)",
                  boxShadow: "0 0 10px var(--accent)",
                  animation: "scan 1.4s ease-in-out infinite",
                }}
              />
            </div>
            <div
              className="font-mono text-[12px] tracking-[2px] text-[var(--muted)]"
              style={{ animation: "pulse-text 1.4s ease-in-out infinite" }}
            >
              {mode === "red"      ? "QUERYING IP INTELLIGENCE..."       :
               mode === "email"    ? "QUERYING EMAIL INTELLIGENCE..."    :
               mode === "username" ? "SCANNING USERNAME ACROSS PLATFORMS..." :
               mode === "urlscan"  ? "ANALYSING URL THREAT INTEL..."     :
                                     "QUERYING AI INTELLIGENCE..."}
            </div>
          </div>
        )}

        {/* Error */}
        {error && !loading && (
          <div className="mx-8 my-5 px-5 py-4 border border-[rgba(255,60,90,0.3)] bg-[rgba(255,60,90,0.07)] rounded-sm">
            <span className="font-mono text-[12px] tracking-[1px] text-[#ff3c5a] leading-relaxed">⚠ {error}</span>
          </div>
        )}

        {/* Result — animated on each new scan */}
        {result && !loading && (
          <div
            key={resultKey}
            style={{ position: "relative", animation: "result-in 0.35s ease-out forwards" }}
          >
            {/* Scan sweep line */}
            <div
              style={{
                position: "absolute",
                top: 0, left: 0, right: 0,
                height: "2px",
                background: "var(--accent)",
                boxShadow: "0 0 12px var(--accent)",
                animation: "scan-sweep 0.7s ease-in forwards",
                pointerEvents: "none",
                zIndex: 10,
              }}
            />
            <div className="p-6 border-t border-[var(--border)]">
              {"ip" in result && !("email" in result) && !("parsed" in result) && !("username" in result) && !("url" in result)
                ? <IpResultCard       result={result as IpLookupResult}       />
                : "email" in result && !("ip" in result) && !("parsed" in result) && !("username" in result) && !("url" in result)
                  ? <EmailResultCard  result={result as EmailLookupResult}    />
                  : "username" in result
                    ? <UsernameResultCard result={result as UsernameResult}   />
                    : "url" in result && !("parsed" in result)
                      ? <UrlScanResultCard result={result as UrlScanResult}   />
                      : <ResultCard       result={result as LookupResult}     />
              }
            </div>
          </div>
        )}
      </div>

      {/* History */}
      {history.length > 0 && (
        <div className="w-full max-w-[700px] mt-6">
          <HistoryPanel history={history} onRestore={handleRestore} onClear={handleClearHistory} onExportCSV={exportHistoryCSV} />
        </div>
      )}

      {/* Footer */}
      <footer className="mt-7 font-mono text-[11px] tracking-[1px] text-[var(--muted)] text-center opacity-50">
        We are not responsible for how you use this · {new Date().getFullYear()}
      </footer>
      </div>
    </>
  );
}
