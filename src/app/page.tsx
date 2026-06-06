"use client";

import { useState, useCallback, useRef, useEffect, useLayoutEffect } from "react";
import type { LookupResult, Mode, Depth, RiskLevel } from "@/lib/phone";

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

const MODES: { id: Mode; label: string; desc: string; icon: React.ReactNode }[] = [
  {
    id: "consumer",
    label: "Scam Check",
    desc: "Plain-language safety verdict for everyday callers",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.75}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
      </svg>
    ),
  },
  {
    id: "blue",
    label: "Blue Team",
    desc: "Defensive SOC analysis with TTPs and controls",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.75}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
      </svg>
    ),
  },
  {
    id: "red",
    label: "Red Team",
    desc: "OSINT deep-dive with attribution and intel value",
    icon: (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.75}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" />
      </svg>
    ),
  },
];

const DEPTHS: { id: Depth; label: string; desc: string }[] = [
  { id: "quick",    label: "Quick",     desc: "3-sentence verdict" },
  { id: "standard", label: "Standard",  desc: "Structured sections" },
  { id: "deep",     label: "Deep OSINT", desc: "Full intel report" },
];

const MODE_COLOURS: Record<Mode, { active: string; icon: string }> = {
  consumer: { active: "border-indigo-500/60 bg-indigo-500/10 shadow-[0_0_24px_rgba(99,102,241,0.12)]", icon: "text-indigo-400 bg-indigo-500/15 border-indigo-500/25" },
  blue:     { active: "border-blue-500/60 bg-blue-500/10 shadow-[0_0_24px_rgba(59,130,246,0.12)]",   icon: "text-blue-400 bg-blue-500/15 border-blue-500/25" },
  red:      { active: "border-rose-500/60 bg-rose-500/10 shadow-[0_0_24px_rgba(244,63,94,0.12)]",    icon: "text-rose-400 bg-rose-500/15 border-rose-500/25" },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type HistoryEntry = LookupResult & { queriedAt: string };

function riskClasses(risk: RiskLevel): string {
  switch (risk) {
    case "High":   return "risk-high";
    case "Medium": return "risk-medium";
    case "Low":    return "risk-low";
    default:       return "risk-unknown";
  }
}

function riskDot(risk: RiskLevel): string {
  switch (risk) {
    case "High":   return "bg-red-400";
    case "Medium": return "bg-orange-400";
    case "Low":    return "bg-green-400";
    default:       return "bg-slate-400";
  }
}

type FlagSeverity = "danger" | "warning" | "safe";

const DANGER_WORDS = [
  "scam", "fraud", "malicious", "reported", "dangerous", "illegal",
  "phishing", "vishing", "smishing", "blacklist", "blacklisted",
  "criminal", "threatening", "extortion", "impersonat",
];
const WARNING_WORDS = [
  "premium", "voip", "unknown", "unverified", "spoofable", "caution",
  "potential", "risk", "suspicious", "unconfirmed", "questionable",
  "unusual", "offshore", "anonymous", "untraceable",
];

function classifyFlag(flag: string): FlagSeverity {
  const lower = flag.toLowerCase();
  if (DANGER_WORDS.some(w => lower.includes(w)))  return "danger";
  if (WARNING_WORDS.some(w => lower.includes(w))) return "warning";
  return "safe";
}

const FLAG_STYLES: Record<FlagSeverity, {
  wrapper: string;
  icon: string;
  iconColor: string;
  labelColor: string;
  label: string;
}> = {
  danger: {
    wrapper:    "border-l-2 border-l-red-500 border border-red-500/20 bg-red-500/10 text-red-200",
    icon:       "⚠",
    iconColor:  "text-red-400",
    labelColor: "text-red-400",
    label:      "danger",
  },
  warning: {
    wrapper:    "border-l-2 border-l-amber-400 border border-amber-400/20 bg-amber-400/10 text-amber-100",
    icon:       "⚡",
    iconColor:  "text-amber-400",
    labelColor: "text-amber-400",
    label:      "warning",
  },
  safe: {
    wrapper:    "border-l-2 border-l-emerald-500 border border-emerald-500/20 bg-emerald-500/5 text-emerald-200",
    icon:       "✓",
    iconColor:  "text-emerald-400",
    labelColor: "text-emerald-400",
    label:      "safe",
  },
};

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function RiskBadge({ risk }: { risk: RiskLevel }) {
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs font-mono-num font-semibold tracking-widest uppercase ${riskClasses(risk)}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${riskDot(risk)}`} />
      {risk}
    </span>
  );
}

function PillBadge({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full border border-slate-700/50 bg-slate-800/50 text-[10px] font-mono-num text-slate-400 tracking-wide">
      {children}
    </span>
  );
}

function MetaGrid({ result }: { result: LookupResult }) {
  const items = [
    { label: "Country",  value: result.parsed.country  ?? "—" },
    { label: "Region",   value: result.parsed.region   ?? "—" },
    { label: "Type",     value: result.parsed.type },
    { label: "Valid",    value: result.parsed.valid ? "Yes" : "No" },
    { label: "E.164",    value: result.parsed.e164     ?? "—" },
    { label: "Mode",     value: result.mode },
  ];
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 gap-px bg-slate-700/20 rounded-lg overflow-hidden border border-slate-700/30">
      {items.map(({ label, value }) => (
        <div key={label} className="bg-[#0e1117] px-4 py-3">
          <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">{label}</div>
          <div className="font-mono-num text-sm text-slate-200 truncate">{value}</div>
        </div>
      ))}
    </div>
  );
}

function AnalysisExpander({ text }: { text: string }) {
  const [expanded, setExpanded] = useState(false);
  const contentRef = useRef<HTMLDivElement>(null);
  const [height, setHeight] = useState(0);

  useLayoutEffect(() => {
    if (contentRef.current) setHeight(contentRef.current.scrollHeight);
  }, [text]);

  const displayText = text.replace(/\{[^}]*"risk"[^}]*\}\s*$/, "").trim();
  const paragraphs  = displayText.split(/\n{2,}/).map(p => p.replace(/\n/g, " ").trim()).filter(Boolean);
  const preview     = paragraphs[0] ?? displayText.slice(0, 120);

  return (
    <div className="rounded-lg border border-slate-700/50 overflow-hidden">
      {/* Toggle button — visible, bordered, chevron rotates */}
      <button
        onClick={() => setExpanded(v => !v)}
        className={`w-full flex items-center justify-between px-4 py-3 text-left transition-colors duration-150 ${
          expanded ? "bg-slate-800/70 border-b border-slate-700/40" : "bg-slate-800/40 hover:bg-slate-800/60"
        }`}
      >
        <div className="flex items-center gap-2.5">
          <svg
            className={`w-4 h-4 text-indigo-400 transition-transform duration-300 ${expanded ? "rotate-90" : "rotate-0"}`}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
          <span className="text-xs font-semibold text-slate-200 tracking-wide">Full AI Analysis</span>
        </div>
        <span className="text-[10px] font-mono-num text-slate-500">
          {expanded ? "collapse" : `${paragraphs.length} section${paragraphs.length !== 1 ? "s" : ""}`}
        </span>
      </button>

      {/* One-line preview with fade */}
      {!expanded && (
        <div className="relative px-4 py-2.5 bg-slate-900/20">
          <p className="text-xs text-slate-500 leading-relaxed truncate pr-10">{preview}</p>
          <div className="absolute inset-y-0 right-0 w-16 bg-gradient-to-l from-[#0e1117] to-transparent pointer-events-none" />
        </div>
      )}

      {/* Height-animated expanded body */}
      <div style={{ height: expanded ? height : 0, transition: "height 320ms cubic-bezier(0.4,0,0.2,1)", overflow: "hidden" }}>
        <div ref={contentRef} className="px-4 py-4 bg-slate-900/20 space-y-3">
          {paragraphs.map((para, i) => (
            <p key={i} className="text-xs text-slate-400 leading-relaxed">{para}</p>
          ))}
        </div>
      </div>
    </div>
  );
}

function useCopyButton(getText: () => string) {
  const [copied, setCopied] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const copy = useCallback(() => {
    navigator.clipboard.writeText(getText()).then(() => {
      setCopied(true);
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => setCopied(false), 2000);
    });
  }, [getText]);
  return { copied, copy };
}

function CopyButton({ label, getText }: { label: string; getText: () => string }) {
  const { copied, copy } = useCopyButton(getText);
  return (
    <button
      onClick={copy}
      className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[11px] font-mono-num transition-all duration-150 ${
        copied
          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
          : "border-slate-600/50 bg-slate-800/40 text-slate-400 hover:border-slate-500/60 hover:text-slate-200 hover:bg-slate-700/40"
      }`}
    >
      {copied ? (
        <>
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
          Copied
        </>
      ) : (
        <>
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <rect x="9" y="9" width="13" height="13" rx="2" strokeLinecap="round" strokeLinejoin="round" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
          </svg>
          {label}
        </>
      )}
    </button>
  );
}

function ResultCard({ result }: { result: LookupResult }) {
  const displayNumber = result.parsed.internationalFormat ?? result.parsed.raw;
  const cleanAnalysis = result.raw.replace(/\{[^}]*"risk"[^}]*\}\s*$/, "").trim();

  const getReportText = useCallback(() =>
    ["PhoneScan Report", `${displayNumber} — ${result.risk} Risk`, result.summary, "",
     "Findings:", ...result.flags.map(f => `• ${f}`), "", "Analysis:", cleanAnalysis].join("\n"),
    [displayNumber, result.risk, result.summary, result.flags, cleanAnalysis]
  );

  const getShareText = useCallback(() =>
    `${displayNumber} scanned on PhoneScan — ${result.risk} risk. ${result.summary} phonescan-gamma.vercel.app`,
    [displayNumber, result.risk, result.summary]
  );

  return (
    <div className="rounded-xl border border-slate-700/50 bg-[#0e1117] overflow-hidden terminal-glow">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-700/40 bg-slate-800/20">
        <div className="flex items-center gap-3 min-w-0">
          <span className="font-mono-num text-lg text-indigo-300 tracking-wide truncate">
            {displayNumber}
          </span>
          <RiskBadge risk={result.risk} />
        </div>
        <div className="flex items-center gap-2 shrink-0 ml-3">
          <CopyButton label="Copy"  getText={getReportText} />
          <CopyButton label="Share" getText={getShareText}  />
          <PillBadge>{result.depth}</PillBadge>
          <PillBadge>{result.mode}</PillBadge>
        </div>
      </div>

      <div className="p-5 space-y-5">
        {/* Summary */}
        <p className="text-slate-300 text-sm leading-relaxed border-l-2 border-indigo-500/50 pl-4">
          {result.summary}
        </p>

        {/* Meta grid */}
        <MetaGrid result={result} />

        {/* Flags */}
        {result.flags.length > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-2.5">
              Intelligence Flags
            </div>
            <div className="space-y-2">
              {result.flags.map((flag, i) => {
                const severity = classifyFlag(flag);
                const style    = FLAG_STYLES[severity];
                return (
                  <div
                    key={i}
                    className={`flex items-start gap-2.5 px-3.5 py-2.5 rounded-r-lg text-xs leading-relaxed ${style.wrapper}`}
                  >
                    <span className={`shrink-0 text-sm leading-none mt-px font-bold ${style.iconColor}`}>
                      {style.icon}
                    </span>
                    <span className="flex-1 min-w-0">{flag}</span>
                    <span className={`shrink-0 self-center font-mono-num text-[9px] uppercase tracking-widest ${style.labelColor}`}>
                      {style.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Full AI analysis expandable */}
        <AnalysisExpander text={result.raw} />
      </div>
    </div>
  );
}

function HistoryPanel({ history, onReplay }: { history: HistoryEntry[]; onReplay: (n: string) => void }) {
  if (history.length === 0) return null;
  return (
    <div className="rounded-xl border border-slate-700/40 bg-[#0e1117]/60 overflow-hidden">
      <div className="px-5 py-3 border-b border-slate-700/30 flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-widest text-slate-500 font-syne">Recent Lookups</span>
        <span className="text-[10px] font-mono-num text-slate-600">({history.length})</span>
      </div>
      <div className="divide-y divide-slate-700/20">
        {history.map((entry, i) => (
          <button
            key={i}
            onClick={() => onReplay(entry.parsed.raw)}
            className="w-full flex items-center justify-between px-5 py-2.5 hover:bg-slate-800/30 transition-colors text-left group"
          >
            <div className="flex items-center gap-3 min-w-0">
              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${riskDot(entry.risk)}`} />
              <span className="font-mono-num text-sm text-slate-300 group-hover:text-indigo-300 transition-colors truncate">
                {entry.parsed.internationalFormat ?? entry.parsed.raw}
              </span>
              <span className="text-[10px] text-slate-600 shrink-0">{entry.mode}</span>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <span className={`text-[10px] font-mono-num px-1.5 py-0.5 rounded border ${riskClasses(entry.risk)}`}>
                {entry.risk}
              </span>
              <span className="text-[10px] text-slate-600 font-mono-num">{entry.queriedAt}</span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function Home() {
  const [number,    setNumber]    = useState("");
  const [mode,      setMode]      = useState<Mode>("consumer");
  const [depth,     setDepth]     = useState<Depth>("standard");
  const [loading,   setLoading]   = useState(false);
  const [result,    setResult]    = useState<LookupResult | null>(null);
  const [error,     setError]     = useState<string | null>(null);
  const [remaining, setRemaining] = useState<number | null>(null);
  const [history,   setHistory]   = useState<HistoryEntry[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);

  const lookup = useCallback(async (raw?: string) => {
    const target = (raw ?? number).trim();
    if (!target) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const res  = await fetch("/api/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ number: target, mode, depth }),
      });
      const rem = res.headers.get("X-RateLimit-Remaining");
      if (rem !== null) setRemaining(parseInt(rem, 10));
      const data = await res.json();
      if (!res.ok) { setError(data.error ?? "Something went wrong."); return; }
      setResult(data);
      setHistory(prev => [{ ...data, queriedAt: new Date().toLocaleTimeString() }, ...prev].slice(0, 10));
    } catch {
      setError("Network error — please check your connection and try again.");
    } finally {
      setLoading(false);
    }
  }, [number, mode, depth]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Enter" && document.activeElement === inputRef.current) lookup();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [lookup]);

  return (
    <div className="min-h-screen bg-[#0a0b0d] text-slate-200">
      {/* Global grid overlay */}
      <div
        className="fixed inset-0 pointer-events-none opacity-[0.025]"
        style={{
          backgroundImage: "linear-gradient(#6366f1 1px, transparent 1px), linear-gradient(90deg, #6366f1 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      <div className="relative max-w-[900px] mx-auto px-6 py-10 space-y-8">

        {/* ---------------------------------------------------------------- */}
        {/* Nav header                                                       */}
        {/* ---------------------------------------------------------------- */}
        <header className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 text-sm select-none">
              ⌖
            </div>
            <span className="font-syne text-xl font-bold tracking-tight text-white">PhoneScan</span>
            <span className="text-slate-700 text-sm hidden sm:block">·</span>
            <span className="text-slate-500 text-sm hidden sm:block">
              Powered by <span className="text-indigo-400/80">Groq AI</span>
            </span>
          </div>
          <div className="flex items-center gap-4">
            {remaining !== null && (
              <div className="flex items-center gap-1.5 text-[11px] font-mono-num text-slate-500">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400/70" />
                {remaining} lookups remaining today
              </div>
            )}
            <a
              href="https://github.com/rawchain"
              target="_blank"
              rel="noreferrer"
              className="text-slate-500 hover:text-white transition-colors duration-150"
              aria-label="GitHub"
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
              </svg>
            </a>
          </div>
        </header>

        {/* ---------------------------------------------------------------- */}
        {/* Hero                                                             */}
        {/* ---------------------------------------------------------------- */}
        <div className="relative rounded-xl overflow-hidden border border-slate-800/50 px-6 py-6">
          {/* Scanline texture */}
          <div
            className="absolute inset-0 pointer-events-none opacity-[0.035]"
            style={{ backgroundImage: "repeating-linear-gradient(0deg,#e2e8f0 0px,#e2e8f0 1px,transparent 1px,transparent 4px)" }}
          />
          {/* Radial accent */}
          <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(ellipse_55%_100%_at_20%_50%,rgba(99,102,241,0.07),transparent)]" />
          <div className="relative">
            <h2 className="font-syne text-[2rem] font-extrabold tracking-tight text-white leading-tight mb-2">
              Who just called you?
              <span
                className="inline-block w-[3px] h-[0.9em] ml-2 align-middle bg-indigo-400"
                style={{ animation: "blink 1s step-end infinite" }}
              />
            </h2>
            <p className="text-slate-400 text-sm leading-relaxed">
              Free AI-powered phone intelligence —{" "}
              <span className="text-slate-300">scam detection</span>,{" "}
              <span className="text-slate-300">security research</span> and{" "}
              <span className="text-slate-300">OSINT</span> in seconds.
            </p>
          </div>
        </div>

        {/* ---------------------------------------------------------------- */}
        {/* Mode cards                                                       */}
        {/* ---------------------------------------------------------------- */}
        <div className="grid grid-cols-3 gap-4">
          {MODES.map(m => {
            const active  = mode === m.id;
            const colours = MODE_COLOURS[m.id];
            return (
              <button
                key={m.id}
                onClick={() => setMode(m.id)}
                className={`rounded-xl border p-4 text-left transition-all duration-200 ${
                  active
                    ? colours.active
                    : "border-slate-700/40 bg-slate-800/20 hover:border-slate-600/50 hover:bg-slate-800/40"
                }`}
              >
                {/* Icon box */}
                <div className={`w-9 h-9 rounded-lg border flex items-center justify-center mb-3 transition-colors ${
                  active ? colours.icon : "text-slate-500 bg-slate-800/50 border-slate-700/40"
                }`}>
                  {m.icon}
                </div>
                <div className={`font-syne text-sm font-semibold mb-1 ${active ? "text-white" : "text-slate-300"}`}>
                  {m.label}
                </div>
                <div className="text-[11px] text-slate-500 leading-snug">{m.desc}</div>
              </button>
            );
          })}
        </div>

        {/* ---------------------------------------------------------------- */}
        {/* Phone input + depth + examples                                   */}
        {/* ---------------------------------------------------------------- */}
        <div className="space-y-3">
          {/* Input row — 52px tall */}
          <div className="relative flex items-center">
            {/* Phone icon */}
            <div className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.75}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 6.75c0 8.284 6.716 15 15 15h2.25a2.25 2.25 0 002.25-2.25v-1.372c0-.516-.351-.966-.852-1.091l-4.423-1.106c-.44-.11-.902.055-1.173.417l-.97 1.293c-.282.376-.769.542-1.21.38a12.035 12.035 0 01-7.143-7.143c-.162-.441.004-.928.38-1.21l1.293-.97c.363-.271.527-.734.417-1.173L6.963 3.102a1.125 1.125 0 00-1.091-.852H4.5A2.25 2.25 0 002.25 4.5v2.25z" />
              </svg>
            </div>
            <input
              ref={inputRef}
              type="tel"
              value={number}
              onChange={e => setNumber(e.target.value)}
              placeholder="+1 800 555 0123"
              className="w-full h-[52px] bg-[#0e1117] border border-slate-700/60 rounded-xl pl-11 pr-[140px] font-mono-num text-base text-slate-200 placeholder-slate-700 focus:outline-none focus:border-blue-500/60 focus:ring-2 focus:ring-blue-500/20 transition-all"
            />
            <button
              onClick={() => lookup()}
              disabled={loading || !number.trim()}
              className="absolute right-2 h-[38px] px-5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-syne font-semibold transition-colors"
            >
              {loading ? (
                <span className="flex items-center gap-1.5">
                  <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                  </svg>
                  Scanning
                </span>
              ) : "Analyze →"}
            </button>
          </div>

          {/* Depth pills */}
          <div className="flex items-center gap-2.5">
            <span className="text-[10px] uppercase tracking-widest text-slate-600 font-mono-num">Depth</span>
            <div className="flex gap-1.5">
              {DEPTHS.map(d => (
                <button
                  key={d.id}
                  onClick={() => setDepth(d.id)}
                  title={d.desc}
                  className={`px-3 py-1 rounded-full text-xs font-mono-num transition-all ${
                    depth === d.id
                      ? "bg-indigo-500/20 text-indigo-300 border border-indigo-500/40"
                      : "text-slate-500 border border-slate-700/40 hover:text-slate-300 hover:border-slate-600/50"
                  }`}
                >
                  {d.label}
                </button>
              ))}
            </div>
          </div>

          {/* Example chips */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] uppercase tracking-widest text-slate-600 font-mono-num">Examples</span>
            {EXAMPLE_NUMBERS.map(ex => (
              <button
                key={ex.number}
                onClick={() => { setNumber(ex.number); lookup(ex.number); }}
                title={ex.note}
                className="px-2.5 py-1 rounded-md border border-slate-700/40 bg-slate-800/30 hover:bg-slate-700/30 hover:border-slate-600/50 transition-all group"
              >
                <span className="font-mono-num text-[11px] text-slate-400 group-hover:text-indigo-300 transition-colors">
                  {ex.label}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* ---------------------------------------------------------------- */}
        {/* Error                                                            */}
        {/* ---------------------------------------------------------------- */}
        {error && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-5 py-3.5 text-sm text-red-400 font-mono-num flex items-start gap-2">
            <span className="mt-0.5 shrink-0">✕</span>
            {error}
          </div>
        )}

        {/* ---------------------------------------------------------------- */}
        {/* Loading                                                          */}
        {/* ---------------------------------------------------------------- */}
        {loading && (
          <div className="rounded-xl border border-slate-700/40 bg-[#0e1117] p-6 space-y-3">
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 rounded-full bg-indigo-400 animate-pulse" />
              <span className="font-mono-num text-sm text-slate-400">
                Analysing {number} <span className="cursor-blink" />
              </span>
            </div>
            <div className="space-y-2">
              {["Parsing number metadata", "Querying Groq LLM", "Extracting intelligence"].map((step, i) => (
                <div key={step} className="flex items-center gap-2 text-[11px] text-slate-600 font-mono-num">
                  <svg className="w-3 h-3 animate-spin" style={{ animationDelay: `${i * 0.2}s` }} fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                  </svg>
                  {step}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ---------------------------------------------------------------- */}
        {/* Result                                                           */}
        {/* ---------------------------------------------------------------- */}
        {result && !loading && <ResultCard result={result} />}

        {/* ---------------------------------------------------------------- */}
        {/* History                                                          */}
        {/* ---------------------------------------------------------------- */}
        <HistoryPanel history={history} onReplay={num => { setNumber(num); lookup(num); }} />

        {/* ---------------------------------------------------------------- */}
        {/* Footer                                                           */}
        {/* ---------------------------------------------------------------- */}
        <footer className="pt-4 border-t border-slate-800/50">
          <p className="text-[11px] text-slate-600 leading-relaxed">
            PhoneScan provides AI-generated intelligence for informational purposes only. Results are not guaranteed to be accurate or complete. Do not use this tool to make legal, financial, or safety decisions. Red Team mode is intended for authorised security research only.
          </p>
          <p className="text-[10px] text-slate-700 font-mono-num mt-1.5">
            PhoneScan · {new Date().getFullYear()} · Rate limited to 20 lookups / 24 h per IP
          </p>
        </footer>

      </div>
    </div>
  );
}
