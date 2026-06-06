"use client";

import { useState, useCallback, useRef, useEffect } from "react";
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

const MODES: { id: Mode; label: string; emoji: string; desc: string }[] = [
  { id: "consumer", label: "Scam Check", emoji: "🛡️", desc: "Plain-language safety verdict for everyday callers" },
  { id: "blue", label: "Blue Team", emoji: "🔵", desc: "Defensive SOC analysis with TTPs and controls" },
  { id: "red", label: "Red Team", emoji: "🔴", desc: "OSINT deep-dive with attribution and intel value" },
];

const DEPTHS: { id: Depth; label: string; desc: string }[] = [
  { id: "quick", label: "Quick", desc: "3-sentence verdict" },
  { id: "standard", label: "Standard", desc: "Structured sections" },
  { id: "deep", label: "Deep OSINT", desc: "Full intel report" },
];

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

function flagSeverityClass(flag: string): string {
  const lower = flag.toLowerCase();
  if (
    lower.includes("high") || lower.includes("scam") ||
    lower.includes("fraud") || lower.includes("malicious")
  ) {
    return "text-red-400 border-red-400/20 bg-red-400/5";
  }
  if (
    lower.includes("medium") || lower.includes("suspicious") ||
    lower.includes("unknown") || lower.includes("unverified")
  ) {
    return "text-orange-400 border-orange-400/20 bg-orange-400/5";
  }
  return "text-slate-300 border-slate-600/40 bg-slate-800/40";
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function RiskBadge({ risk }: { risk: RiskLevel }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs font-mono-num font-semibold tracking-widest uppercase ${riskClasses(risk)}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${riskDot(risk)}`} />
      {risk}
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
    <div className="grid grid-cols-2 sm:grid-cols-3 gap-px bg-slate-700/30 rounded-lg overflow-hidden border border-slate-700/40">
      {items.map(({ label, value }) => (
        <div key={label} className="bg-[#0e1117] px-3 py-2.5">
          <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-0.5">{label}</div>
          <div className="font-mono-num text-sm text-slate-200">{value}</div>
        </div>
      ))}
    </div>
  );
}

function ResultCard({ result }: { result: LookupResult }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-xl border border-slate-700/60 bg-[#0e1117] overflow-hidden terminal-glow">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700/40 bg-slate-800/20">
        <div className="flex items-center gap-3">
          <span className="font-mono-num text-lg text-indigo-300 tracking-wide">
            {result.parsed.internationalFormat ?? result.parsed.raw}
          </span>
          <RiskBadge risk={result.risk} />
        </div>
        <span className="text-[10px] uppercase tracking-widest text-slate-500 font-mono-num">
          {result.depth} · {result.mode}
        </span>
      </div>

      <div className="p-4 space-y-4">
        {/* Summary */}
        <p className="text-slate-300 text-sm leading-relaxed border-l-2 border-indigo-500/50 pl-3">
          {result.summary}
        </p>

        {/* Meta grid */}
        <MetaGrid result={result} />

        {/* Flags */}
        {result.flags.length > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">
              Intelligence Flags
            </div>
            <div className="space-y-1.5">
              {result.flags.map((flag, i) => (
                <div
                  key={i}
                  className={`flex items-start gap-2 px-3 py-2 rounded border text-xs leading-relaxed ${flagSeverityClass(flag)}`}
                >
                  <span className="mt-0.5 shrink-0 font-mono-num text-[10px] opacity-50">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  {flag}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Full AI analysis toggle */}
        <div>
          <button
            onClick={() => setExpanded(v => !v)}
            className="flex items-center gap-2 text-[10px] uppercase tracking-widest text-slate-500 hover:text-slate-300 transition-colors mb-2"
          >
            <span className={`transition-transform duration-200 ${expanded ? "rotate-90" : ""}`}>
              ▶
            </span>
            Full AI Analysis
          </button>
          {expanded && (
            <pre className="text-xs text-slate-400 leading-relaxed whitespace-pre-wrap font-mono-num bg-slate-900/60 rounded-lg p-3 border border-slate-700/30 max-h-96 overflow-y-auto scrollbar-thin">
              {result.raw}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}

function HistoryPanel({
  history,
  onReplay,
}: {
  history: HistoryEntry[];
  onReplay: (number: string) => void;
}) {
  if (history.length === 0) return null;
  return (
    <div className="rounded-xl border border-slate-700/40 bg-[#0e1117]/60 overflow-hidden">
      <div className="px-4 py-2.5 border-b border-slate-700/30 flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-widest text-slate-500 font-syne">
          Recent Lookups
        </span>
        <span className="text-[10px] font-mono-num text-slate-600">({history.length})</span>
      </div>
      <div className="divide-y divide-slate-700/20">
        {history.map((entry, i) => (
          <button
            key={i}
            onClick={() => onReplay(entry.parsed.raw)}
            className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-slate-800/30 transition-colors text-left group"
          >
            <div className="flex items-center gap-3">
              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${riskDot(entry.risk)}`} />
              <span className="font-mono-num text-sm text-slate-300 group-hover:text-indigo-300 transition-colors">
                {entry.parsed.internationalFormat ?? entry.parsed.raw}
              </span>
              <span className="text-[10px] text-slate-600">{entry.mode}</span>
            </div>
            <div className="flex items-center gap-3">
              <span
                className={`text-[10px] font-mono-num px-1.5 py-0.5 rounded border ${riskClasses(entry.risk)}`}
              >
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
  const [number, setNumber] = useState("");
  const [mode, setMode] = useState<Mode>("consumer");
  const [depth, setDepth] = useState<Depth>("standard");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<LookupResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [remaining, setRemaining] = useState<number | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);

  const lookup = useCallback(
    async (raw?: string) => {
      const target = (raw ?? number).trim();
      if (!target) return;

      setLoading(true);
      setError(null);
      setResult(null);

      try {
        const res = await fetch("/api/lookup", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ number: target, mode, depth }),
        });

        const rem = res.headers.get("X-RateLimit-Remaining");
        if (rem !== null) setRemaining(parseInt(rem, 10));

        const data = await res.json();

        if (!res.ok) {
          setError(data.error ?? "Something went wrong.");
          return;
        }

        setResult(data);
        setHistory(prev =>
          [{ ...data, queriedAt: new Date().toLocaleTimeString() }, ...prev].slice(0, 10)
        );
      } catch {
        setError("Network error — please check your connection and try again.");
      } finally {
        setLoading(false);
      }
    },
    [number, mode, depth]
  );

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Enter" && document.activeElement === inputRef.current) {
        lookup();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [lookup]);

  return (
    <div className="min-h-screen bg-[#0a0b0d] text-slate-200">
      {/* Subtle grid overlay */}
      <div
        className="fixed inset-0 pointer-events-none opacity-[0.03]"
        style={{
          backgroundImage:
            "linear-gradient(#6366f1 1px, transparent 1px), linear-gradient(90deg, #6366f1 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      <div className="relative max-w-3xl mx-auto px-4 py-10 space-y-8">

        {/* ---------------------------------------------------------------- */}
        {/* Header                                                           */}
        {/* ---------------------------------------------------------------- */}
        <header className="space-y-1">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 text-sm">
                ⌖
              </div>
              <h1 className="font-syne text-2xl font-bold tracking-tight text-white">
                PhoneScan
              </h1>
            </div>
            {remaining !== null && (
              <div className="flex items-center gap-1.5 text-[11px] font-mono-num text-slate-500">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400/70" />
                {remaining} lookups remaining today
              </div>
            )}
          </div>
          <p className="text-slate-500 text-sm pl-11">
            Free phone intelligence · Powered by{" "}
            <span className="text-indigo-400/80">Groq AI</span>
          </p>
        </header>

        {/* ---------------------------------------------------------------- */}
        {/* Mode cards                                                       */}
        {/* ---------------------------------------------------------------- */}
        <div className="grid grid-cols-3 gap-3">
          {MODES.map(m => (
            <button
              key={m.id}
              onClick={() => setMode(m.id)}
              className={`rounded-xl border p-3 text-left transition-all duration-150 ${
                mode === m.id
                  ? "border-indigo-500/50 bg-indigo-500/10 shadow-[0_0_20px_rgba(99,102,241,0.1)]"
                  : "border-slate-700/50 bg-slate-800/20 hover:border-slate-600/50 hover:bg-slate-800/40"
              }`}
            >
              <div className="text-xl mb-1.5">{m.emoji}</div>
              <div
                className={`font-syne text-sm font-semibold mb-0.5 ${
                  mode === m.id ? "text-indigo-300" : "text-slate-300"
                }`}
              >
                {m.label}
              </div>
              <div className="text-[11px] text-slate-500 leading-snug">{m.desc}</div>
            </button>
          ))}
        </div>

        {/* ---------------------------------------------------------------- */}
        {/* Phone input + depth + examples                                   */}
        {/* ---------------------------------------------------------------- */}
        <div className="space-y-3">
          {/* Input row */}
          <div className="relative">
            <div className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600 font-mono-num text-sm select-none">
              $
            </div>
            <input
              ref={inputRef}
              type="tel"
              value={number}
              onChange={e => setNumber(e.target.value)}
              placeholder="+1 800 555 0123"
              className="w-full bg-[#0e1117] border border-slate-700/60 rounded-xl pl-9 pr-36 py-3.5 font-mono-num text-base text-slate-200 placeholder-slate-700 focus:outline-none focus:border-indigo-500/50 focus:shadow-[0_0_20px_rgba(99,102,241,0.08)] transition-all"
            />
            <button
              onClick={() => lookup()}
              disabled={loading || !number.trim()}
              className="absolute right-2 top-1/2 -translate-y-1/2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-syne font-semibold transition-colors"
            >
              {loading ? (
                <span className="flex items-center gap-1.5">
                  <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                  </svg>
                  Scanning
                </span>
              ) : (
                "Analyze →"
              )}
            </button>
          </div>

          {/* Depth pills */}
          <div className="flex items-center gap-2">
            <span className="text-[10px] uppercase tracking-widest text-slate-600 font-mono-num">
              Depth
            </span>
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

          {/* Example number chips */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] uppercase tracking-widest text-slate-600 font-mono-num">
              Examples
            </span>
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
        {/* Error banner                                                     */}
        {/* ---------------------------------------------------------------- */}
        {error && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400 font-mono-num flex items-start gap-2">
            <span className="mt-0.5 shrink-0">✕</span>
            {error}
          </div>
        )}

        {/* ---------------------------------------------------------------- */}
        {/* Loading state                                                    */}
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
              {["Parsing number metadata", "Querying Groq LLM", "Extracting intelligence"].map(
                (step, i) => (
                  <div
                    key={step}
                    className="flex items-center gap-2 text-[11px] text-slate-600 font-mono-num"
                  >
                    <svg
                      className="w-3 h-3 animate-spin"
                      style={{ animationDelay: `${i * 0.2}s` }}
                      fill="none"
                      viewBox="0 0 24 24"
                    >
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                    </svg>
                    {step}
                  </div>
                )
              )}
            </div>
          </div>
        )}

        {/* ---------------------------------------------------------------- */}
        {/* Result card                                                      */}
        {/* ---------------------------------------------------------------- */}
        {result && !loading && <ResultCard result={result} />}

        {/* ---------------------------------------------------------------- */}
        {/* History                                                          */}
        {/* ---------------------------------------------------------------- */}
        <HistoryPanel
          history={history}
          onReplay={num => { setNumber(num); lookup(num); }}
        />

        {/* ---------------------------------------------------------------- */}
        {/* Footer                                                           */}
        {/* ---------------------------------------------------------------- */}
        <footer className="pt-4 border-t border-slate-800/60 space-y-2">
          <p className="text-[11px] text-slate-600 leading-relaxed">
            <span className="text-slate-500 font-semibold">Disclaimer:</span> PhoneScan provides
            AI-generated intelligence for informational purposes only. Results are not guaranteed to
            be accurate or complete. Do not use this tool to make legal, financial, or safety
            decisions. Red Team mode is intended for authorised security research only.
          </p>
          <p className="text-[10px] text-slate-700 font-mono-num">
            PhoneScan · {new Date().getFullYear()} · Rate limited to 20 lookups / 24 h per IP
          </p>
        </footer>
      </div>
    </div>
  );
}
