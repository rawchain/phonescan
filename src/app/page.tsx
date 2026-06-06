"use client";

import { useState, useCallback, useRef, useEffect } from "react";
import dynamic from "next/dynamic";
import type { LookupResult, IpLookupResult, Mode, Depth, RiskLevel } from "@/lib/phone";

const IpMap = dynamic(() => import("@/components/IpMap"), { ssr: false });

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

const MODES: { id: Mode; label: string; placeholder: string }[] = [
  { id: "consumer", label: "📞 SCAM CHECK",    placeholder: "+1 555 123 4567  or  +44 7700 900000" },
  { id: "blue",     label: "📞 PHONE LOOKUP",  placeholder: "+1 800 555 0199  or  +49 30 12345678" },
  { id: "red",      label: "🌐 IP LOOKUP",     placeholder: "IP address or domain (e.g. 8.8.8.8 or google.com)" },
];

const DEPTHS: { id: Depth; label: string }[] = [
  { id: "quick",    label: "QUICK"      },
  { id: "standard", label: "STANDARD"   },
  { id: "deep",     label: "DEEP OSINT" },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type AnyResult = LookupResult | IpLookupResult;
type HistoryEntry = AnyResult & { queriedAt: string };

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

function isValidIp(s: string): boolean {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^[0-9a-fA-F:]{2,45}$/;
  return ipv4.test(s) || ipv6.test(s);
}

function isValidDomain(s: string): boolean {
  return /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$/.test(s);
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
    <div className="bg-[#070910] border border-[var(--border)] rounded-sm px-3.5 py-3">
      <div className="font-mono text-[10px] tracking-[2px] text-[var(--muted)] mb-1.5 uppercase">{label}</div>
      <div className="font-head font-semibold text-[15px] text-white break-words leading-tight">{value}</div>
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
  const preview = paras[0] ?? clean.slice(0, 120);

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
// Phone result card
// ---------------------------------------------------------------------------

function ResultCard({ result }: { result: LookupResult }) {
  const displayNum    = result.parsed.internationalFormat ?? result.parsed.raw;
  const cleanAnalysis = result.raw.replace(/\{[^}]*"risk"[^}]*\}\s*$/, "").trim();
  const rc = riskColour(result.risk);

  const getReport = useCallback(() =>
    ["PhoneScan Report", `${displayNum} — ${result.risk} Risk`, result.summary, "",
     "Findings:", ...result.flags.map(f => `• ${f}`), "", "Analysis:", cleanAnalysis].join("\n"),
    [result] // eslint-disable-line react-hooks/exhaustive-deps
  );
  const getShare = useCallback(() =>
    `${displayNum} scanned on PhoneScan — ${result.risk} risk. ${result.summary} phonescan-gamma.vercel.app`,
    [result] // eslint-disable-line react-hooks/exhaustive-deps
  );

  const metaItems = [
    { label: "NUMBER",    value: displayNum },
    { label: "COUNTRY",   value: result.parsed.region ?? "—" },
    { label: "CODE",      value: result.parsed.country ?? "—" },
    { label: "LINE TYPE", value: result.parsed.type.toUpperCase() },
    { label: "E.164",     value: result.parsed.e164 ?? "—" },
    { label: "VALID",     value: result.parsed.valid ? "YES ✓" : "NO ✗" },
    { label: "DEPTH",     value: result.depth.toUpperCase() },
    { label: "MODE",      value: result.mode.toUpperCase() },
  ];

  return (
    <div className="border border-[var(--border)] rounded-sm bg-[var(--surface)] overflow-hidden">
      <div className="px-6 py-4 border-b border-[var(--border)]">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="font-mono text-[10px] tracking-[3px] text-[var(--muted)] mb-1.5">
              ANALYSIS COMPLETE
              <span className="ml-2 px-1.5 py-0.5 border border-[var(--border)] rounded-sm text-[9px]">libphonenumber + groq</span>
            </div>
            <div className="font-mono text-xl text-white tracking-[2px] break-all">{displayNum}</div>
          </div>
          <div className="flex items-center gap-2 shrink-0 mt-1">
            <CopyBtn label="COPY"  getText={getReport} />
            <CopyBtn label="SHARE" getText={getShare}  />
          </div>
        </div>
      </div>

      <div className="px-6 py-5 space-y-5">
        <div className={`flex items-center gap-4 px-5 py-4 border rounded-sm ${rc.bg} ${rc.border}`}>
          <span className="text-3xl leading-none">{rc.icon}</span>
          <div>
            <div className={`font-head font-bold text-xl tracking-[2px] ${rc.text}`}>{rc.label}</div>
            <div className="font-head text-[14px] text-[var(--text)] mt-0.5 leading-snug">{result.summary}</div>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {metaItems.map(({ label, value }) => (
            <InfoCell key={label} label={label} value={value} />
          ))}
        </div>

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

function ScoreBar({ label, score, lowGood }: { label: string; score: number | null; lowGood?: boolean }) {
  if (score === null) return null;
  const pct = Math.min(100, Math.max(0, score));
  const colour = lowGood
    ? (pct <= 20 ? "#00ff88" : pct <= 60 ? "#ffb800" : "#ff3c5a")
    : (pct >= 61 ? "#ff3c5a" : pct >= 31 ? "#ffb800" : "#00ff88");
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

function IpResultCard({ result }: { result: IpLookupResult }) {
  const rc = riskColour(result.risk);
  const flag = flagEmoji(result.countryCode);
  const locationStr = [result.city, result.region, result.country].filter(Boolean).join(", ") || "Unknown";

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
  const getShare = useCallback(() =>
    `${result.ip} scanned on PhoneScan — ${result.risk} risk. ${result.summary} phonescan-gamma.vercel.app`,
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
    { label: "TIMEZONE",      value: result.timezone ?? "—" },
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
            <div className="font-mono text-xl text-white tracking-[2px] break-all">{result.ip}</div>
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
            <CopyBtn label="COPY"  getText={getReport} />
            <CopyBtn label="SHARE" getText={getShare}  />
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
            <IndicatorPill label="VPN"           active={result.is_vpn}           colour="#ffb800" />
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
// History
// ---------------------------------------------------------------------------

function HistoryPanel({ history, onReplay }: { history: HistoryEntry[]; onReplay: (n: string) => void }) {
  if (history.length === 0) return null;
  return (
    <div className="border border-[var(--border)] rounded-sm bg-[var(--surface)] overflow-hidden">
      <div className="px-5 py-3 border-b border-[var(--border)]">
        <span className="font-mono text-[10px] tracking-[3px] text-[var(--muted)]">
          {"// RECENT LOOKUPS ("}{history.length}{")"}
        </span>
      </div>
      <div className="divide-y divide-[var(--border)]">
        {history.map((entry, i) => {
          const rc = riskColour(entry.risk);
          const isIp = "ip" in entry;
          const displayVal = isIp
            ? (entry as IpLookupResult).ip
            : ((entry as LookupResult).parsed.internationalFormat ?? (entry as LookupResult).parsed.raw);
          const raw = isIp ? (entry as IpLookupResult).ip : (entry as LookupResult).parsed.raw;
          return (
            <button
              key={i}
              onClick={() => onReplay(raw)}
              className="w-full flex items-center justify-between px-5 py-2.5 hover:bg-[#0d1117] transition-colors text-left group"
            >
              <div className="flex items-center gap-3 min-w-0">
                <span className="font-mono text-[10px] text-[var(--muted)]">{String(i + 1).padStart(2, "0")}</span>
                <span className={`font-mono text-[13px] tracking-wide group-hover:text-[var(--accent)] transition-colors truncate ${rc.text}`}>
                  {displayVal}
                </span>
                <span className="font-mono text-[10px] text-[var(--muted)] shrink-0">
                  {isIp ? "IP" : (entry as LookupResult).mode.toUpperCase()}
                </span>
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
  const [mode,      setMode]      = useState<Mode>("consumer");
  const [depth,     setDepth]     = useState<Depth>("standard");
  const [loading,   setLoading]   = useState(false);
  const [result,    setResult]    = useState<AnyResult | null>(null);
  const [error,     setError]     = useState<string | null>(null);
  const [remaining, setRemaining] = useState<number | null>(null);
  const [history,   setHistory]   = useState<HistoryEntry[]>([]);
  const inputRef       = useRef<HTMLInputElement>(null);
  const myIpRef        = useRef<string | null>(null);
  const hasAutoRunRef  = useRef(false);

  const lookup = useCallback(async (raw?: string) => {
    const target = (raw ?? number).trim();
    if (!target) return;

    // IP mode validation — accept IPs and domain names
    if (mode === "red" && !isValidIp(target) && !isValidDomain(target)) {
      setError("Invalid input. Enter a valid IP address (e.g. 8.8.8.8) or domain (e.g. google.com).");
      return;
    }

    setLoading(true); setError(null); setResult(null);
    try {
      const endpoint = mode === "red" ? "/api/iplookup" : "/api/lookup";
      const body = mode === "red"
        ? { ip: target, depth }
        : { number: target, mode, depth };

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
      setHistory(prev => [{ ...data, queriedAt: new Date().toLocaleTimeString() }, ...prev].slice(0, 10));
    } catch {
      setError("Network error — check your connection and try again.");
    } finally {
      setLoading(false);
    }
  }, [number, mode, depth]);

  const fetchMyIp = useCallback(async () => {
    try {
      const res = await fetch("https://api.ipify.org?format=json");
      const { ip } = await res.json() as { ip: string };
      setNumber(ip);
    } catch {
      setError("Could not detect your IP address.");
    }
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
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [lookup]);

  return (
    <div
      className="min-h-screen flex flex-col items-center px-4 py-10"
      style={{
        background: `
          radial-gradient(ellipse at 20% 0%,   rgba(0,255,136,0.04) 0%, transparent 60%),
          radial-gradient(ellipse at 80% 100%, rgba(255,60,90,0.04)  0%, transparent 60%),
          repeating-linear-gradient(0deg,   transparent, transparent 40px, rgba(255,255,255,0.01) 40px, rgba(255,255,255,0.01) 41px),
          repeating-linear-gradient(90deg,  transparent, transparent 40px, rgba(255,255,255,0.01) 40px, rgba(255,255,255,0.01) 41px),
          #0a0c10
        `,
      }}
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

      {/* Tab bar */}
      <div className="flex w-full max-w-[700px]">
        {MODES.map((m, i) => (
          <button
            key={m.id}
            onClick={() => { setMode(m.id); setResult(null); setError(null); }}
            className={`flex-1 py-3 font-head font-bold text-[13px] tracking-[2px] border transition-all duration-150 ${
              i === 0 ? "rounded-tl-sm" : ""
            } ${
              i === MODES.length - 1 ? "rounded-tr-sm border-l-0" : i > 0 ? "border-l-0" : ""
            } ${
              mode === m.id
                ? "text-[var(--accent)] border-[var(--border)] bg-[var(--surface)]"
                : "text-[var(--muted)] border-[var(--border)] bg-[var(--surface)] hover:bg-[#141a22]"
            }`}
            style={mode === m.id ? { borderBottomColor: "var(--surface)" } : {}}
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
          className="flex items-center px-4 border border-l-0 border-[var(--border)] bg-[var(--surface)] rounded-tr-sm text-[var(--muted)] hover:text-white transition-colors"
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
            {mode === "red" ? "// ENTER IP ADDRESS OR DOMAIN" : "// ENTER NUMBER (with country code)"}
          </span>
          <div className="flex gap-3">
            <input
              ref={inputRef}
              type={mode === "red" ? "text" : "tel"}
              value={number}
              onChange={e => setNumber(e.target.value)}
              placeholder={MODES.find(m => m.id === mode)?.placeholder ?? "+1 555 123 4567"}
              maxLength={mode === "red" ? 45 : 20}
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
              style={{ background: "var(--accent)" }}
              onMouseEnter={e => { if (!e.currentTarget.disabled) { e.currentTarget.style.background = "#00ffaa"; e.currentTarget.style.boxShadow = "var(--glow)"; e.currentTarget.style.transform = "translateY(-1px)"; }}}
              onMouseLeave={e => { e.currentTarget.style.background = "var(--accent)"; e.currentTarget.style.boxShadow = ""; e.currentTarget.style.transform = ""; }}
            >
              {loading ? "SCANNING..." : "SCAN"}
            </button>
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

          {/* Example chips */}
          {mode !== "red" && (
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
              {mode === "red" ? "QUERYING IP INTELLIGENCE..." : "QUERYING AI INTELLIGENCE..."}
            </div>
          </div>
        )}

        {/* Error */}
        {error && !loading && (
          <div className="mx-8 my-5 px-5 py-4 border border-[rgba(255,60,90,0.3)] bg-[rgba(255,60,90,0.07)] rounded-sm">
            <span className="font-mono text-[12px] tracking-[1px] text-[#ff3c5a] leading-relaxed">⚠ {error}</span>
          </div>
        )}

        {/* Result */}
        {result && !loading && (
          <div className="p-6 border-t border-[var(--border)]">
            {"ip" in result
              ? <IpResultCard result={result as IpLookupResult} />
              : <ResultCard   result={result as LookupResult}   />
            }
          </div>
        )}
      </div>

      {/* History */}
      {history.length > 0 && (
        <div className="w-full max-w-[700px] mt-6">
          <HistoryPanel history={history} onReplay={n => { setNumber(n); lookup(n); }} />
        </div>
      )}

      {/* Footer */}
      <footer className="mt-7 font-mono text-[11px] tracking-[1px] text-[var(--muted)] text-center opacity-50">
        We are not responsible for how you use this · {new Date().getFullYear()}
      </footer>
    </div>
  );
}
