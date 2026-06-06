import { NextRequest, NextResponse } from "next/server";
import Groq from "groq-sdk";
import {
  getSystemPrompt,
  buildUserPrompt,
  type Depth,
  type RiskLevel,
  type IpLookupResult,
} from "@/lib/phone";

// ---------------------------------------------------------------------------
// Rate limiter — in-memory, per-IP, rolling 24-hour window
// ---------------------------------------------------------------------------

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const rateLimitMap = new Map<string, RateLimitEntry>();
const WINDOW_MS = 24 * 60 * 60 * 1000;
const LIMIT = parseInt(process.env.RATE_LIMIT_PER_DAY ?? "20", 10);

function checkRateLimit(ip: string): { allowed: boolean; remaining: number } {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now >= entry.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return { allowed: true, remaining: LIMIT - 1 };
  }
  if (entry.count >= LIMIT) return { allowed: false, remaining: 0 };
  entry.count += 1;
  return { allowed: true, remaining: LIMIT - entry.count };
}

// ---------------------------------------------------------------------------
// Groq client
// ---------------------------------------------------------------------------

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

const MAX_TOKENS: Record<Depth, number> = {
  quick: 400,
  standard: 700,
  deep: 1200,
};

// ---------------------------------------------------------------------------
// JSON extraction
// ---------------------------------------------------------------------------

function extractJson(text: string): { risk: RiskLevel; summary: string; flags: string[] } | null {
  const lastClose = text.lastIndexOf("}");
  if (lastClose === -1) return null;
  const firstOpen = text.lastIndexOf("{", lastClose);
  if (firstOpen === -1) return null;
  try {
    const raw = JSON.parse(text.slice(firstOpen, lastClose + 1));
    const validRisk: RiskLevel[] = ["High", "Medium", "Low", "Unknown"];
    return {
      risk: validRisk.includes(raw.risk) ? raw.risk : "Unknown",
      summary: typeof raw.summary === "string" ? raw.summary.trim() : "No summary provided.",
      flags: Array.isArray(raw.flags)
        ? raw.flags.filter((f: unknown) => typeof f === "string").slice(0, 10)
        : [],
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getClientIp(req: NextRequest): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ??
    req.headers.get("x-real-ip") ??
    "unknown"
  );
}

function isValidIpAddress(s: string): boolean {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^[0-9a-fA-F:]{2,45}$/;
  return ipv4.test(s) || ipv6.test(s);
}

// ---------------------------------------------------------------------------
// Route handler
// ---------------------------------------------------------------------------

export async function POST(req: NextRequest) {
  // --- Rate limit ---
  const clientIp = getClientIp(req);
  const { allowed, remaining } = checkRateLimit(clientIp);
  if (!allowed) {
    return NextResponse.json(
      { error: "You've reached the daily lookup limit. Please try again in 24 hours." },
      { status: 429, headers: { "X-RateLimit-Remaining": "0" } }
    );
  }

  // --- Parse body ---
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON in request body." }, { status: 400 });
  }

  const { ip: rawIp, depth: rawDepth } = body as Record<string, unknown>;

  if (typeof rawIp !== "string" || !rawIp.trim()) {
    return NextResponse.json({ error: "An IP address is required." }, { status: 400 });
  }

  const ip = rawIp.trim();

  if (!isValidIpAddress(ip)) {
    return NextResponse.json(
      { error: "Invalid IP address format. Please enter a valid IPv4 or IPv6 address." },
      { status: 400 }
    );
  }

  const validDepths: Depth[] = ["quick", "standard", "deep"];
  const depth: Depth = validDepths.includes(rawDepth as Depth) ? (rawDepth as Depth) : "standard";

  // --- Call three free IP APIs in parallel ---
  const ipApiUrl = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query`;
  const ipapiIsUrl = `https://api.ipapi.is/?q=${encodeURIComponent(ip)}`;
  const getipintelEmail = process.env.GETIPINTEL_EMAIL;
  const getipintelUrl = getipintelEmail
    ? `https://check.getipintel.net/check.php?ip=${encodeURIComponent(ip)}&contact=${encodeURIComponent(getipintelEmail)}&format=json`
    : null;

  const [ipApiRes, ipapiIsRes, getipintelRes] = await Promise.allSettled([
    fetch(ipApiUrl, { cache: "no-store" }).then(r => r.json()),
    fetch(ipapiIsUrl, { cache: "no-store" }).then(r => r.json()),
    getipintelUrl
      ? fetch(getipintelUrl, { cache: "no-store" }).then(r => r.json())
      : Promise.resolve(null),
  ]);

  // Extract from ip-api.com
  const ipApi =
    ipApiRes.status === "fulfilled" && ipApiRes.value?.status === "success"
      ? (ipApiRes.value as Record<string, unknown>)
      : null;

  // Extract from ipapi.is
  const ipapiIs =
    ipapiIsRes.status === "fulfilled" && !ipapiIsRes.value?.error
      ? (ipapiIsRes.value as Record<string, unknown>)
      : null;
  const ipapiIsAsn = ipapiIs?.asn as Record<string, unknown> | undefined;
  const ipapiIsLoc = ipapiIs?.location as Record<string, unknown> | undefined;
  const ipapiIsCompany = ipapiIs?.company as Record<string, unknown> | undefined;

  // Extract from GetIPIntel
  const getipintel =
    getipintelRes.status === "fulfilled" &&
    getipintelRes.value !== null &&
    (getipintelRes.value as Record<string, unknown>)?.status === "success"
      ? (getipintelRes.value as Record<string, unknown>)
      : null;

  // --- Merge results ---
  const merged = {
    ip,
    country:      (ipApi?.country ?? ipapiIsLoc?.country ?? null) as string | null,
    countryCode:  (ipApi?.countryCode ?? ipapiIsLoc?.country_code ?? null) as string | null,
    city:         (ipApi?.city ?? ipapiIsLoc?.city ?? null) as string | null,
    region:       (ipApi?.regionName ?? ipapiIsLoc?.state ?? null) as string | null,
    isp:          (ipApi?.isp ?? ipapiIsCompany?.name ?? null) as string | null,
    org:          (ipApi?.org ?? ipapiIsCompany?.name ?? null) as string | null,
    asn:          ipapiIsAsn?.asn != null
                    ? `AS${ipapiIsAsn.asn}`
                    : ((ipApi?.as ?? null) as string | null),
    lat:          (ipApi?.lat ?? ipapiIsLoc?.latitude ?? null) as number | null,
    lon:          (ipApi?.lon ?? ipapiIsLoc?.longitude ?? null) as number | null,
    timezone:     (ipApi?.timezone ?? ipapiIsLoc?.timezone ?? null) as string | null,
    is_proxy:     !!(ipApi?.proxy || ipapiIs?.is_proxy),
    is_vpn:       !!(ipapiIs?.is_vpn),
    is_hosting:   !!(ipApi?.hosting || ipapiIs?.is_datacenter),
    is_tor:       !!(ipapiIs?.is_tor),
    threat_score: getipintel?.result != null
                    ? Math.round(parseFloat(String(getipintel.result)) * 100)
                    : null,
  };

  // --- Build Groq prompt with enriched geo data ---
  const systemPrompt = getSystemPrompt("red");

  const metaLines = [
    `IP Address: ${ip}`,
    merged.country   ? `Country: ${merged.country} (${merged.countryCode ?? "?"})` : null,
    merged.city      ? `City: ${merged.city}${merged.region ? `, ${merged.region}` : ""}` : null,
    merged.isp       ? `ISP: ${merged.isp}` : null,
    merged.asn       ? `ASN: ${merged.asn}` : null,
    merged.timezone  ? `Timezone: ${merged.timezone}` : null,
    merged.lat != null && merged.lon != null
                     ? `Coordinates: ${merged.lat}, ${merged.lon}` : null,
    `VPN: ${merged.is_vpn ? "YES" : "No"} | Proxy: ${merged.is_proxy ? "YES" : "No"} | Tor: ${merged.is_tor ? "YES" : "No"} | Hosting/Datacenter: ${merged.is_hosting ? "YES" : "No"}`,
    merged.threat_score !== null
                     ? `Threat Score: ${merged.threat_score}/100 (GetIPIntel — 0 = clean, 100 = malicious)` : null,
  ].filter(Boolean).join("\n");

  // Reuse buildUserPrompt structure but substitute enriched meta
  const stubParsed = {
    raw: ip, e164: null, country: null, region: null,
    type: "unknown" as const, valid: true, nationalNumber: null, internationalFormat: null,
  };
  const basePrompt = buildUserPrompt(ip, stubParsed, "red", depth);
  const userPrompt = basePrompt.replace(`IP Address: ${ip}`, metaLines);

  // --- Call Groq ---
  let aiText = "";
  try {
    const completion = await groq.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      temperature: 0.4,
      max_tokens: MAX_TOKENS[depth],
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
    });
    aiText = completion.choices[0]?.message?.content ?? "";
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to contact AI service.";
    return NextResponse.json({ error: `AI service error: ${message}` }, { status: 502 });
  }

  const extracted = extractJson(aiText);

  const result: IpLookupResult = {
    ...merged,
    risk: extracted?.risk ?? "Unknown",
    summary: extracted?.summary ?? aiText.slice(0, 200).trim(),
    flags: extracted?.flags ?? [],
    raw: aiText,
    depth,
  };

  return NextResponse.json(result, {
    status: 200,
    headers: { "X-RateLimit-Remaining": String(remaining) },
  });
}
