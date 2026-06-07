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
// Rate limiter
// ---------------------------------------------------------------------------

interface RateLimitEntry { count: number; resetAt: number; }
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
// Tor exit node list — 1-hour in-memory cache
// ---------------------------------------------------------------------------

let torListCache: Set<string> | null = null;
let torListExpiry = 0;

async function getTorExitNodes(): Promise<Set<string>> {
  if (torListCache && Date.now() < torListExpiry) return torListCache;
  try {
    const res = await fetch("https://check.torproject.org/torbulkexitlist", {
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    const text = await res.text();
    torListCache = new Set(
      text.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"))
    );
    torListExpiry = Date.now() + 60 * 60 * 1000; // 1 hour
    return torListCache;
  } catch {
    return torListCache ?? new Set();
  }
}

// ---------------------------------------------------------------------------
// Groq
// ---------------------------------------------------------------------------

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
const MAX_TOKENS: Record<Depth, number> = { quick: 400, standard: 700, deep: 1200 };

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
      summary: typeof raw.summary === "string" ? raw.summary.trim() : "No summary.",
      flags: Array.isArray(raw.flags)
        ? raw.flags.filter((f: unknown) => typeof f === "string").slice(0, 10)
        : [],
    };
  } catch { return null; }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getClientIp(req: NextRequest): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0].trim()
    ?? req.headers.get("x-real-ip")
    ?? "unknown";
}

/** Pure IPv4: four numeric octets */
function isPureIpv4(s: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s);
}

/** Pure IPv6: contains a colon and only hex digits + colons */
function isPureIpv6(s: string): boolean {
  return s.includes(":") && /^[0-9a-fA-F:]+$/.test(s);
}

/** Anything that isn't a pure IP is treated as a domain to resolve */
function isIpAddress(s: string): boolean {
  return isPureIpv4(s) || isPureIpv6(s);
}

async function resolveDomainToIp(domain: string): Promise<string | null> {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`;
  console.log(`[iplookup] DNS request: ${url}`);
  try {
    const res = await fetch(url, { cache: "no-store", signal: AbortSignal.timeout(6000) });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data = await res.json() as { Status?: number; Answer?: Array<Record<string, any>> };
    console.log(`[iplookup] DNS response status=${data.Status} answers=${JSON.stringify(data.Answer ?? [])}`);
    if (!Array.isArray(data.Answer)) return null;
    // type 1 = A record; Google DNS returns type as a number
    const aRecord = data.Answer.find(r => Number(r.type) === 1);
    const resolved = aRecord ? String(aRecord.data) : null;
    console.log(`[iplookup] Resolved: ${resolved}`);
    return resolved;
  } catch (err) {
    console.error(`[iplookup] DNS resolution failed:`, err);
    return null;
  }
}

// AbuseIPDB category ID → human-readable label
const ABUSE_CATEGORIES: Record<number, string> = {
  3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
  6: "Ping of Death", 7: "Phishing", 9: "Open Proxy",
  10: "Web Spam", 11: "Email Spam", 14: "Port Scan",
  15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
  18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
  21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
};

function reverseIpv4ForPTR(ip: string): string | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  return parts.reverse().join(".") + ".in-addr.arpa";
}

// Recursively find a vCard field value inside RDAP entity trees
function rdapFind(
  entities: unknown[],
  role: string,
  vcardKey: string
): string | null {
  if (!Array.isArray(entities)) return null;
  for (const raw of entities) {
    const e = raw as Record<string, unknown>;
    const roles = Array.isArray(e.roles) ? (e.roles as string[]) : [];
    if (roles.includes(role)) {
      const vcard = e.vcardArray as unknown[] | undefined;
      if (Array.isArray(vcard) && Array.isArray(vcard[1])) {
        for (const entry of vcard[1] as unknown[][]) {
          if (Array.isArray(entry) && entry[0] === vcardKey) {
            return String(entry[3] ?? "");
          }
        }
      }
    }
    // Recurse into nested entities
    if (Array.isArray(e.entities)) {
      const found = rdapFind(e.entities as unknown[], role, vcardKey);
      if (found) return found;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Route handler
// ---------------------------------------------------------------------------

export async function POST(req: NextRequest) {
  const clientIp = getClientIp(req);
  const { allowed, remaining } = checkRateLimit(clientIp);
  if (!allowed) {
    return NextResponse.json(
      { error: "You've reached the daily lookup limit. Please try again in 24 hours." },
      { status: 429, headers: { "X-RateLimit-Remaining": "0" } }
    );
  }

  let body: unknown;
  try { body = await req.json(); }
  catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }

  const { ip: rawIp, depth: rawDepth } = body as Record<string, unknown>;
  if (typeof rawIp !== "string" || !rawIp.trim())
    return NextResponse.json({ error: "An IP address is required." }, { status: 400 });

  const originalInput = rawIp.trim();
  let ip = originalInput;

  console.log(`[iplookup] Input: "${originalInput}" isIp=${isIpAddress(originalInput)}`);

  if (isIpAddress(originalInput)) {
    console.log(`[iplookup] Pure IP detected — skipping DNS`);
  } else {
    // Treat as domain — must contain at least one letter or dot to be plausible
    if (!/[a-zA-Z.]/.test(originalInput)) {
      return NextResponse.json(
        { error: "Invalid input. Please enter a valid IPv4, IPv6, or domain name." },
        { status: 400 }
      );
    }
    console.log(`[iplookup] Domain detected — resolving via Google DNS`);
    const resolved = await resolveDomainToIp(originalInput);
    if (!resolved) {
      return NextResponse.json(
        { error: `Could not resolve "${originalInput}" to an IP address. Check the domain and try again.` },
        { status: 400 }
      );
    }
    console.log(`[iplookup] "${originalInput}" → ${resolved}`);
    ip = resolved;
  }

  const validDepths: Depth[] = ["quick", "standard", "deep"];
  const depth: Depth = validDepths.includes(rawDepth as Depth) ? (rawDepth as Depth) : "standard";

  // ---------------------------------------------------------------------------
  // Build all API URLs
  // ---------------------------------------------------------------------------
  const abuseKey    = process.env.ABUSEIPDB_API_KEY;
  const getipEmail  = process.env.GETIPINTEL_EMAIL;

  const ipApiUrl       = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,proxy,hosting,query`;
  const ipapiIsUrl     = `https://api.ipapi.is/?q=${encodeURIComponent(ip)}`;
  const getipintelUrl  = getipEmail
    ? `https://check.getipintel.net/check.php?ip=${encodeURIComponent(ip)}&contact=${encodeURIComponent(getipEmail)}&format=json`
    : null;
  const abuseUrl       = abuseKey
    ? `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`
    : null;
  const ptrName        = reverseIpv4ForPTR(ip);
  const dnsUrl         = ptrName ? `https://dns.google/resolve?name=${ptrName}&type=PTR` : null;
  const rdapUrl        = `https://rdap.arin.net/registry/ip/${encodeURIComponent(ip)}`;

  const fetchOpts = { cache: "no-store" as const, signal: AbortSignal.timeout(8000) };

  // ---------------------------------------------------------------------------
  // Fire all 7 sources in parallel
  // ---------------------------------------------------------------------------
  const hackertargetUrl  = `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ip)}`;
  const nmapUrl          = `https://api.hackertarget.com/nmap/?q=${encodeURIComponent(ip)}`;

  const [
    ipApiRes, ipapiIsRes, getipintelRes,
    abuseRes, dnsRes, rdapRes, torRes, hackertargetRes, nmapRes,
  ] = await Promise.allSettled([
    fetch(ipApiUrl, fetchOpts).then(r => r.json()),
    fetch(ipapiIsUrl, fetchOpts).then(r => r.json()),
    getipintelUrl ? fetch(getipintelUrl, fetchOpts).then(r => r.json()) : Promise.resolve(null),
    abuseUrl
      ? fetch(abuseUrl, { ...fetchOpts, headers: { Key: abuseKey!, Accept: "application/json" } }).then(r => r.json())
      : Promise.resolve(null),
    dnsUrl ? fetch(dnsUrl, fetchOpts).then(r => r.json()) : Promise.resolve(null),
    fetch(rdapUrl, fetchOpts).then(r => r.json()),
    getTorExitNodes(),
    fetch(hackertargetUrl, { cache: "no-store", signal: AbortSignal.timeout(6000) }).then(r => r.text()),
    fetch(nmapUrl, { cache: "no-store", signal: AbortSignal.timeout(10000) }).then(r => r.text()),
  ]);

  // ---------------------------------------------------------------------------
  // Extract raw API values
  // ---------------------------------------------------------------------------
  const ipApi = ipApiRes.status === "fulfilled" && ipApiRes.value?.status === "success"
    ? (ipApiRes.value as Record<string, unknown>) : null;

  const ipapiIs = ipapiIsRes.status === "fulfilled" && !ipapiIsRes.value?.error
    ? (ipapiIsRes.value as Record<string, unknown>) : null;
  const ipapiIsAsn = ipapiIs?.asn as Record<string, unknown> | undefined;
  const ipapiIsLoc = ipapiIs?.location as Record<string, unknown> | undefined;
  const ipapiIsCompany = ipapiIs?.company as Record<string, unknown> | undefined;

  const getipintel = getipintelRes.status === "fulfilled"
    && (getipintelRes.value as Record<string, unknown>)?.status === "success"
    ? (getipintelRes.value as Record<string, unknown>) : null;

  const abuseData = abuseRes.status === "fulfilled" && abuseRes.value?.data
    ? (abuseRes.value.data as Record<string, unknown>) : null;

  // DNS PTR record
  let reverseDns: string | null = null;
  if (dnsRes.status === "fulfilled" && dnsRes.value?.Answer) {
    const answers = dnsRes.value.Answer as Array<Record<string, unknown>>;
    const ptr = answers.find(a => a.type === 12);
    if (ptr?.data) reverseDns = String(ptr.data).replace(/\.$/, ""); // strip trailing dot
  }

  // RDAP
  const rdapData = rdapRes.status === "fulfilled" && !rdapRes.value?.errorCode
    ? (rdapRes.value as Record<string, unknown>) : null;
  const rdapEntities = Array.isArray(rdapData?.entities) ? (rdapData!.entities as unknown[]) : [];
  const whoisOrg = rdapFind(rdapEntities, "registrant", "fn")
    ?? rdapFind(rdapEntities, "registrant", "org")
    ?? null;
  const whoisAbuseEmail = rdapFind(rdapEntities, "abuse", "email");
  const whoisNetworkName = rdapData?.name ? String(rdapData.name) : null;

  // Tor
  const torSet = torRes.status === "fulfilled" ? torRes.value : new Set<string>();

  // HackerTarget reverse IP — list of domains hosted on this IP
  let hostedDomains: string[] = [];
  if (hackertargetRes.status === "fulfilled" && typeof hackertargetRes.value === "string") {
    const htText = hackertargetRes.value as string;
    if (!htText.includes("error") && !htText.includes("API count") && !htText.includes("No records")) {
      hostedDomains = htText
        .split("\n")
        .map(l => l.trim())
        .filter(l => l && l.includes(".") && !l.startsWith("#"))
        .slice(0, 20);
    }
  }

  // HackerTarget nmap — open ports
  interface PortInfo { port: number; protocol: string; service: string; state: string; }
  let openPorts: PortInfo[] = [];
  if (nmapRes.status === "fulfilled" && typeof nmapRes.value === "string") {
    const nmapText = nmapRes.value as string;
    if (!nmapText.includes("error") && !nmapText.includes("API count")) {
      // Parse lines like: "22/tcp   open  ssh"
      const portLines = nmapText.split("\n").filter(l => /^\d+\//.test(l.trim()));
      openPorts = portLines.map(line => {
        const parts = line.trim().split(/\s+/);
        const [portProto] = parts;
        const [port, proto] = portProto.split("/");
        const state   = parts[1] ?? "unknown";
        const service = parts[2] ?? "unknown";
        return { port: parseInt(port, 10), protocol: proto, service, state };
      }).filter(p => p.state === "open").slice(0, 20);
    }
  }

  // ---------------------------------------------------------------------------
  // Merge
  // ---------------------------------------------------------------------------
  const merged = {
    ip,
    original_input: originalInput,
    resolved_ip: ip,
    country:     (ipApi?.country ?? ipapiIsLoc?.country ?? null) as string | null,
    countryCode: (ipApi?.countryCode ?? ipapiIsLoc?.country_code ?? null) as string | null,
    city:        (ipApi?.city ?? ipapiIsLoc?.city ?? null) as string | null,
    region:      (ipApi?.regionName ?? ipapiIsLoc?.state ?? null) as string | null,
    isp:         (ipApi?.isp ?? ipapiIsCompany?.name ?? null) as string | null,
    org:         (ipApi?.org ?? ipapiIsCompany?.name ?? null) as string | null,
    asn:         ipapiIsAsn?.asn != null
                   ? `AS${ipapiIsAsn.asn}`
                   : ((ipApi?.as ?? null) as string | null),
    lat:         (ipApi?.lat ?? ipapiIsLoc?.latitude ?? null) as number | null,
    lon:         (ipApi?.lon ?? ipapiIsLoc?.longitude ?? null) as number | null,
    timezone:    (ipApi?.timezone ?? ipapiIsLoc?.timezone ?? null) as string | null,
    // Anonymisation
    is_proxy:    !!(ipApi?.proxy || ipapiIs?.is_proxy),
    is_vpn:      !!(ipapiIs?.is_vpn),
    is_hosting:  !!(ipApi?.hosting || ipapiIs?.is_datacenter),
    is_tor:      !!(ipapiIs?.is_tor) || torSet.has(ip),
    // GetIPIntel
    threat_score: getipintel?.result != null
                    ? Math.round(parseFloat(String(getipintel.result)) * 100)
                    : null,
    // AbuseIPDB
    abuse_confidence_score: abuseData?.abuseConfidenceScore != null
                              ? Number(abuseData.abuseConfidenceScore) : null,
    abuse_total_reports:    abuseData?.totalReports != null
                              ? Number(abuseData.totalReports) : null,
    abuse_last_reported:    (abuseData?.lastReportedAt as string | null | undefined) ?? null,
    abuse_usage_type:       (abuseData?.usageType as string | null | undefined) ?? null,
    abuse_reports: Array.isArray(abuseData?.reports)
      ? (abuseData!.reports as Array<Record<string, unknown>>)
          .slice(0, 10)
          .map(r => ({
            reportedAt: String(r.reportedAt ?? ""),
            comment: String(r.comment ?? "").trim(),
            categories: Array.isArray(r.categories)
              ? (r.categories as number[]).map(id => ABUSE_CATEGORIES[id] ?? `Category ${id}`)
              : [],
            reporterCountryCode: String(r.reporterCountryCode ?? ""),
          }))
      : [],
    // Reverse DNS + WHOIS
    reverse_dns:        reverseDns,
    whois_org:          whoisOrg,
    whois_network_name: whoisNetworkName,
    whois_abuse_email:  whoisAbuseEmail,
  };

  // ---------------------------------------------------------------------------
  // Build enriched Groq prompt
  // ---------------------------------------------------------------------------
  const systemPrompt = getSystemPrompt("red");

  const metaLines = [
    `IP Address: ${ip}${originalInput !== ip ? ` (resolved from domain: ${originalInput})` : ""}`,
    merged.country   ? `Country: ${merged.country} (${merged.countryCode ?? "?"})` : null,
    merged.city      ? `City: ${merged.city}${merged.region ? `, ${merged.region}` : ""}` : null,
    merged.isp       ? `ISP: ${merged.isp}` : null,
    merged.asn       ? `ASN: ${merged.asn}` : null,
    merged.reverse_dns     ? `Reverse DNS: ${merged.reverse_dns}` : null,
    merged.whois_org       ? `WHOIS Org: ${merged.whois_org}` : null,
    merged.whois_network_name ? `WHOIS Network: ${merged.whois_network_name}` : null,
    merged.timezone  ? `Timezone: ${merged.timezone}` : null,
    merged.lat != null && merged.lon != null ? `Coordinates: ${merged.lat}, ${merged.lon}` : null,
    `VPN: ${merged.is_vpn ? "YES" : "No"} | Proxy: ${merged.is_proxy ? "YES" : "No"} | Tor: ${merged.is_tor ? "YES" : "No"} | Hosting/DC: ${merged.is_hosting ? "YES" : "No"}`,
    merged.abuse_confidence_score != null
      ? `AbuseIPDB Confidence Score: ${merged.abuse_confidence_score}/100 (${merged.abuse_total_reports ?? 0} reports${merged.abuse_last_reported ? `, last: ${merged.abuse_last_reported}` : ""})` : null,
    merged.abuse_usage_type ? `Usage Type: ${merged.abuse_usage_type}` : null,
    merged.threat_score !== null ? `GetIPIntel Threat Score: ${merged.threat_score}/100` : null,
  ].filter(Boolean).join("\n");

  const stubParsed = {
    raw: ip, e164: null, country: null, region: null,
    type: "unknown" as const, valid: true, nationalNumber: null, internationalFormat: null,
  };
  const basePrompt = buildUserPrompt(ip, stubParsed, "red", depth);
  const userPrompt = basePrompt.replace(`IP Address: ${ip}`, metaLines);

  // ---------------------------------------------------------------------------
  // Groq
  // ---------------------------------------------------------------------------
  let aiText = "";
  try {
    const completion = await groq.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      temperature: 0.4,
      max_tokens: MAX_TOKENS[depth],
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user",   content: userPrompt   },
      ],
    });
    aiText = completion.choices[0]?.message?.content ?? "";
  } catch (err) {
    const message = err instanceof Error ? err.message : "AI service error.";
    return NextResponse.json({ error: `AI service error: ${message}` }, { status: 502 });
  }

  const extracted = extractJson(aiText);

  const result: IpLookupResult = {
    ...merged,
    hosted_domains: hostedDomains,
    open_ports:     openPorts,
    risk:    extracted?.risk    ?? "Unknown",
    summary: extracted?.summary ?? aiText.slice(0, 200).trim(),
    flags:   extracted?.flags   ?? [],
    raw:     aiText,
    depth,
  };

  return NextResponse.json(result, {
    status: 200,
    headers: { "X-RateLimit-Remaining": String(remaining) },
  });
}
