import { NextRequest, NextResponse } from "next/server";
import Groq from "groq-sdk";
import type { Depth, RiskLevel, UrlScanResult } from "@/lib/phone";

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

function getIp(req: NextRequest): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0].trim()
    ?? req.headers.get("x-real-ip") ?? "unknown";
}

// ---------------------------------------------------------------------------
// Groq
// ---------------------------------------------------------------------------

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
const MAX_TOKENS: Record<Depth, number> = { quick: 300, standard: 700, deep: 1400 };

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
      summary: typeof raw.summary === "string" ? raw.summary.trim() : "",
      flags: Array.isArray(raw.flags)
        ? raw.flags.filter((f: unknown) => typeof f === "string").slice(0, 12) : [],
    };
  } catch { return null; }
}

// ---------------------------------------------------------------------------
// Known URL shorteners
// ---------------------------------------------------------------------------

const SHORTENERS = new Set([
  "bit.ly","tinyurl.com","t.co","ow.ly","goo.gl","buff.ly","dlvr.it",
  "su.pr","is.gd","cli.gs","yfrog.com","migre.me","ff.im","tiny.cc","url4.eu","tr.im",
  "twit.ac","snipurl.com","short.to","budurl.com","ping.fm","post.ly","just.as",
  "bkite.com","snipr.com","flic.kr","loopt.us","doiop.com","short.ie","kl.am","wp.me",
  "rubyurl.com","om.ly","to.ly","bit.do","t.ly","rb.gy","cutt.ly","shorturl.at",
  "bl.ink","short.cm","rebrand.ly","tiny.one","s.id","go2.me","clck.ru",
]);

// ---------------------------------------------------------------------------
// DNS resolution (Google)
// ---------------------------------------------------------------------------

async function resolveDomainToIp(hostname: string): Promise<string | null> {
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`,
      { cache: "no-store", signal: AbortSignal.timeout(5000) }
    );
    const data = await res.json() as { Answer?: Array<{ type: number; data: string }> };
    return data.Answer?.find(r => r.type === 1)?.data ?? null;
  } catch { return null; }
}

// ---------------------------------------------------------------------------
// Redirect chain follower (up to 6 hops)
// ---------------------------------------------------------------------------

async function followRedirects(url: string): Promise<{ chain: string[]; final: string }> {
  const chain: string[] = [];
  let current = url;
  const maxHops = 6;
  for (let i = 0; i < maxHops; i++) {
    try {
      const res = await fetch(current, {
        method: "HEAD",
        redirect: "manual",
        signal: AbortSignal.timeout(4000),
        headers: { "User-Agent": "Mozilla/5.0 (compatible; REVL/1.0)" },
      });
      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get("location");
        if (!location) break;
        const next = location.startsWith("http") ? location : new URL(location, current).toString();
        if (next === current) break;
        chain.push(next);
        current = next;
      } else {
        break;
      }
    } catch {
      break;
    }
  }
  return { chain, final: current };
}

// ---------------------------------------------------------------------------
// URLScan.io — search for recent scans of this domain (free, no key)
// ---------------------------------------------------------------------------

interface URLScanResult {
  results?: Array<{
    task?: { url?: string; time?: string };
    verdicts?: { overall?: { score?: number; categories?: string[]; tags?: string[]; malicious?: boolean } };
  }>;
  total?: number;
}

async function fetchURLScan(domain: string): Promise<{
  found: boolean;
  categories: string[];
  verdicts: string[];
  score: number | null;
}> {
  try {
    const res = await fetch(
      `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=10`,
      {
        headers: { "Accept": "application/json" },
        signal: AbortSignal.timeout(7000),
        cache: "no-store",
      }
    );
    if (!res.ok) return { found: false, categories: [], verdicts: [], score: null };
    const data = await res.json() as URLScanResult;
    if (!data.results || data.results.length === 0) return { found: false, categories: [], verdicts: [], score: null };

    // Aggregate categories and verdicts across all scans
    const cats = new Set<string>();
    const tags = new Set<string>();
    let maxScore = 0;

    for (const r of data.results) {
      const ov = r.verdicts?.overall;
      if (ov?.categories) ov.categories.forEach(c => cats.add(c));
      if (ov?.tags)       ov.tags.forEach(t => tags.add(t));
      if (ov?.score != null && ov.score > maxScore) maxScore = ov.score;
    }

    return {
      found:      true,
      categories: Array.from(cats),
      verdicts:   Array.from(tags),
      score:      maxScore > 0 ? maxScore : null,
    };
  } catch {
    return { found: false, categories: [], verdicts: [], score: null };
  }
}

// ---------------------------------------------------------------------------
// Wayback Machine — check if URL has been archived
// ---------------------------------------------------------------------------

interface WaybackResponse {
  archived_snapshots?: {
    closest?: { available?: boolean; url?: string; timestamp?: string; status?: string };
  };
}

async function fetchWayback(url: string): Promise<{ available: boolean; oldestSnapshot: string | null }> {
  try {
    const res = await fetch(
      `https://archive.org/wayback/available?url=${encodeURIComponent(url)}`,
      { cache: "no-store", signal: AbortSignal.timeout(6000) }
    );
    if (!res.ok) return { available: false, oldestSnapshot: null };
    const data = await res.json() as WaybackResponse;
    const snap = data.archived_snapshots?.closest;
    if (snap?.available && snap.timestamp) {
      // Format: YYYYMMDDHHmmss -> YYYY-MM-DD
      const ts = snap.timestamp;
      const formatted = `${ts.slice(0,4)}-${ts.slice(4,6)}-${ts.slice(6,8)}`;
      return { available: true, oldestSnapshot: formatted };
    }
    return { available: false, oldestSnapshot: null };
  } catch {
    return { available: false, oldestSnapshot: null };
  }
}

// ---------------------------------------------------------------------------
// crt.sh — SSL certificate transparency (free, no key)
// ---------------------------------------------------------------------------

interface CrtShEntry {
  issuer_name: string;
  not_before: string;
  not_after: string;
  common_name?: string;
}

async function fetchCrtSh(domain: string): Promise<{
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
}> {
  try {
    const res = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`,
      {
        headers: { "Accept": "application/json" },
        signal: AbortSignal.timeout(8000),
        cache: "no-store",
      }
    );
    if (!res.ok) return { issuer: null, validFrom: null, validTo: null, daysRemaining: null };
    const certs = await res.json() as CrtShEntry[];
    if (!Array.isArray(certs) || certs.length === 0) return { issuer: null, validFrom: null, validTo: null, daysRemaining: null };

    // Find the most recent cert that hasn't expired
    const now = Date.now();
    const validCerts = certs
      .filter(c => c.not_after && new Date(c.not_after).getTime() > now)
      .sort((a, b) => new Date(b.not_before).getTime() - new Date(a.not_before).getTime());

    const best = validCerts[0] ?? certs.sort((a,b) => new Date(b.not_before).getTime() - new Date(a.not_before).getTime())[0];
    if (!best) return { issuer: null, validFrom: null, validTo: null, daysRemaining: null };

    const notAfter = new Date(best.not_after);
    const daysRemaining = Math.floor((notAfter.getTime() - now) / 86_400_000);

    // Clean up issuer name — extract CN or O
    const issuer = best.issuer_name
      .split(",")
      .map(p => p.trim())
      .find(p => p.startsWith("O=") || p.startsWith("CN="))
      ?.replace(/^(O|CN)=/, "")
      ?? best.issuer_name.slice(0, 60);

    return {
      issuer,
      validFrom: best.not_before.slice(0, 10),
      validTo:   best.not_after.slice(0, 10),
      daysRemaining,
    };
  } catch {
    return { issuer: null, validFrom: null, validTo: null, daysRemaining: null };
  }
}

// ---------------------------------------------------------------------------
// RDAP domain age
// ---------------------------------------------------------------------------

interface RDAPEvent { eventAction: string; eventDate: string; }
interface RDAPResponse { events?: RDAPEvent[]; entities?: Array<{ vcardArray?: unknown; roles?: string[] }> }

async function fetchRDAPDomain(domain: string): Promise<{ created: string | null; registrar: string | null }> {
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      cache: "no-store",
      signal: AbortSignal.timeout(6000),
      headers: { "Accept": "application/json" },
    });
    if (!res.ok) return { created: null, registrar: null };
    const data = await res.json() as RDAPResponse;
    const regEvent = data.events?.find(e => e.eventAction === "registration");
    const created = regEvent?.eventDate ?? null;
    let registrar: string | null = null;
    for (const entity of data.entities ?? []) {
      if (entity.roles?.includes("registrar") && Array.isArray(entity.vcardArray)) {
        const vcard = entity.vcardArray as unknown[][];
        const fnEntry = vcard.flat().find((v): v is unknown[] => Array.isArray(v) && v[0] === "fn");
        if (Array.isArray(fnEntry) && typeof fnEntry[3] === "string") {
          registrar = fnEntry[3];
          break;
        }
      }
    }
    return { created, registrar };
  } catch { return { created: null, registrar: null }; }
}

// ---------------------------------------------------------------------------
// Route handler
// ---------------------------------------------------------------------------

export async function POST(req: NextRequest) {
  const clientIp = getIp(req);
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

  const { url: rawUrl, depth: rawDepth } = body as Record<string, unknown>;
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    return NextResponse.json({ error: "A URL is required." }, { status: 400 });
  }

  let urlStr = rawUrl.trim();
  if (!/^https?:\/\//i.test(urlStr)) urlStr = `https://${urlStr}`;

  let parsedUrl: URL;
  try { parsedUrl = new URL(urlStr); }
  catch { return NextResponse.json({ error: "Invalid URL format." }, { status: 400 }); }

  const validDepths: Depth[] = ["quick", "standard", "deep"];
  const depth: Depth = validDepths.includes(rawDepth as Depth) ? (rawDepth as Depth) : "standard";

  const domain = parsedUrl.hostname.toLowerCase().replace(/^www\./, "");
  const isShortened = SHORTENERS.has(domain) || Array.from(SHORTENERS).some(s => domain.endsWith(`.${s}`));

  // ---------------------------------------------------------------------------
  // All lookups in parallel
  // ---------------------------------------------------------------------------
  const [
    urlhausSettled,
    dnsSettled,
    urlscanSettled,
    waybackSettled,
    crtSettled,
    rdapSettled,
    redirectSettled,
  ] = await Promise.allSettled([
    // 1. URLhaus malware database
    fetch("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "REVL/1.0" },
      body: `url=${encodeURIComponent(urlStr)}`,
      signal: AbortSignal.timeout(6000),
      cache: "no-store",
    }).then(r => r.json()).catch(() => null),

    // 2. DNS resolution
    resolveDomainToIp(parsedUrl.hostname),

    // 3. URLScan.io domain search
    fetchURLScan(domain),

    // 4. Wayback Machine
    fetchWayback(urlStr),

    // 5. crt.sh SSL certificates
    fetchCrtSh(domain),

    // 6. RDAP domain age
    fetchRDAPDomain(domain),

    // 7. Redirect chain (only follow if not a known shortener to avoid infinite loops)
    isShortened ? followRedirects(urlStr) : Promise.resolve({ chain: [] as string[], final: urlStr }),
  ]);

  // Extract results
  interface URLhausResponse { query_status?: string; url_status?: string; threat?: string; tags?: string[] }
  const uh = (urlhausSettled.status === "fulfilled" ? urlhausSettled.value : null) as URLhausResponse | null;
  const resolvedIp    = dnsSettled.status    === "fulfilled" ? dnsSettled.value    : null;
  const urlscanData   = urlscanSettled.status === "fulfilled" ? urlscanSettled.value : { found: false, categories: [], verdicts: [], score: null };
  const wayback       = waybackSettled.status === "fulfilled" ? waybackSettled.value : { available: false, oldestSnapshot: null };
  const ssl           = crtSettled.status     === "fulfilled" ? crtSettled.value     : { issuer: null, validFrom: null, validTo: null, daysRemaining: null };
  const rdap          = rdapSettled.status    === "fulfilled" ? rdapSettled.value    : { created: null, registrar: null };
  const redirectData  = redirectSettled.status === "fulfilled" ? redirectSettled.value : { chain: [] as string[], final: urlStr };

  // Parse URLhaus
  const uhStatus = uh?.query_status ?? "unknown";
  const urlhausStatus: UrlScanResult["urlhaus_status"] =
    uhStatus === "is_host" || uhStatus === "no_results" ? "not_found"
    : uh?.url_status === "online"  ? "online"
    : uh?.url_status === "offline" ? "offline"
    : "unknown";
  const urlhausThreat = uh?.threat ?? null;
  const urlhausTags   = Array.isArray(uh?.tags) ? uh!.tags as string[] : [];

  const isMalware  = urlhausTags.includes("malware_download") || urlhausThreat === "malware_download"
    || urlscanData.categories.some(c => c.toLowerCase().includes("malware"));
  const isPhishing = urlhausTags.includes("phishing") || urlhausThreat === "phishing"
    || urlscanData.categories.some(c => c.toLowerCase().includes("phishing"));

  // Domain age
  let domainAgeDays: number | null = null;
  let domainCreated: string | null = rdap.created;
  if (rdap.created) {
    const d = new Date(rdap.created);
    if (!isNaN(d.getTime())) {
      domainAgeDays = Math.floor((Date.now() - d.getTime()) / 86_400_000);
      domainCreated = rdap.created.slice(0, 10);
    }
  }

  // If RDAP failed but crt.sh has cert history, use oldest cert as lower bound for domain age
  if (domainAgeDays === null && ssl.validFrom) {
    const firstCert = new Date(ssl.validFrom);
    if (!isNaN(firstCert.getTime())) {
      domainAgeDays = Math.floor((Date.now() - firstCert.getTime()) / 86_400_000);
    }
  }

  // ---------------------------------------------------------------------------
  // Build Groq prompt
  // ---------------------------------------------------------------------------
  const meta = [
    `URL: ${urlStr}`,
    `Domain: ${domain}`,
    resolvedIp ? `Resolved IP: ${resolvedIp}` : "DNS resolution: failed (domain may not exist)",
    `URL Shortener: ${isShortened ? `YES — hides true destination (${domain})` : "No"}`,
    redirectData.chain.length > 0 ? `Redirect chain (${redirectData.chain.length} hops): ${[urlStr, ...redirectData.chain].join(" → ")}` : null,
    redirectData.chain.length > 0 ? `Final destination: ${redirectData.final}` : null,
    "",
    "--- THREAT DATABASES ---",
    `URLhaus: ${urlhausStatus === "not_found" ? "CLEAN (not in malware database)" : urlhausStatus === "online" ? "⚠️ ACTIVE THREAT IN DATABASE" : urlhausStatus}`,
    urlhausThreat ? `URLhaus threat type: ${urlhausThreat}` : null,
    urlhausTags.length > 0 ? `URLhaus tags: ${urlhausTags.join(", ")}` : null,
    urlscanData.found ? `URLScan.io: FOUND — ${urlscanData.categories.length} categories, ${urlscanData.verdicts.length} tags` : "URLScan.io: not in recent scan history",
    urlscanData.categories.length > 0 ? `URLScan categories: ${urlscanData.categories.join(", ")}` : null,
    urlscanData.verdicts.length  > 0  ? `URLScan verdicts/tags: ${urlscanData.verdicts.join(", ")}` : null,
    isMalware  ? "⚠️ CONFIRMED MALWARE — multiple threat databases" : null,
    isPhishing ? "⚠️ CONFIRMED PHISHING — multiple threat databases" : null,
    "",
    "--- DOMAIN INTELLIGENCE ---",
    domainAgeDays !== null
      ? `Domain age: ${domainAgeDays} days (${Math.floor(domainAgeDays / 365)} years)${domainAgeDays < 30 ? " ⚠️ VERY NEW — high phishing risk" : domainAgeDays < 180 ? " ⚠️ Recent — moderate risk" : ""}`
      : "Domain age: unknown",
    domainCreated ? `Domain registered: ${domainCreated}` : null,
    rdap.registrar ? `Domain registrar: ${rdap.registrar}` : null,
    "",
    "--- SSL / TLS ---",
    ssl.issuer ? `SSL issuer: ${ssl.issuer}` : "SSL: no valid certificate found in certificate transparency logs",
    ssl.validFrom ? `SSL valid from: ${ssl.validFrom}` : null,
    ssl.validTo   ? `SSL valid to: ${ssl.validTo}`   : null,
    ssl.daysRemaining !== null
      ? `SSL days remaining: ${ssl.daysRemaining}${ssl.daysRemaining < 0 ? " ⚠️ EXPIRED" : ssl.daysRemaining < 14 ? " ⚠️ EXPIRING SOON" : ""}`
      : null,
    "",
    "--- WEB HISTORY ---",
    `Wayback Machine: ${wayback.available ? `ARCHIVED — first snapshot ${wayback.oldestSnapshot}` : "No snapshots found (new or obscure site)"}`,
    "",
    "--- URL STRUCTURE ---",
    `Protocol: ${parsedUrl.protocol}`,
    `Path: ${parsedUrl.pathname}`,
    parsedUrl.searchParams.size > 0 ? `Query parameters: ${parsedUrl.searchParams.size} present` : null,
    isShortened ? "⚠️ SHORTENED URL — destination is hidden until clicked" : null,
  ].filter(s => s !== null).join("\n");

  const jsonInstruction = `\nAt the very end of your response, output the following JSON on its own line:\n{"risk":"High|Medium|Low|Unknown","summary":"one sentence summary","flags":["finding 1","finding 2","finding 3"]}`;

  let userPrompt: string;
  if (depth === "quick") {
    userPrompt = `Analyse this URL in 2–3 sentences. State whether it is safe, suspicious, or dangerous, and the most important finding.\n\n${meta}${jsonInstruction}`;
  } else if (depth === "standard") {
    userPrompt = `Analyse this URL. Cover: (1) Safety Assessment, (2) Threat Intelligence Findings, (3) Domain & SSL Analysis, (4) Recommended Action. 2–3 sentences each.\n\n${meta}${jsonInstruction}`;
  } else {
    userPrompt = `Produce a full URL threat intelligence report. Cover:\n1. URL Structure & Purpose Analysis\n2. Threat Database Findings (URLhaus, URLScan.io)\n3. Domain Age & Registration Analysis\n4. SSL/TLS Certificate Analysis\n5. Web History & Reputation\n6. Redirect Chain & Obfuscation Assessment\n7. Phishing & Malware Indicators\n8. Overall Risk Assessment & Recommended Actions\n\nURL data:\n${meta}${jsonInstruction}`;
  }

  const systemPrompt = `You are a senior cybersecurity analyst specialising in URL threat intelligence, phishing detection, and malware analysis. Analyse URLs for all threat vectors: phishing, malware, scams, social engineering, domain squatting, newly registered domains, expired SSL, suspicious redirects, and shortened URL abuse. Cross-reference all available threat intelligence data. Be direct and specific. Do not use markdown.`;

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
    const message = err instanceof Error ? err.message : "AI service error.";
    return NextResponse.json({ error: `AI service error: ${message}` }, { status: 502 });
  }

  const extracted = extractJson(aiText);

  const result: UrlScanResult = {
    url: urlStr,
    domain,
    resolved_ip: resolvedIp,
    urlhaus_status:  urlhausStatus,
    urlhaus_threat:  urlhausThreat,
    urlhaus_tags:    urlhausTags,
    is_phishing:     isPhishing,
    is_malware:      isMalware,
    is_shortened:    isShortened,
    redirect_chain:  redirectData.chain,
    final_url:       redirectData.chain.length > 0 ? redirectData.final : null,
    domain_age_days: domainAgeDays,
    domain_created:  domainCreated,
    domain_registrar: rdap.registrar,
    urlscan_found:      urlscanData.found,
    urlscan_categories: urlscanData.categories,
    urlscan_verdicts:   urlscanData.verdicts,
    wayback_available:       wayback.available,
    wayback_oldest_snapshot: wayback.oldestSnapshot,
    ssl_issuer:         ssl.issuer,
    ssl_valid_from:     ssl.validFrom,
    ssl_valid_to:       ssl.validTo,
    ssl_days_remaining: ssl.daysRemaining,
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
