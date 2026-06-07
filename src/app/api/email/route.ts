import { NextRequest, NextResponse } from "next/server";
import Groq from "groq-sdk";
import type { Depth, RiskLevel, EmailLookupResult } from "@/lib/phone";

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
      summary: typeof raw.summary === "string" ? raw.summary.trim() : "No summary.",
      flags: Array.isArray(raw.flags)
        ? raw.flags.filter((f: unknown) => typeof f === "string").slice(0, 12)
        : [],
    };
  } catch { return null; }
}

// ---------------------------------------------------------------------------
// DNS helpers (Google Public DNS)
// ---------------------------------------------------------------------------

interface DnsResponse {
  Status: number;
  Answer?: Array<{ type: number; data: string; TTL?: number }>;
}

async function dnsQuery(name: string, type: string): Promise<DnsResponse | null> {
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
      { cache: "no-store", signal: AbortSignal.timeout(5000) }
    );
    return res.ok ? (await res.json() as DnsResponse) : null;
  } catch { return null; }
}

function parseMxRecords(resp: DnsResponse | null): string[] {
  if (!resp?.Answer) return [];
  // MX Answer data format: "10 mail.example.com."
  return resp.Answer
    .filter(r => r.type === 15)
    .map(r => {
      const parts = r.data.trim().split(/\s+/);
      return parts.length >= 2 ? parts[1].replace(/\.$/, "") : r.data.trim();
    })
    .sort();
}

function parseSpfRecord(resp: DnsResponse | null): string | null {
  if (!resp?.Answer) return null;
  const spfRecord = resp.Answer
    .filter(r => r.type === 16)
    .map(r => r.data.replace(/^"|"$/g, ""))
    .find(d => d.startsWith("v=spf1"));
  return spfRecord ?? null;
}

function parseDmarcRecord(resp: DnsResponse | null): string | null {
  if (!resp?.Answer) return null;
  const dmarcRecord = resp.Answer
    .filter(r => r.type === 16)
    .map(r => r.data.replace(/^"|"$/g, ""))
    .find(d => d.startsWith("v=DMARC1"));
  return dmarcRecord ?? null;
}

function isSpfEnforced(spf: string | null): boolean {
  if (!spf) return false;
  // ~all = softfail, -all = hardfail (enforced), +all = pass all (very permissive), ?all = neutral
  return spf.includes("-all");
}

function isDmarcEnforced(dmarc: string | null): boolean {
  if (!dmarc) return false;
  // p=reject or p=quarantine = enforced; p=none = monitoring only
  return /p=(reject|quarantine)/i.test(dmarc);
}

// ---------------------------------------------------------------------------
// RDAP domain age
// ---------------------------------------------------------------------------

interface RDAPEvent { eventAction: string; eventDate: string; }
interface RDAPResponse { events?: RDAPEvent[]; entities?: Array<{ vcardArray?: unknown; roles?: string[] }> }

async function fetchRDAPDomain(domain: string): Promise<{ created: string | null; registrar: string | null }> {
  try {
    // Try IANA RDAP bootstrap
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      cache: "no-store",
      signal: AbortSignal.timeout(6000),
      headers: { "Accept": "application/json" },
    });
    if (!res.ok) return { created: null, registrar: null };
    const data = await res.json() as RDAPResponse;
    const regEvent = data.events?.find(e => e.eventAction === "registration");
    const created = regEvent?.eventDate ?? null;

    // Try to extract registrar from entities
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
// emailrep.io response shape
// ---------------------------------------------------------------------------

interface EmailRepDetails {
  blacklisted?: boolean;
  malicious_activity?: boolean;
  malicious_activity_recent?: boolean;
  credentials_leaked?: boolean;
  credentials_leaked_recent?: boolean;
  data_breach?: boolean;
  first_seen?: string;
  last_seen?: string;
  domain_exists?: boolean;
  domain_reputation?: string;
  new_domain?: boolean;
  days_since_domain_creation?: number;
  suspicious_tld?: boolean;
  spam?: boolean;
  free_provider?: boolean;
  disposable?: boolean;
  deliverable?: boolean;
  valid_mx?: boolean;
  spoofable?: boolean;
  spf_strict?: boolean;
  dmarc_enforced?: boolean;
  profiles?: string[];
}

interface EmailRepResponse {
  email?: string;
  reputation?: string;
  suspicious?: boolean;
  references?: number;
  details?: EmailRepDetails;
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

  const { email: rawEmail, depth: rawDepth } = body as Record<string, unknown>;
  if (typeof rawEmail !== "string" || !rawEmail.trim()) {
    return NextResponse.json({ error: "An email address is required." }, { status: 400 });
  }

  const email = rawEmail.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return NextResponse.json({ error: "Invalid email address format." }, { status: 400 });
  }

  const validDepths: Depth[] = ["quick", "standard", "deep"];
  const depth: Depth = validDepths.includes(rawDepth as Depth) ? (rawDepth as Depth) : "standard";

  const domain = email.split("@")[1];

  // ---------------------------------------------------------------------------
  // All lookups in parallel: emailrep + MX + SPF + DMARC + RDAP
  // ---------------------------------------------------------------------------
  const [emailrepSettled, mxSettled, spfSettled, dmarcSettled, rdapSettled] = await Promise.allSettled([
    // 1. emailrep.io — reputation, breach, disposable, profiles
    fetch(`https://emailrep.io/query/${encodeURIComponent(email)}`, {
      headers: { "User-Agent": "PhoneScan/1.0" },
      signal: AbortSignal.timeout(7000),
      cache: "no-store",
    }).then(r => r.ok ? r.json() as Promise<EmailRepResponse> : null).catch(() => null),

    // 2. MX records
    dnsQuery(domain, "MX"),

    // 3. SPF (TXT on domain)
    dnsQuery(domain, "TXT"),

    // 4. DMARC (TXT on _dmarc.domain)
    dnsQuery(`_dmarc.${domain}`, "TXT"),

    // 5. RDAP domain age
    fetchRDAPDomain(domain),
  ]);

  // Extract results
  const emailrep = emailrepSettled.status === "fulfilled" ? emailrepSettled.value : null;
  const mxResp   = mxSettled.status    === "fulfilled" ? mxSettled.value    : null;
  const spfResp  = spfSettled.status   === "fulfilled" ? spfSettled.value   : null;
  const dmarcResp = dmarcSettled.status === "fulfilled" ? dmarcSettled.value : null;
  const rdap     = rdapSettled.status  === "fulfilled" ? rdapSettled.value  : { created: null, registrar: null };

  // Parse DNS results
  const mxRecords   = parseMxRecords(mxResp);
  const hasMx       = mxRecords.length > 0;
  const spfRecord   = parseSpfRecord(spfResp);
  const dmarcRecord = parseDmarcRecord(dmarcResp);
  const spfEnforced  = isSpfEnforced(spfRecord);
  const dmarcEnforced = isDmarcEnforced(dmarcRecord);

  // Parse emailrep data
  const details = (emailrep as EmailRepResponse | null)?.details ?? {};
  const isDisposable       = details.disposable         ?? false;
  const isFreeProvider     = details.free_provider      ?? false;
  const isSuspicious       = (emailrep as EmailRepResponse | null)?.suspicious ?? false;
  const references         = (emailrep as EmailRepResponse | null)?.references ?? 0;
  const blacklisted        = details.blacklisted        ?? false;
  const credentialsLeaked  = details.credentials_leaked ?? false;
  const dataBreach         = details.data_breach        ?? false;
  const maliciousActivity  = details.malicious_activity ?? false;
  const spoofable          = details.spoofable          ?? (!spfEnforced || !dmarcEnforced);
  const domainReputation   = details.domain_reputation  ?? null;
  const profiles           = details.profiles           ?? [];
  const reputation         = (emailrep as EmailRepResponse | null)?.reputation ?? "unknown";
  const firstSeen          = details.first_seen && details.first_seen !== "never" ? details.first_seen : null;
  const lastSeen           = details.last_seen && details.last_seen !== "never" ? details.last_seen : null;
  const deliverable        = details.deliverable ?? (hasMx ? true : null);
  const newDomain          = details.new_domain ?? false;
  const suspiciousTld      = details.suspicious_tld ?? false;

  // Domain age — prefer emailrep's days_since_domain_creation, fall back to RDAP
  let domainAgeDays: number | null = details.days_since_domain_creation ?? null;
  let domainCreated: string | null = rdap.created;
  if (domainAgeDays === null && rdap.created) {
    const created = new Date(rdap.created);
    if (!isNaN(created.getTime())) {
      domainAgeDays = Math.floor((Date.now() - created.getTime()) / 86_400_000);
    }
  }

  // ---------------------------------------------------------------------------
  // Build enriched Groq prompt
  // ---------------------------------------------------------------------------
  const meta = [
    `Email: ${email}`,
    `Domain: ${domain}`,
    `Overall Reputation: ${reputation}`,
    `Suspicious flag: ${isSuspicious ? "YES" : "No"}`,
    `References in external databases: ${references}`,
    "",
    "--- DISPOSABLE / PROVIDER ---",
    `Disposable/temporary email: ${isDisposable ? "YES — high suspicion" : "No"}`,
    `Free email provider: ${isFreeProvider ? "Yes (Gmail, Yahoo, etc.)" : "No (likely business/custom)"}`,
    `Domain reputation: ${domainReputation ?? "unknown"}`,
    `Suspicious TLD: ${suspiciousTld ? "YES" : "No"}`,
    "",
    "--- BREACH & SECURITY ---",
    `Blacklisted: ${blacklisted ? "YES" : "No"}`,
    `Credentials leaked in known breach: ${credentialsLeaked ? "YES" : "No"}`,
    `Associated with known data breach: ${dataBreach ? "YES" : "No"}`,
    `Known malicious activity: ${maliciousActivity ? "YES" : "No"}`,
    "",
    "--- EMAIL INFRASTRUCTURE ---",
    `MX records (can receive email): ${hasMx ? `YES — ${mxRecords.slice(0, 3).join(", ")}` : "NO MX RECORDS — cannot receive email"}`,
    `Deliverable: ${deliverable === null ? "Unknown" : deliverable ? "Yes" : "No"}`,
    `SPF record: ${spfRecord ? spfRecord.slice(0, 80) : "MISSING"}`,
    `SPF enforcement: ${spfEnforced ? "Strict (-all)" : spfRecord ? "Permissive (not -all)" : "MISSING — domain can be spoofed"}`,
    `DMARC record: ${dmarcRecord ? dmarcRecord.slice(0, 80) : "MISSING"}`,
    `DMARC enforcement: ${dmarcEnforced ? "Enforced (reject/quarantine)" : dmarcRecord ? "Monitoring only (p=none)" : "MISSING — no DMARC policy"}`,
    `Domain spoofable: ${spoofable ? "YES — weak/missing SPF or DMARC" : "No (strict policies)"}`,
    "",
    "--- DOMAIN AGE & HISTORY ---",
    domainAgeDays !== null ? `Domain age: ${domainAgeDays} days (${Math.floor(domainAgeDays / 365)} years)` : "Domain age: unknown",
    domainCreated ? `Domain created: ${domainCreated.slice(0, 10)}` : null,
    rdap.registrar ? `Registrar: ${rdap.registrar}` : null,
    newDomain ? "⚠️ NEW DOMAIN — created recently, higher phishing risk" : null,
    "",
    "--- ACTIVITY ---",
    firstSeen ? `First seen in databases: ${firstSeen}` : null,
    lastSeen ? `Last seen in databases: ${lastSeen}` : null,
    profiles.length > 0 ? `Known linked social profiles: ${profiles.join(", ")}` : null,
  ].filter(s => s !== null).join("\n");

  const jsonInstruction = `\nAt the very end of your response, output the following JSON on its own line with no surrounding text or code fences:\n{"risk":"High|Medium|Low|Unknown","summary":"one sentence summary","flags":["finding 1","finding 2","finding 3"]}`;

  let userPrompt: string;
  if (depth === "quick") {
    userPrompt = `Analyse this email address in 2–3 sentences. State whether it is likely legitimate or suspicious, and the single most important finding.\n\n${meta}${jsonInstruction}`;
  } else if (depth === "standard") {
    userPrompt = `Analyse this email address. Cover: (1) Legitimacy Assessment, (2) Key Risk Signals, (3) Email Infrastructure Health, (4) Recommended Action. Keep each section to 2–3 sentences.\n\n${meta}${jsonInstruction}`;
  } else {
    userPrompt = `Produce a full email intelligence report. Cover each section in depth:\n1. Address & Domain Analysis\n2. Breach & Leak History\n3. Reputation & Trust Signals\n4. Email Infrastructure (MX / SPF / DMARC)\n5. Domain Age & Registration Analysis\n6. Malicious Activity Indicators\n7. Recommended Actions\n\nEmail metadata:\n${meta}${jsonInstruction}`;
  }

  const systemPrompt = `You are an email intelligence analyst specialising in fraud detection, phishing identification, and security research. Analyse email addresses for legitimacy, breach exposure, DNS infrastructure health, and threat indicators. Be precise and actionable. Clearly flag disposable, temporary, or known malicious email providers. Domain spoofing risk is determined by SPF/DMARC policies. Do not use markdown formatting — plain text only.`;

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

  const result: EmailLookupResult = {
    email,
    domain,
    is_disposable:      isDisposable,
    is_free_provider:   isFreeProvider,
    suspicious:         isSuspicious,
    references,
    blacklisted,
    credentials_leaked: credentialsLeaked,
    data_breach:        dataBreach,
    malicious_activity: maliciousActivity,
    spoofable,
    domain_reputation:  domainReputation,
    profiles,
    // DNS
    mx_records:    mxRecords,
    has_mx:        hasMx,
    spf_record:    spfRecord,
    dmarc_record:  dmarcRecord,
    spf_enforced:  spfEnforced,
    dmarc_enforced: dmarcEnforced,
    // Domain age
    domain_age_days: domainAgeDays,
    domain_created:  domainCreated,
    domain_registrar: rdap.registrar,
    // Activity
    first_seen:     firstSeen,
    last_seen:      lastSeen,
    deliverable,
    new_domain:     newDomain,
    suspicious_tld: suspiciousTld,
    // AI
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
