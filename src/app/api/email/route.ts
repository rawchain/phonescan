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
    ?? req.headers.get("x-real-ip")
    ?? "unknown";
}

// ---------------------------------------------------------------------------
// Groq
// ---------------------------------------------------------------------------

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
const MAX_TOKENS: Record<Depth, number> = { quick: 300, standard: 600, deep: 1100 };

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
  // Fetch emailrep.io — free, no API key required
  // ---------------------------------------------------------------------------
  let emailrep: EmailRepResponse | null = null;
  try {
    const res = await fetch(`https://emailrep.io/query/${encodeURIComponent(email)}`, {
      headers: { "User-Agent": "PhoneScan/1.0" },
      signal: AbortSignal.timeout(7000),
      cache: "no-store",
    });
    if (res.ok) emailrep = await res.json() as EmailRepResponse;
  } catch {
    // continue without emailrep — Groq still runs
  }

  const details = emailrep?.details ?? {};
  const isDisposable       = details.disposable         ?? false;
  const isFreeProvider     = details.free_provider      ?? false;
  const isSuspicious       = emailrep?.suspicious       ?? false;
  const references         = emailrep?.references       ?? 0;
  const blacklisted        = details.blacklisted        ?? false;
  const credentialsLeaked  = details.credentials_leaked ?? false;
  const dataBreach         = details.data_breach        ?? false;
  const maliciousActivity  = details.malicious_activity ?? false;
  const spoofable          = details.spoofable          ?? false;
  const domainReputation   = details.domain_reputation  ?? null;
  const profiles           = details.profiles           ?? [];
  const reputation         = emailrep?.reputation       ?? "unknown";

  // ---------------------------------------------------------------------------
  // Build enriched Groq prompt
  // ---------------------------------------------------------------------------
  const meta = [
    `Email: ${email}`,
    `Domain: ${domain}`,
    `Overall Reputation: ${reputation}`,
    `Suspicious flag: ${isSuspicious ? "YES" : "No"}`,
    `References in external databases: ${references}`,
    `Disposable/temporary email: ${isDisposable ? "YES — treat with high suspicion" : "No"}`,
    `Free email provider: ${isFreeProvider ? "Yes" : "No"}`,
    `Blacklisted: ${blacklisted ? "YES" : "No"}`,
    `Credentials leaked in known breach: ${credentialsLeaked ? "YES" : "No"}`,
    `Associated with a known data breach: ${dataBreach ? "YES" : "No"}`,
    `Known malicious activity: ${maliciousActivity ? "YES" : "No"}`,
    `Domain can be spoofed (weak SPF/DMARC): ${spoofable ? "Yes" : "No (strict)"}`,
    `Domain reputation: ${domainReputation ?? "unknown"}`,
    profiles.length > 0 ? `Known linked profiles: ${profiles.join(", ")}` : null,
    details.first_seen && details.first_seen !== "never" ? `First seen: ${details.first_seen}` : null,
    details.last_seen && details.last_seen !== "never" ? `Last seen: ${details.last_seen}` : null,
    details.days_since_domain_creation != null
      ? `Domain age: ${details.days_since_domain_creation} days` : null,
    details.valid_mx === false ? "MX records: MISSING — domain cannot receive email" : null,
    details.new_domain ? "⚠️ New domain (created recently — higher phishing risk)" : null,
    details.suspicious_tld ? "⚠️ Suspicious TLD detected" : null,
  ].filter(Boolean).join("\n");

  const jsonInstruction = `\nAt the very end of your response, output the following JSON on its own line with no surrounding text or code fences:\n{"risk":"High|Medium|Low|Unknown","summary":"one sentence summary","flags":["finding 1","finding 2","finding 3"]}`;

  let userPrompt: string;
  if (depth === "quick") {
    userPrompt = `Analyse this email address in 2–3 sentences. State whether it is likely legitimate or suspicious, and the single most important finding.\n\n${meta}${jsonInstruction}`;
  } else if (depth === "standard") {
    userPrompt = `Analyse this email address. Cover: (1) Legitimacy Assessment, (2) Key Risk Signals, (3) Recommended Action. Keep each section to 2–3 sentences.\n\n${meta}${jsonInstruction}`;
  } else {
    userPrompt = `Produce a full email intelligence report. Cover each section in depth:\n1. Address & Domain Analysis\n2. Breach & Leak History\n3. Reputation & Trust Signals\n4. Malicious Activity Indicators\n5. Domain Security (SPF/DMARC/MX)\n6. Recommended Actions\n\nEmail metadata:\n${meta}${jsonInstruction}`;
  }

  const systemPrompt = `You are an email intelligence analyst specialising in fraud detection, phishing identification, and security research. Analyse email addresses for legitimacy, breach exposure, and threat indicators. Be precise and actionable. Clearly flag disposable, temporary, or known malicious email providers. Do not use markdown formatting — plain text only.`;

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
