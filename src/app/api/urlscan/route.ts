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
const MAX_TOKENS: Record<Depth, number> = { quick: 300, standard: 600, deep: 1000 };

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
        ? raw.flags.filter((f: unknown) => typeof f === "string").slice(0, 10) : [],
    };
  } catch { return null; }
}

// Known URL shorteners
const SHORTENERS = ["bit.ly","tinyurl.com","t.co","ow.ly","goo.gl","buff.ly","dlvr.it",
  "su.pr","is.gd","cli.gs","yfrog.com","migre.me","ff.im","tiny.cc","url4.eu","tr.im",
  "twit.ac","snipurl.com","short.to","BudURL.com","ping.fm","post.ly","Just.as",
  "bkite.com","snipr.com","flic.kr","loopt.us","doiop.com","short.ie","kl.am","wp.me",
  "rubyurl.com","om.ly","to.ly","bit.do","t.ly","rb.gy","cutt.ly","shorturl.at"];

async function resolveDomainToIp(domain: string): Promise<string | null> {
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`,
      { cache: "no-store", signal: AbortSignal.timeout(5000) }
    );
    const data = await res.json() as { Answer?: Array<{ type: number; data: string }> };
    const aRecord = data.Answer?.find(r => r.type === 1);
    return aRecord?.data ?? null;
  } catch { return null; }
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

  // Normalise — add https:// if no protocol
  let urlStr = rawUrl.trim();
  if (!/^https?:\/\//i.test(urlStr)) urlStr = `https://${urlStr}`;

  let parsedUrl: URL;
  try { parsedUrl = new URL(urlStr); }
  catch {
    return NextResponse.json({ error: "Invalid URL format." }, { status: 400 });
  }

  const validDepths: Depth[] = ["quick", "standard", "deep"];
  const depth: Depth = validDepths.includes(rawDepth as Depth) ? (rawDepth as Depth) : "standard";

  const domain = parsedUrl.hostname.toLowerCase().replace(/^www\./, "");
  const isShortened = SHORTENERS.some(s => domain === s || domain.endsWith(`.${s}`));

  // ---------------------------------------------------------------------------
  // Parallel: URLhaus check + DNS resolution
  // ---------------------------------------------------------------------------
  const [urlhausRes, resolvedIp] = await Promise.all([
    // URLhaus - free malware URL database
    fetch("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "PhoneScan/1.0" },
      body: `url=${encodeURIComponent(urlStr)}`,
      signal: AbortSignal.timeout(6000),
      cache: "no-store",
    }).then(r => r.json()).catch(() => null),
    resolveDomainToIp(parsedUrl.hostname),
  ]);

  // Parse URLhaus response
  interface URLhausResponse {
    query_status?: string;
    url_status?: string;
    threat?: string;
    tags?: string[];
  }
  const uh = urlhausRes as URLhausResponse | null;
  const uhStatus = uh?.query_status ?? "unknown";
  const urlhausStatus: UrlScanResult["urlhaus_status"] =
    uhStatus === "is_host" || uhStatus === "no_results" ? "not_found"
    : uh?.url_status === "online"  ? "online"
    : uh?.url_status === "offline" ? "offline"
    : "unknown";
  const urlhausThreat = uh?.threat ?? null;
  const urlhausTags   = Array.isArray(uh?.tags) ? uh!.tags as string[] : [];

  const isMalware  = urlhausTags.includes("malware_download") || urlhausThreat === "malware_download";
  const isPhishing = urlhausTags.includes("phishing") || urlhausThreat === "phishing";

  // ---------------------------------------------------------------------------
  // Build Groq prompt
  // ---------------------------------------------------------------------------
  const meta = [
    `URL: ${urlStr}`,
    `Domain: ${domain}`,
    resolvedIp ? `Resolved IP: ${resolvedIp}` : "IP resolution: failed",
    `URL Shortener: ${isShortened ? "YES — hides true destination" : "No"}`,
    `URLhaus database: ${urlhausStatus === "not_found" ? "not in database (clean signal)" : urlhausStatus}`,
    urlhausThreat ? `Threat type: ${urlhausThreat}` : null,
    urlhausTags.length > 0 ? `Tags: ${urlhausTags.join(", ")}` : null,
    isMalware  ? "⚠️ MALWARE: confirmed malware download URL" : null,
    isPhishing ? "⚠️ PHISHING: confirmed phishing URL" : null,
    isShortened ? "⚠️ SHORTENED URL: destination unknown — treat with caution" : null,
    `Protocol: ${parsedUrl.protocol}`,
    `Path: ${parsedUrl.pathname || "/"}`,
    parsedUrl.searchParams.size > 0 ? `Query parameters: ${parsedUrl.searchParams.size} present` : null,
  ].filter(Boolean).join("\n");

  const jsonInstruction = `\nAt the very end of your response, output the following JSON on its own line:\n{"risk":"High|Medium|Low|Unknown","summary":"one sentence summary","flags":["finding 1","finding 2","finding 3"]}`;

  let userPrompt: string;
  if (depth === "quick") {
    userPrompt = `Analyse this URL in 2–3 sentences. State whether it is safe, suspicious, or dangerous, and the most important finding.\n\n${meta}${jsonInstruction}`;
  } else if (depth === "standard") {
    userPrompt = `Analyse this URL. Cover: (1) Safety Assessment, (2) Key Red Flags, (3) Recommended Action. 2–3 sentences each.\n\n${meta}${jsonInstruction}`;
  } else {
    userPrompt = `Produce a full URL threat analysis. Cover:\n1. URL Structure & Domain Analysis\n2. Threat Intelligence Findings\n3. Phishing & Malware Indicators\n4. Redirect & Obfuscation Risks\n5. Recommended Actions\n\nURL data:\n${meta}${jsonInstruction}`;
  }

  const systemPrompt = `You are a cybersecurity analyst specialising in URL and web threat analysis. Analyse URLs for phishing, malware, scam, and social engineering indicators. Be direct about threats. Do not use markdown formatting.`;

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
