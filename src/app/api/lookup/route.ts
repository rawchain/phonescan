import { NextRequest, NextResponse } from "next/server";
import Groq from "groq-sdk";
import {
  parsePhoneNumber,
  getSystemPrompt,
  buildUserPrompt,
  type Mode,
  type Depth,
  type RiskLevel,
  type LookupResult,
} from "@/lib/phone";

// ---------------------------------------------------------------------------
// Rate limiter — in-memory, per-IP, rolling 24-hour window
// ---------------------------------------------------------------------------

interface RateLimitEntry {
  count: number;
  resetAt: number; // epoch ms
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

  if (entry.count >= LIMIT) {
    return { allowed: false, remaining: 0 };
  }

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
// JSON extraction — finds the last {...} block in the AI response
// ---------------------------------------------------------------------------

function extractJson(text: string): { risk: RiskLevel; summary: string; flags: string[] } | null {
  // Walk backwards to find the last closing brace, then find its matching open
  const lastClose = text.lastIndexOf("}");
  if (lastClose === -1) return null;

  const firstOpen = text.lastIndexOf("{", lastClose);
  if (firstOpen === -1) return null;

  try {
    const raw = JSON.parse(text.slice(firstOpen, lastClose + 1));

    const validRisk: RiskLevel[] = ["High", "Medium", "Low", "Unknown"];
    const risk: RiskLevel = validRisk.includes(raw.risk) ? raw.risk : "Unknown";
    const summary = typeof raw.summary === "string" ? raw.summary.trim() : "No summary provided.";
    const flags: string[] = Array.isArray(raw.flags)
      ? raw.flags.filter((f: unknown) => typeof f === "string").slice(0, 10)
      : [];

    return { risk, summary, flags };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Route handler
// ---------------------------------------------------------------------------

function getIp(req: NextRequest): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ??
    req.headers.get("x-real-ip") ??
    "unknown"
  );
}

export async function POST(req: NextRequest) {
  // --- Rate limit ---
  const ip = getIp(req);
  const { allowed, remaining } = checkRateLimit(ip);

  if (!allowed) {
    return NextResponse.json(
      {
        error:
          "You've reached the daily lookup limit. Please try again in 24 hours.",
      },
      {
        status: 429,
        headers: { "X-RateLimit-Remaining": "0" },
      }
    );
  }

  // --- Parse body ---
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON in request body." }, { status: 400 });
  }

  const { number, mode: rawMode, depth: rawDepth } = body as Record<string, unknown>;

  if (typeof number !== "string" || !number.trim()) {
    return NextResponse.json({ error: "A phone number or IP address is required." }, { status: 400 });
  }

  const validModes: Mode[] = ["consumer", "blue", "red"];
  const validDepths: Depth[] = ["quick", "standard", "deep"];
  const mode: Mode = validModes.includes(rawMode as Mode) ? (rawMode as Mode) : "consumer";
  const depth: Depth = validDepths.includes(rawDepth as Depth) ? (rawDepth as Depth) : "standard";

  // --- Parse input — skip phone parsing for IP mode ---
  const parsed = mode === "red"
    ? {
        raw: number.trim(),
        e164: null,
        country: null,
        region: null,
        type: "unknown" as const,
        valid: true,           // IPs are always "valid" inputs
        nationalNumber: null,
        internationalFormat: null,
      }
    : parsePhoneNumber(number);

  // --- Build system prompt ---
  const systemPrompt = getSystemPrompt(mode);

  // --- Fetch NumVerify first (fast ~1s) so carrier/lineType can enrich the Groq prompt ---
  const numVerifyKey = process.env.NUMVERIFY_API_KEY;
  const e164 = parsed.e164 ?? number.trim();

  let numVerifyData: Record<string, unknown> | null = null;

  if (numVerifyKey && mode !== "red") {
    try {
      const nvRes = await fetch(
        `http://apilayer.net/api/validate?access_key=${numVerifyKey}&number=${encodeURIComponent(e164)}&format=1`,
        { cache: "no-store", signal: AbortSignal.timeout(5000) }
      );
      const nv = await nvRes.json() as Record<string, unknown>;
      if (nv && nv.valid !== false && !nv.error) {
        numVerifyData = nv;
      }
    } catch {
      // NumVerify timed out or failed — continue without it
    }
  }

  // --- Build user prompt — now enriched with verified carrier + line type ---
  const verifiedCarrier  = (numVerifyData?.carrier  as string | null | undefined) ?? null;
  const verifiedLineType = (numVerifyData?.line_type as string | null | undefined) ?? null;
  const userPrompt = buildUserPrompt(number, parsed, mode, depth, verifiedCarrier, verifiedLineType);

  // --- Call Groq ---
  let aiText: string;

  try {
    const groqResult = await groq.chat.completions.create({
      model: "llama-3.3-70b-versatile",
      temperature: 0.4,
      max_tokens: MAX_TOKENS[depth],
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
    });
    aiText = groqResult.choices[0]?.message?.content ?? "";
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Failed to contact AI service.";
    return NextResponse.json(
      { error: `AI service error: ${message}` },
      { status: 502 }
    );
  }

  // --- Extract structured JSON from response ---
  const extracted = extractJson(aiText);

  const result: LookupResult = {
    risk: extracted?.risk ?? "Unknown",
    summary: extracted?.summary ?? aiText.slice(0, 200).trim(),
    flags: extracted?.flags ?? [],
    raw: aiText,
    parsed,
    mode,
    depth,
    // NumVerify enrichment
    carrier:            verifiedCarrier,
    line_type_verified: verifiedLineType,
    number_valid:       numVerifyData?.valid != null ? Boolean(numVerifyData.valid) : null,
    number_location:    (numVerifyData?.location as string | null | undefined) ?? null,
  };

  return NextResponse.json(result, {
    status: 200,
    headers: { "X-RateLimit-Remaining": String(remaining) },
  });
}
