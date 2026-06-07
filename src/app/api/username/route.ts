import { NextRequest, NextResponse } from "next/server";
import Groq from "groq-sdk";
import type { Depth, RiskLevel, UsernameResult } from "@/lib/phone";

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

// ---------------------------------------------------------------------------
// Platform definitions
// ---------------------------------------------------------------------------

interface Platform {
  name: string;
  category: string;
  url: (u: string) => string;
  apiUrl: (u: string) => string;
  // Returns true if the account exists based on the API response
  exists: (status: number, body: unknown) => boolean;
}

const PLATFORMS: Platform[] = [
  {
    name: "GitHub", category: "Dev",
    url: u => `https://github.com/${u}`,
    apiUrl: u => `https://api.github.com/users/${encodeURIComponent(u)}`,
    exists: (s, b) => s === 200 && !!(b as Record<string, unknown>)?.login,
  },
  {
    name: "GitLab", category: "Dev",
    url: u => `https://gitlab.com/${u}`,
    apiUrl: u => `https://gitlab.com/api/v4/users?username=${encodeURIComponent(u)}`,
    exists: (s, b) => s === 200 && Array.isArray(b) && b.length > 0,
  },
  {
    name: "npm", category: "Dev",
    url: u => `https://www.npmjs.com/~${u}`,
    apiUrl: u => `https://registry.npmjs.org/-/user/org.couchdb.user:${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },
  {
    name: "dev.to", category: "Dev",
    url: u => `https://dev.to/${u}`,
    apiUrl: u => `https://dev.to/api/users/by_username?url=${encodeURIComponent(u)}`,
    exists: (s, b) => s === 200 && !!(b as Record<string, unknown>)?.id,
  },
  {
    name: "HackerNews", category: "Community",
    url: u => `https://news.ycombinator.com/user?id=${u}`,
    apiUrl: u => `https://hacker-news.firebaseio.com/v0/user/${encodeURIComponent(u)}.json`,
    exists: (s, b) => s === 200 && b !== null && !!(b as Record<string, unknown>)?.id,
  },
  {
    name: "Reddit", category: "Community",
    url: u => `https://www.reddit.com/user/${u}`,
    apiUrl: u => `https://www.reddit.com/user/${encodeURIComponent(u)}/about.json`,
    exists: (s, b) => s === 200 && !!(b as Record<string, unknown>)?.data,
  },
  {
    name: "Keybase", category: "Crypto/Security",
    url: u => `https://keybase.io/${u}`,
    apiUrl: u => `https://keybase.io/_/api/1.0/user/lookup.json?username=${encodeURIComponent(u)}`,
    exists: (s, b) => {
      if (s !== 200) return false;
      const data = b as Record<string, unknown>;
      return Array.isArray(data?.them) && (data.them as unknown[]).length > 0;
    },
  },
  {
    name: "Chess.com", category: "Gaming",
    url: u => `https://www.chess.com/member/${u}`,
    apiUrl: u => `https://api.chess.com/pub/player/${encodeURIComponent(u.toLowerCase())}`,
    exists: (s, b) => s === 200 && !!(b as Record<string, unknown>)?.username,
  },
  {
    name: "Lichess", category: "Gaming",
    url: u => `https://lichess.org/@/${u}`,
    apiUrl: u => `https://lichess.org/api/user/${encodeURIComponent(u.toLowerCase())}`,
    exists: (s, b) => s === 200 && !!(b as Record<string, unknown>)?.id,
  },
  {
    name: "Replit", category: "Dev",
    url: u => `https://replit.com/@${u}`,
    apiUrl: u => `https://replit.com/data/repls/${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },
  {
    name: "Gravatar", category: "Identity",
    url: u => `https://gravatar.com/${u}`,
    apiUrl: u => `https://en.gravatar.com/${encodeURIComponent(u)}.json`,
    exists: (s) => s === 200,
  },
  {
    name: "Twitch", category: "Streaming",
    url: u => `https://www.twitch.tv/${u}`,
    apiUrl: u => `https://www.twitch.tv/${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },
];

const HEADERS = {
  "User-Agent": "PhoneScan/1.0 (+https://phonescan-gamma.vercel.app)",
  "Accept": "application/json",
};

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

  const { username: rawUsername, depth: rawDepth } = body as Record<string, unknown>;
  if (typeof rawUsername !== "string" || !rawUsername.trim()) {
    return NextResponse.json({ error: "A username is required." }, { status: 400 });
  }

  const username = rawUsername.trim().replace(/^@/, ""); // strip leading @
  if (!/^[a-zA-Z0-9_.\-]{1,50}$/.test(username)) {
    return NextResponse.json(
      { error: "Invalid username. Use only letters, numbers, underscores, hyphens, and dots." },
      { status: 400 }
    );
  }

  const validDepths: Depth[] = ["quick", "standard", "deep"];
  const depth: Depth = validDepths.includes(rawDepth as Depth) ? (rawDepth as Depth) : "standard";

  // ---------------------------------------------------------------------------
  // Check all platforms in parallel
  // ---------------------------------------------------------------------------
  const fetchOpts = { signal: AbortSignal.timeout(6000), headers: HEADERS, cache: "no-store" as const };

  const checks = await Promise.allSettled(
    PLATFORMS.map(async (platform) => {
      try {
        const res = await fetch(platform.apiUrl(username), fetchOpts);
        let body: unknown = null;
        const ct = res.headers.get("content-type") ?? "";
        if (ct.includes("json")) {
          try { body = await res.json(); } catch { body = null; }
        }
        const found = platform.exists(res.status, body);
        return { platform, found };
      } catch {
        return { platform, found: false };
      }
    })
  );

  const found: UsernameResult["found"] = [];
  const not_found: string[] = [];

  for (const result of checks) {
    if (result.status === "fulfilled") {
      const { platform, found: isFound } = result.value;
      if (isFound) {
        found.push({ platform: platform.name, url: platform.url(username), category: platform.category });
      } else {
        not_found.push(platform.name);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Groq analysis
  // ---------------------------------------------------------------------------
  const foundList = found.map(f => `${f.platform} (${f.category}): ${f.url}`).join("\n");
  const meta = [
    `Username: @${username}`,
    `Platforms found on (${found.length}/${PLATFORMS.length}): ${found.length > 0 ? found.map(f => f.platform).join(", ") : "none"}`,
    `Platforms not found: ${not_found.join(", ") || "none"}`,
    found.length > 0 ? `Profile links:\n${foundList}` : null,
  ].filter(Boolean).join("\n");

  const jsonInstruction = `\nAt the very end of your response, output the following JSON on its own line:\n{"risk":"High|Medium|Low|Unknown","summary":"one sentence summary","flags":["finding 1","finding 2","finding 3"]}`;

  let userPrompt: string;
  if (depth === "quick") {
    userPrompt = `Analyse this username OSINT data in 2–3 sentences. Note the most significant platforms found and any risk implications.\n\n${meta}${jsonInstruction}`;
  } else if (depth === "standard") {
    userPrompt = `Analyse this username. Cover: (1) Digital Footprint Overview, (2) Key Platforms & Implications, (3) Risk Assessment. 2–3 sentences each.\n\n${meta}${jsonInstruction}`;
  } else {
    userPrompt = `Produce a full username OSINT report. Cover:\n1. Digital Footprint Scope\n2. Platform Presence & Implications\n3. Identity Consistency Signals\n4. Privacy Risk Assessment\n5. Recommended Next Steps\n\nData:\n${meta}${jsonInstruction}`;
  }

  const systemPrompt = `You are an OSINT analyst specialising in digital identity investigation. Given a username and the platforms it was found on, analyse the person's digital footprint, assess privacy risks, and identify any notable patterns. Be factual and precise. Do not use markdown.`;

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

  const result: UsernameResult = {
    username,
    found,
    not_found,
    checked: PLATFORMS.length,
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
