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
        ? raw.flags.filter((f: unknown) => typeof f === "string").slice(0, 10) : [],
    };
  } catch { return null; }
}

// ---------------------------------------------------------------------------
// Platform definitions — 27 platforms
// ---------------------------------------------------------------------------

interface Platform {
  name: string;
  category: string;
  url: (u: string) => string;
  apiUrl: (u: string) => string;
  exists: (status: number, body: unknown) => boolean;
  // Optional per-platform headers (e.g. User-Agent spoofing not needed — all server-side)
}

function b(x: unknown): Record<string, unknown> {
  return (x && typeof x === "object") ? x as Record<string, unknown> : {};
}

const PLATFORMS: Platform[] = [
  // ── Dev & Engineering ─────────────────────────────────────────────────────
  {
    name: "GitHub", category: "Dev",
    url:    u => `https://github.com/${u}`,
    apiUrl: u => `https://api.github.com/users/${encodeURIComponent(u)}`,
    exists: (s, x) => s === 200 && !!b(x).login,
  },
  {
    name: "GitLab", category: "Dev",
    url:    u => `https://gitlab.com/${u}`,
    apiUrl: u => `https://gitlab.com/api/v4/users?username=${encodeURIComponent(u)}`,
    exists: (s, x) => s === 200 && Array.isArray(x) && (x as unknown[]).length > 0,
  },
  {
    name: "npm", category: "Dev",
    url:    u => `https://www.npmjs.com/~${u}`,
    apiUrl: u => `https://registry.npmjs.org/-/user/org.couchdb.user:${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },
  {
    name: "dev.to", category: "Dev",
    url:    u => `https://dev.to/${u}`,
    apiUrl: u => `https://dev.to/api/users/by_username?url=${encodeURIComponent(u)}`,
    exists: (s, x) => s === 200 && !!b(x).id,
  },
  {
    name: "Replit", category: "Dev",
    url:    u => `https://replit.com/@${u}`,
    apiUrl: u => `https://replit.com/data/repls/${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },
  {
    name: "Codeberg", category: "Dev",
    url:    u => `https://codeberg.org/${u}`,
    apiUrl: u => `https://codeberg.org/api/v1/users/${encodeURIComponent(u)}`,
    exists: (s, x) => s === 200 && !!b(x).login,
  },
  {
    name: "DockerHub", category: "Dev",
    url:    u => `https://hub.docker.com/u/${u}`,
    apiUrl: u => `https://hub.docker.com/v2/users/${encodeURIComponent(u)}/`,
    exists: (s, x) => s === 200 && !!b(x).username,
  },
  {
    name: "HuggingFace", category: "Dev",
    url:    u => `https://huggingface.co/${u}`,
    apiUrl: u => `https://huggingface.co/api/users/${encodeURIComponent(u)}`,
    exists: (s, x) => s === 200 && (!!b(x).name || !!b(x).user),
  },
  {
    name: "PyPI", category: "Dev",
    url:    u => `https://pypi.org/user/${u}/`,
    apiUrl: u => `https://pypi.org/user/${encodeURIComponent(u)}/`,
    exists: (s) => s === 200,
  },
  {
    name: "RubyGems", category: "Dev",
    url:    u => `https://rubygems.org/profiles/${u}`,
    apiUrl: u => `https://rubygems.org/api/v1/owners/${encodeURIComponent(u)}/gems.json`,
    exists: (s, x) => s === 200 && Array.isArray(x),
  },
  {
    name: "Bitbucket", category: "Dev",
    url:    u => `https://bitbucket.org/${u}`,
    apiUrl: u => `https://api.bitbucket.org/2.0/users/${encodeURIComponent(u)}`,
    exists: (s, x) => s === 200 && !!b(x).account_id,
  },
  {
    name: "Codepen", category: "Dev",
    url:    u => `https://codepen.io/${u}`,
    apiUrl: u => `https://codepen.io/${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },

  // ── Community & Forums ────────────────────────────────────────────────────
  {
    name: "HackerNews", category: "Community",
    url:    u => `https://news.ycombinator.com/user?id=${u}`,
    apiUrl: u => `https://hacker-news.firebaseio.com/v0/user/${encodeURIComponent(u)}.json`,
    exists: (s, x) => s === 200 && x !== null && !!b(x).id,
  },
  {
    name: "Reddit", category: "Community",
    url:    u => `https://www.reddit.com/user/${u}`,
    apiUrl: u => `https://www.reddit.com/user/${encodeURIComponent(u)}/about.json`,
    exists: (s, x) => s === 200 && !!b(b(x).data).name,
  },
  {
    name: "Stack Overflow", category: "Community",
    url:    u => `https://stackoverflow.com/users?tab=reputation&search=${u}`,
    apiUrl: u => `https://api.stackexchange.com/2.3/users?order=desc&sort=reputation&inname=${encodeURIComponent(u)}&site=stackoverflow&pagesize=5`,
    exists: (s, x) => {
      if (s !== 200 || !Array.isArray(b(x).items)) return false;
      const items = b(x).items as Array<Record<string, unknown>>;
      // Accept if any item has a display_name (can't access u here; presence is good signal)
      return items.length > 0 && items.some(i => typeof i.display_name === "string" && i.display_name.length > 0);
    },
  },
  {
    name: "Mastodon", category: "Community",
    url:    u => `https://mastodon.social/@${u}`,
    apiUrl: u => `https://mastodon.social/api/v1/accounts/lookup?acct=${encodeURIComponent(u)}`,
    exists: (s, x) => s === 200 && !!b(x).id,
  },

  // ── Gaming ────────────────────────────────────────────────────────────────
  {
    name: "Chess.com", category: "Gaming",
    url:    u => `https://www.chess.com/member/${u}`,
    apiUrl: u => `https://api.chess.com/pub/player/${encodeURIComponent(u.toLowerCase())}`,
    exists: (s, x) => s === 200 && !!b(x).username,
  },
  {
    name: "Lichess", category: "Gaming",
    url:    u => `https://lichess.org/@/${u}`,
    apiUrl: u => `https://lichess.org/api/user/${encodeURIComponent(u.toLowerCase())}`,
    exists: (s, x) => s === 200 && !!b(x).id,
  },
  {
    name: "Speedrun.com", category: "Gaming",
    url:    u => `https://www.speedrun.com/user/${u}`,
    apiUrl: u => `https://www.speedrun.com/api/v1/users?lookup=${encodeURIComponent(u)}`,
    exists: (s, x) => {
      if (s !== 200) return false;
      const data = (b(x).data) as unknown;
      return Array.isArray(data) ? (data as unknown[]).length > 0 : !!b(data as Record<string,unknown>).id;
    },
  },

  // ── Social & Creative ─────────────────────────────────────────────────────
  {
    name: "Twitch", category: "Streaming",
    url:    u => `https://www.twitch.tv/${u}`,
    apiUrl: u => `https://www.twitch.tv/${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },
  {
    name: "Bluesky", category: "Social",
    url:    u => `https://bsky.app/profile/${u}.bsky.social`,
    apiUrl: u => `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(u)}.bsky.social`,
    exists: (s, x) => s === 200 && !!b(x).did,
  },
  {
    name: "Medium", category: "Social",
    url:    u => `https://medium.com/@${u}`,
    apiUrl: u => `https://medium.com/@${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },
  {
    name: "Keybase", category: "Crypto/Security",
    url:    u => `https://keybase.io/${u}`,
    apiUrl: u => `https://keybase.io/_/api/1.0/user/lookup.json?username=${encodeURIComponent(u)}`,
    exists: (s, x) => {
      if (s !== 200) return false;
      const them = b(x).them;
      return Array.isArray(them) && (them as unknown[]).length > 0;
    },
  },

  // ── Identity & Publishing ─────────────────────────────────────────────────
  {
    name: "Gravatar", category: "Identity",
    url:    u => `https://gravatar.com/${u}`,
    apiUrl: u => `https://en.gravatar.com/${encodeURIComponent(u)}.json`,
    exists: (s) => s === 200,
  },
  {
    name: "Substack", category: "Publishing",
    url:    u => `https://${u}.substack.com`,
    apiUrl: u => `https://${encodeURIComponent(u)}.substack.com/api/v1/homepage`,
    exists: (s) => s === 200,
  },
  {
    name: "Patreon", category: "Publishing",
    url:    u => `https://www.patreon.com/${u}`,
    apiUrl: u => `https://www.patreon.com/api/user?filter[vanity]=${encodeURIComponent(u)}`,
    exists: (s, x) => {
      if (s !== 200) return false;
      const data = (b(x).data) as unknown[];
      return Array.isArray(data) && data.length > 0;
    },
  },
  {
    name: "SoundCloud", category: "Music",
    url:    u => `https://soundcloud.com/${u}`,
    apiUrl: u => `https://soundcloud.com/${encodeURIComponent(u)}`,
    exists: (s) => s === 200,
  },
  {
    name: "Bandcamp", category: "Music",
    url:    u => `https://${u}.bandcamp.com`,
    apiUrl: u => `https://${encodeURIComponent(u)}.bandcamp.com`,
    exists: (s) => s === 200,
  },
];

const HEADERS = {
  "User-Agent": "Mozilla/5.0 (compatible; REVL/1.0; +https://revl.vercel.app)",
  "Accept": "application/json, text/html",
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

  const username = rawUsername.trim().replace(/^@/, "");
  if (!/^[a-zA-Z0-9_.\-]{1,50}$/.test(username)) {
    return NextResponse.json(
      { error: "Invalid username. Use only letters, numbers, underscores, hyphens, and dots." },
      { status: 400 }
    );
  }

  const validDepths: Depth[] = ["quick", "standard", "deep"];
  const depth: Depth = validDepths.includes(rawDepth as Depth) ? (rawDepth as Depth) : "standard";

  // ---------------------------------------------------------------------------
  // Check all platforms in parallel (7 s timeout each)
  // ---------------------------------------------------------------------------
  const checks = await Promise.allSettled(
    PLATFORMS.map(async (platform) => {
      try {
        const res = await fetch(platform.apiUrl(username), {
          signal: AbortSignal.timeout(7000),
          headers: HEADERS,
          cache: "no-store",
        });
        let respBody: unknown = null;
        const ct = res.headers.get("content-type") ?? "";
        if (ct.includes("json")) {
          try { respBody = await res.json(); } catch { respBody = null; }
        } else {
          // For HTML-based checks we only care about status
          respBody = null;
        }
        const found = platform.exists(res.status, respBody);
        return { platform, found };
      } catch {
        return { platform, found: false };
      }
    })
  );

  const found: UsernameResult["found"] = [];
  const not_found: string[] = [];

  for (const r of checks) {
    if (r.status === "fulfilled") {
      const { platform, found: isFound } = r.value;
      if (isFound) {
        found.push({ platform: platform.name, url: platform.url(username), category: platform.category });
      } else {
        not_found.push(platform.name);
      }
    } else {
      // Promise rejected entirely — count as not found
      not_found.push("Unknown");
    }
  }

  // ---------------------------------------------------------------------------
  // Groq analysis
  // ---------------------------------------------------------------------------
  const foundList = found.map(f => `${f.platform} (${f.category}): ${f.url}`).join("\n");
  const meta = [
    `Username: @${username}`,
    `Total platforms checked: ${PLATFORMS.length}`,
    `Found on ${found.length} platforms: ${found.length > 0 ? found.map(f => f.platform).join(", ") : "none"}`,
    `Not found on: ${not_found.slice(0, 15).join(", ") || "none"}`,
    "",
    found.length > 0 ? `Profile links:\n${foundList}` : "No profiles found.",
    "",
    `Digital footprint breadth: ${found.length === 0 ? "None detected" : found.length <= 3 ? "Minimal" : found.length <= 8 ? "Moderate" : found.length <= 15 ? "Extensive" : "Very Extensive"}`,
    `Dev presence: ${found.filter(f => f.category === "Dev").map(f => f.platform).join(", ") || "none"}`,
    `Community presence: ${found.filter(f => f.category === "Community").map(f => f.platform).join(", ") || "none"}`,
    `Social presence: ${found.filter(f => ["Social","Streaming","Publishing","Music"].includes(f.category)).map(f => f.platform).join(", ") || "none"}`,
    `Security presence (Keybase, etc.): ${found.filter(f => f.category === "Crypto/Security").map(f => f.platform).join(", ") || "none"}`,
  ].filter(s => s !== null).join("\n");

  const jsonInstruction = `\nAt the very end of your response, output the following JSON on its own line:\n{"risk":"High|Medium|Low|Unknown","summary":"one sentence summary","flags":["finding 1","finding 2","finding 3"]}`;

  let userPrompt: string;
  if (depth === "quick") {
    userPrompt = `Analyse this username OSINT data in 2–3 sentences. Note the most significant platforms found and any risk implications.\n\n${meta}${jsonInstruction}`;
  } else if (depth === "standard") {
    userPrompt = `Analyse this username. Cover: (1) Digital Footprint Overview — how broad and consistent is the online presence, (2) Key Platforms & What They Reveal, (3) Privacy Risk Assessment — is this person easily traceable? 2–4 sentences each.\n\n${meta}${jsonInstruction}`;
  } else {
    userPrompt = `Produce a full username OSINT intelligence report. Cover:\n1. Digital Footprint Scope & Breadth\n2. Platform Presence & Cross-Platform Consistency\n3. Professional vs Personal Identity Balance\n4. Developer/Technical Profile (if applicable)\n5. Privacy & Exposure Risk Assessment\n6. What this presence reveals about the person\n7. Recommended Actions (for subject or investigator)\n\nData:\n${meta}${jsonInstruction}`;
  }

  const systemPrompt = `You are an OSINT analyst specialising in digital identity investigation and social media intelligence. Given a username and the platforms it was found on, analyse the person's digital footprint, assess privacy risks, identify patterns across platforms, and draw inferences about the subject. Be factual, precise, and thorough. Do not use markdown.`;

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
