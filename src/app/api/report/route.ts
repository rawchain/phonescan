import { NextRequest, NextResponse } from "next/server";
import { createHash } from "crypto";
import { REPORT_CATEGORIES, type ReportCategory } from "@/lib/reportCategories";

interface CommunityReport {
  number: string;
  category: string;
  comment: string;
  timestamp: string;
  ip_hash: string;
}

interface BinData {
  reports: CommunityReport[];
}

// ---------------------------------------------------------------------------
// Rate limiter — 3 submissions per IP per hour
// ---------------------------------------------------------------------------

const reportRateMap = new Map<string, { count: number; resetAt: number }>();

function checkReportRate(ip: string): boolean {
  const now = Date.now();
  const WINDOW = 60 * 60 * 1000;
  const entry = reportRateMap.get(ip);
  if (!entry || now >= entry.resetAt) {
    reportRateMap.set(ip, { count: 1, resetAt: now + WINDOW });
    return true;
  }
  if (entry.count >= 3) return false;
  entry.count++;
  return true;
}

// ---------------------------------------------------------------------------
// JSONBin helpers
// ---------------------------------------------------------------------------

const BIN_ID  = process.env.JSONBIN_BIN_ID;
const API_KEY = process.env.JSONBIN_API_KEY;

async function readBin(): Promise<BinData> {
  if (!BIN_ID || !API_KEY) return { reports: [] };
  try {
    const res = await fetch(`https://api.jsonbin.io/v3/b/${BIN_ID}/latest`, {
      headers: { "X-Master-Key": API_KEY },
      cache: "no-store",
    });
    if (!res.ok) return { reports: [] };
    const json = await res.json() as { record?: BinData };
    return json.record ?? { reports: [] };
  } catch {
    return { reports: [] };
  }
}

async function writeBin(data: BinData): Promise<boolean> {
  if (!BIN_ID || !API_KEY) return false;
  try {
    const res = await fetch(`https://api.jsonbin.io/v3/b/${BIN_ID}`, {
      method: "PUT",
      headers: {
        "X-Master-Key": API_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getIp(req: NextRequest): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0].trim()
    ?? req.headers.get("x-real-ip")
    ?? "unknown";
}

// ---------------------------------------------------------------------------
// GET /api/report?number=+18005550100
// ---------------------------------------------------------------------------

export async function GET(req: NextRequest) {
  const number = req.nextUrl.searchParams.get("number");
  if (!number) return NextResponse.json({ error: "number is required" }, { status: 400 });

  const bin = await readBin();
  const matching = bin.reports.filter(r => r.number === number);

  // Tally categories
  const tally = new Map<string, number>();
  for (const r of matching) {
    tally.set(r.category, (tally.get(r.category) ?? 0) + 1);
  }
  const categories = Array.from(tally.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));

  const latest = matching.length > 0
    ? matching.reduce((a, b) => a.timestamp > b.timestamp ? a : b).timestamp
    : null;

  return NextResponse.json({ count: matching.length, categories, latest });
}

// ---------------------------------------------------------------------------
// POST /api/report  { number, category, comment }
// ---------------------------------------------------------------------------

export async function POST(req: NextRequest) {
  const ip = getIp(req);

  if (!checkReportRate(ip)) {
    return NextResponse.json(
      { error: "Too many reports from your IP. Please try again in an hour." },
      { status: 429 }
    );
  }

  let body: unknown;
  try { body = await req.json(); }
  catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }

  const { number, category, comment } = body as Record<string, unknown>;

  if (!number || typeof number !== "string" || !number.trim())
    return NextResponse.json({ error: "number is required." }, { status: 400 });

  if (!category || !REPORT_CATEGORIES.includes(category as ReportCategory))
    return NextResponse.json(
      { error: `category must be one of: ${REPORT_CATEGORIES.join(", ")}` },
      { status: 400 }
    );

  const commentStr = typeof comment === "string" ? comment.trim().slice(0, 200) : "";

  // Hash the IP — never store raw IPs
  const ip_hash = createHash("sha256").update(ip + "phonescan_salt").digest("hex");

  const bin = await readBin();
  bin.reports.push({
    number: number.trim(),
    category: String(category),
    comment: commentStr,
    timestamp: new Date().toISOString(),
    ip_hash,
  });

  const ok = await writeBin(bin);
  if (!ok && (BIN_ID && API_KEY)) {
    return NextResponse.json({ error: "Failed to save report. Try again." }, { status: 500 });
  }

  const totalForNumber = bin.reports.filter(r => r.number === number.trim()).length;
  return NextResponse.json({ success: true, total_reports: totalForNumber });
}
