import {
  parsePhoneNumber as libParse,
  isValidPhoneNumber,
  getNumberType,
  CountryCode,
  NumberType,
} from "libphonenumber-js";

export type Mode = "consumer" | "blue" | "red";
export type Depth = "quick" | "standard" | "deep";
export type RiskLevel = "High" | "Medium" | "Low" | "Unknown";

export interface ParsedNumber {
  raw: string;
  e164: string | null;
  country: CountryCode | null;
  region: string | null;
  type: "toll-free" | "premium-rate" | "mobile" | "landline" | "unknown";
  valid: boolean;
  nationalNumber: string | null;
  internationalFormat: string | null;
}

export interface LookupResult {
  risk: RiskLevel;
  summary: string;
  flags: string[];
  raw: string;
  parsed: ParsedNumber;
  mode: Mode;
  depth: Depth;
}

export interface IpLookupResult {
  ip: string;
  country: string | null;
  countryCode: string | null;
  city: string | null;
  region: string | null;
  isp: string | null;
  org: string | null;
  asn: string | null;
  lat: number | null;
  lon: number | null;
  timezone: string | null;
  is_proxy: boolean;
  is_vpn: boolean;
  is_hosting: boolean;
  is_tor: boolean;
  threat_score: number | null; // 0–100 (from GetIPIntel × 100)
  risk: RiskLevel;
  summary: string;
  flags: string[];
  raw: string; // raw AI text
  depth: Depth;
}

const SUPPORTED_COUNTRIES: CountryCode[] = ["US", "GB", "AU", "DE", "IN", "BR"];

function mapNumberType(type: NumberType | undefined): ParsedNumber["type"] {
  switch (type) {
    case "TOLL_FREE":
      return "toll-free";
    case "PREMIUM_RATE":
      return "premium-rate";
    case "MOBILE":
    case "FIXED_LINE_OR_MOBILE":
      return "mobile";
    case "FIXED_LINE":
      return "landline";
    default:
      return "unknown";
  }
}

// Country name map for human-readable region labels
const COUNTRY_NAMES: Partial<Record<CountryCode, string>> = {
  US: "United States",
  GB: "United Kingdom",
  AU: "Australia",
  DE: "Germany",
  IN: "India",
  BR: "Brazil",
};

export function parsePhoneNumber(raw: string): ParsedNumber {
  const trimmed = raw.trim();

  // Try each supported country as a fallback default if no + prefix
  const countriestoTry: CountryCode[] = trimmed.startsWith("+")
    ? SUPPORTED_COUNTRIES
    : ["US", ...SUPPORTED_COUNTRIES];

  for (const country of countriestoTry) {
    try {
      const parsed = libParse(trimmed, country);
      const parsedCountry = parsed.country as CountryCode | undefined;

      if (!parsedCountry || !SUPPORTED_COUNTRIES.includes(parsedCountry)) {
        continue;
      }

      const valid = isValidPhoneNumber(trimmed, country);
      const numberType = getNumberType(trimmed, country);

      return {
        raw: trimmed,
        e164: parsed.format("E.164"),
        country: parsedCountry,
        region: COUNTRY_NAMES[parsedCountry] ?? parsedCountry,
        type: mapNumberType(numberType),
        valid,
        nationalNumber: parsed.nationalNumber ?? null,
        internationalFormat: parsed.formatInternational(),
      };
    } catch {
      continue;
    }
  }

  return {
    raw: trimmed,
    e164: null,
    country: null,
    region: null,
    type: "unknown",
    valid: false,
    nationalNumber: null,
    internationalFormat: null,
  };
}

export function getSystemPrompt(mode: Mode): string {
  switch (mode) {
    case "consumer":
      return `You are a friendly, plain-language scam detection assistant helping everyday people identify whether a phone number that contacted them is safe or suspicious. Explain findings in simple terms anyone can understand — avoid jargon. Be reassuring but honest. Focus on practical advice the person can act on. Never alarm unnecessarily, but always flag genuine red flags clearly.`;

    case "blue":
      return `You are a phone number investigation analyst. Your role is to perform a thorough lookup and analysis of any phone number — identifying the carrier, line type, geographic origin, registration patterns, likely use case (personal, business, virtual, etc.), and any associated risk signals. Provide clear, structured intelligence: who likely owns this number, what type of line it is, where it originates, and whether anything about it is unusual or notable. Be factual, detailed, and methodical.`;

    case "red":
      return `You are an IP address OSINT and intelligence analyst. Given an IP address, your role is to determine everything possible about it: geolocation (country, city, region), ISP and organisation, ASN, whether it is a VPN, Tor exit node, proxy, or datacenter/hosting IP, any known threat actor associations, abuse reports, or blacklist status, and an overall risk assessment. Think like a network intelligence researcher. Be thorough, technical, and label confidence levels clearly. This is for authorised security research only.`;
  }
}

export function buildUserPrompt(
  number: string,
  parsed: ParsedNumber,
  mode: Mode,
  depth: Depth
): string {
  const jsonInstruction = `\nAt the very end of your response, output the following JSON object on its own line with no surrounding text, code fences, or formatting:\n{"risk":"High|Medium|Low|Unknown","summary":"one sentence risk summary","flags":["finding 1","finding 2","finding 3"]}`;

  // ── IP mode ─────────────────────────────────────────────────────────────────
  if (mode === "red") {
    const ipMeta = `IP Address: ${number}`;

    if (depth === "quick") {
      return `Analyse this IP address in 3 sentences or fewer. State the likely origin and owner, whether it shows any anonymisation or hosting signals, and the overall risk level.\n\n${ipMeta}${jsonInstruction}`;
    }

    if (depth === "standard") {
      const sections = ["Geolocation & Owner", "Anonymisation Signals (VPN/Tor/Proxy/Hosting)", "Risk Assessment"];
      return `Analyse this IP address using the following structured sections: ${sections.join(", ")}. Keep each section concise — 2 to 4 sentences.\n\n${ipMeta}${jsonInstruction}`;
    }

    // deep
    const ipSections = [
      "Geolocation (Country, Region, City)",
      "ISP, Organisation & ASN",
      "Anonymisation Detection (VPN / Tor / Proxy / Datacenter)",
      "Threat Intelligence & Blacklist Status",
      "Known Associations or Abuse Reports",
      "Confidence Assessment",
      "Recommended Next Steps",
    ];
    return `Produce a full IP intelligence report. Cover each of the following sections in depth:\n\n${ipSections.map((s, i) => `${i + 1}. ${s}`).join("\n")}\n\nTarget:\n${ipMeta}${jsonInstruction}`;
  }

  // ── Phone modes (consumer + blue) ───────────────────────────────────────────
  const meta = [
    `Number: ${number}`,
    parsed.e164 ? `E.164: ${parsed.e164}` : null,
    parsed.internationalFormat ? `Formatted: ${parsed.internationalFormat}` : null,
    parsed.country ? `Country: ${parsed.region} (${parsed.country})` : "Country: Unknown",
    `Type: ${parsed.type}`,
    `Valid: ${parsed.valid ? "Yes" : "No"}`,
  ]
    .filter(Boolean)
    .join("\n");

  if (depth === "quick") {
    const task = mode === "consumer"
      ? "State whether it is likely safe or suspicious, the single biggest risk indicator, and one action the recipient should take."
      : "Identify the carrier and line type, the likely geographic origin, and any notable characteristics of this number.";
    return `Analyse this phone number in 3 sentences or fewer. ${task}\n\n${meta}${jsonInstruction}`;
  }

  if (depth === "standard") {
    const sections = mode === "consumer"
      ? ["Is this number safe?", "Warning signs (if any)", "What should I do?"]
      : ["Number Identity (carrier, line type, origin)", "Notable Characteristics", "Risk or Trust Assessment"];
    return `Analyse this phone number using the following structured sections: ${sections.join(", ")}. Keep each section concise — 2 to 4 sentences.\n\n${meta}${jsonInstruction}`;
  }

  // deep
  const sections = mode === "consumer"
    ? [
        "Overview",
        "Scam Patterns Associated With This Number Type or Region",
        "Red Flags Detected",
        "Safe vs Suspicious Indicators",
        "Recommended Actions",
        "Additional Resources",
      ]
    : [
        "Number Identity (carrier, operator, line type)",
        "Geographic Origin & Registration Patterns",
        "Likely Use Case (personal, business, virtual, etc.)",
        "Risk Signals & Unusual Characteristics",
        "Confidence Assessment",
        "Recommended Next Steps",
      ];

  return `Produce a full intelligence report on this phone number. Cover each of the following sections in depth:\n\n${sections.map((s, i) => `${i + 1}. ${s}`).join("\n")}\n\nPhone number metadata:\n${meta}${jsonInstruction}`;
}
