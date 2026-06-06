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
      return `You are a defensive security analyst working for a corporate security operations centre (SOC). Your role is to assess phone numbers for vishing (voice phishing), smishing, fraud campaigns, and social engineering threats targeting organisations. Provide structured, actionable intelligence suitable for security teams. Reference threat actor TTPs where relevant. Recommend defensive controls and escalation paths. Be precise and evidence-based.`;

    case "red":
      return `You are an OSINT intelligence researcher conducting lawful, authorised reconnaissance. Your role is to extract maximum intelligence value from a phone number — carrier data, geographic attribution, likely registration patterns, associated infrastructure, and potential links to known threat actors or fraud operations. Think like a threat intelligence analyst. Surface connections and hypotheses even when evidence is partial, but clearly label confidence levels. This is for authorised security research only.`;
  }
}

export function buildUserPrompt(
  number: string,
  parsed: ParsedNumber,
  mode: Mode,
  depth: Depth
): string {
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

  const jsonInstruction = `\nAt the very end of your response, output the following JSON object on its own line with no surrounding text, code fences, or formatting:\n{"risk":"High|Medium|Low|Unknown","summary":"one sentence risk summary","flags":["finding 1","finding 2","finding 3"]}`;

  if (depth === "quick") {
    return `Analyse this phone number in 3 sentences or fewer. State whether it is likely safe or suspicious, the single biggest risk indicator, and one action the recipient should take.\n\n${meta}${jsonInstruction}`;
  }

  if (depth === "standard") {
    const sections =
      mode === "consumer"
        ? ["Is this number safe?", "Warning signs (if any)", "What should I do?"]
        : mode === "blue"
        ? ["Threat Assessment", "Indicators of Compromise", "Recommended Controls"]
        : ["Attribution", "Intelligence Value", "Associated Patterns"];

    return `Analyse this phone number using the following structured sections: ${sections.join(", ")}. Keep each section concise — 2 to 4 sentences.\n\n${meta}${jsonInstruction}`;
  }

  // deep
  const sections =
    mode === "consumer"
      ? [
          "Overview",
          "Scam Patterns Associated With This Number Type or Region",
          "Red Flags Detected",
          "Safe vs Suspicious Indicators",
          "Recommended Actions",
          "Additional Resources",
        ]
      : mode === "blue"
      ? [
          "Executive Summary",
          "Threat Classification",
          "TTP Analysis (MITRE ATT&CK if applicable)",
          "Indicators of Compromise",
          "Campaign Attribution (if known)",
          "Defensive Recommendations",
          "Escalation Criteria",
        ]
      : [
          "OSINT Summary",
          "Carrier & Infrastructure Analysis",
          "Geographic & Temporal Attribution",
          "Known Threat Actor Associations",
          "Confidence Assessment",
          "Collection Gaps",
          "Recommended Next Steps",
        ];

  return `Produce a full intelligence report on this phone number. Cover each of the following sections in depth:\n\n${sections.map((s, i) => `${i + 1}. ${s}`).join("\n")}\n\nPhone number metadata:\n${meta}${jsonInstruction}`;
}
