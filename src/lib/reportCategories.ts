export const REPORT_CATEGORIES = [
  "Scam Call",
  "Robocall",
  "Telemarketer",
  "Harassment",
  "Fraud",
  "Silent Call",
  "Other",
] as const;

export type ReportCategory = typeof REPORT_CATEGORIES[number];
