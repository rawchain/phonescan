import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhoneScan — Free Phone Intelligence",
  description: "Identify scams, fraud, and unknown callers with AI-powered phone number analysis.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
