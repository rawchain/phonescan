import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "PhoneScan",
    short_name: "PhoneScan",
    description: "AI-powered phone, email & IP intelligence — identify scams, fraud, and unknown callers.",
    start_url: "/",
    display: "standalone",
    background_color: "#0a0c0f",
    theme_color: "#00ff41",
    icons: [
      { src: "/favicon.ico", sizes: "any", type: "image/x-icon" },
    ],
  };
}
