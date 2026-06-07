import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "REVL",
    short_name: "REVL",
    description: "Free OSINT suite — phone, IP, email, username and URL intelligence powered by AI.",
    start_url: "/",
    display: "standalone",
    background_color: "#0a0c0f",
    theme_color: "#00ff41",
    icons: [
      { src: "/favicon.ico", sizes: "any", type: "image/x-icon" },
    ],
  };
}
