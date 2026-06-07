"use client";

interface RevlLogoProps {
  size?: number;
  className?: string;
  showText?: boolean;
}

export default function RevlLogo({ size = 64, className = "", showText = false }: RevlLogoProps) {
  const id = `revl-logo-${size}`;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-label="REVL"
    >
      <defs>
        {/* Outer glow filter */}
        <filter id={`${id}-glow`} x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="2.5" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>

        {/* Intense eye glow */}
        <filter id={`${id}-eye-glow`} x="-80%" y="-80%" width="360%" height="360%">
          <feGaussianBlur stdDeviation="2" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>

        {/* Clip to square */}
        <clipPath id={`${id}-clip`}>
          <rect width="64" height="64" />
        </clipPath>

        {/* Eye pulse animation */}
        <style>{`
          @keyframes revl-eye-pulse {
            0%, 100% { opacity: 0.7; }
            50% { opacity: 1; }
          }
          @keyframes revl-scanline {
            0% { transform: translateY(-4px); opacity: 0; }
            10% { opacity: 0.18; }
            90% { opacity: 0.18; }
            100% { transform: translateY(68px); opacity: 0; }
          }
          .revl-eye-pulse {
            animation: revl-eye-pulse 2s ease-in-out infinite;
          }
          .revl-scanline-sweep {
            animation: revl-scanline 4s linear infinite;
          }
        `}</style>
      </defs>

      <g clipPath={`url(#${id}-clip)`}>
        {/* Background */}
        <rect width="64" height="64" fill="#000" />

        {/* ── Matrix rain fragments (background) ──────────────────────── */}
        {/* Column 1 */}
        <text x="2" y="10" fontFamily="monospace" fontSize="5" fill="#003300" opacity="0.9">1</text>
        <text x="2" y="17" fontFamily="monospace" fontSize="5" fill="#00ff41" opacity="0.5">0</text>
        <text x="2" y="24" fontFamily="monospace" fontSize="5" fill="#003300" opacity="0.7">ア</text>
        <text x="2" y="55" fontFamily="monospace" fontSize="5" fill="#003300" opacity="0.5">1</text>
        <text x="2" y="62" fontFamily="monospace" fontSize="5" fill="#00ff41" opacity="0.3">|</text>
        {/* Column 2 */}
        <text x="56" y="8"  fontFamily="monospace" fontSize="5" fill="#00ff41" opacity="0.4">ウ</text>
        <text x="56" y="15" fontFamily="monospace" fontSize="5" fill="#003300" opacity="0.8">1</text>
        <text x="56" y="22" fontFamily="monospace" fontSize="5" fill="#003300" opacity="0.5">0</text>
        <text x="56" y="50" fontFamily="monospace" fontSize="5" fill="#00ff41" opacity="0.3">イ</text>
        <text x="56" y="57" fontFamily="monospace" fontSize="5" fill="#003300" opacity="0.6">1</text>
        <text x="56" y="64" fontFamily="monospace" fontSize="5" fill="#003300" opacity="0.4">0</text>

        {/* ── Skull / demon face ───────────────────────────────────────── */}
        {/* Outer skull shape — angular polygon */}
        <polygon
          points="12,52 10,38 13,22 20,13 32,10 44,13 51,22 54,38 52,52 44,56 32,58 20,56"
          fill="#0a0a0a"
          stroke="#00ff41"
          strokeWidth="0.8"
          opacity="0.95"
          filter={`url(#${id}-glow)`}
        />

        {/* Cheekbone ridges */}
        <polyline points="12,38 16,34 14,42" fill="none" stroke="#00ff41" strokeWidth="0.6" opacity="0.6" />
        <polyline points="52,38 48,34 50,42" fill="none" stroke="#00ff41" strokeWidth="0.6" opacity="0.6" />

        {/* ── Forehead circuit / hex pattern ───────────────────────────── */}
        {/* Hex outline */}
        <polygon
          points="32,12 37,15 37,21 32,24 27,21 27,15"
          fill="none"
          stroke="#003300"
          strokeWidth="0.7"
          opacity="0.9"
        />
        {/* Center dot */}
        <circle cx="32" cy="18" r="1" fill="#003300" opacity="0.9" />
        {/* Circuit traces radiating from hex */}
        <line x1="27" y1="18" x2="22" y2="18" stroke="#003300" strokeWidth="0.5" opacity="0.8" />
        <line x1="22" y1="18" x2="20" y2="15" stroke="#003300" strokeWidth="0.5" opacity="0.8" />
        <line x1="37" y1="18" x2="42" y2="18" stroke="#003300" strokeWidth="0.5" opacity="0.8" />
        <line x1="42" y1="18" x2="44" y2="15" stroke="#003300" strokeWidth="0.5" opacity="0.8" />
        <line x1="32" y1="24" x2="32" y2="27" stroke="#003300" strokeWidth="0.5" opacity="0.8" />
        {/* Corner nodes */}
        <rect x="19" y="13.5" width="2" height="2" fill="#003300" opacity="0.8" />
        <rect x="43" y="13.5" width="2" height="2" fill="#003300" opacity="0.8" />

        {/* ── Left eye socket ──────────────────────────────────────────── */}
        {/* Socket outer (angular diamond) */}
        <polygon
          points="17,32 22,27 27,32 22,37"
          fill="#000"
          stroke="#00ff41"
          strokeWidth="0.9"
        />
        {/* Socket inner shadow */}
        <polygon
          points="18.5,32 22,28.5 25.5,32 22,35.5"
          fill="#001800"
        />
        {/* Glowing eye — small rectangle */}
        <rect
          x="19.5" y="30" width="5" height="4"
          rx="0.3"
          fill="#00ff41"
          className="revl-eye-pulse"
          filter={`url(#${id}-eye-glow)`}
        />
        {/* Eye highlight slit */}
        <line x1="20" y1="32" x2="24" y2="32" stroke="#ffffff" strokeWidth="0.5" opacity="0.8" className="revl-eye-pulse" />

        {/* ── Right eye socket ─────────────────────────────────────────── */}
        {/* Socket outer */}
        <polygon
          points="37,32 42,27 47,32 42,37"
          fill="#000"
          stroke="#00ff41"
          strokeWidth="0.9"
        />
        {/* Socket inner shadow */}
        <polygon
          points="38.5,32 42,28.5 45.5,32 42,35.5"
          fill="#001800"
        />
        {/* Glowing eye */}
        <rect
          x="39.5" y="30" width="5" height="4"
          rx="0.3"
          fill="#00ff41"
          className="revl-eye-pulse"
          filter={`url(#${id}-eye-glow)`}
          style={{ animationDelay: "0.3s" }}
        />
        {/* Eye highlight slit */}
        <line x1="40" y1="32" x2="44" y2="32" stroke="#ffffff" strokeWidth="0.5" opacity="0.8" className="revl-eye-pulse" style={{ animationDelay: "0.3s" }} />

        {/* ── Nose bridge (minimal) ─────────────────────────────────────── */}
        <polyline points="30,37 32,40 34,37" fill="none" stroke="#00ff41" strokeWidth="0.6" opacity="0.5" />

        {/* ── Mouth — angular grimace ───────────────────────────────────── */}
        {/* Grimace baseline */}
        <polyline
          points="20,47 24,44 28,46 32,44 36,46 40,44 44,47"
          fill="none"
          stroke="#00ff41"
          strokeWidth="0.9"
          opacity="0.85"
        />
        {/* Teeth suggestion — short vertical ticks */}
        <line x1="24" y1="44" x2="24" y2="47" stroke="#00ff41" strokeWidth="0.7" opacity="0.5" />
        <line x1="28" y1="44" x2="28" y2="46.5" stroke="#00ff41" strokeWidth="0.7" opacity="0.5" />
        <line x1="32" y1="44" x2="32" y2="47" stroke="#00ff41" strokeWidth="0.7" opacity="0.5" />
        <line x1="36" y1="44" x2="36" y2="46.5" stroke="#00ff41" strokeWidth="0.7" opacity="0.5" />
        <line x1="40" y1="44" x2="40" y2="47" stroke="#00ff41" strokeWidth="0.7" opacity="0.5" />

        {/* ── Scan lines overlay ───────────────────────────────────────── */}
        {[0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30].map(y => (
          <line
            key={y}
            x1="10" y1={12 + y} x2="54" y2={12 + y}
            stroke="#00ff41"
            strokeWidth="0.4"
            opacity="0.04"
          />
        ))}

        {/* Moving scan line sweep */}
        <rect
          x="10" y="10" width="44" height="3"
          fill="#00ff41"
          opacity="0"
          className="revl-scanline-sweep"
        />

        {/* ── Corner bracket decoration ─────────────────────────────────── */}
        {/* Top-left */}
        <polyline points="2,8 2,2 8,2"   fill="none" stroke="#00ff41" strokeWidth="0.8" opacity="0.5" />
        {/* Top-right */}
        <polyline points="56,2 62,2 62,8"  fill="none" stroke="#00ff41" strokeWidth="0.8" opacity="0.5" />
        {/* Bottom-left */}
        <polyline points="2,56 2,62 8,62"  fill="none" stroke="#00ff41" strokeWidth="0.8" opacity="0.5" />
        {/* Bottom-right */}
        <polyline points="62,56 62,62 56,62" fill="none" stroke="#00ff41" strokeWidth="0.8" opacity="0.5" />

        {/* ── "REVL" text label (optional) ─────────────────────────────── */}
        {showText && (
          <text
            x="32" y="76"
            textAnchor="middle"
            fontFamily="'JetBrains Mono', 'Courier New', monospace"
            fontWeight="700"
            fontSize="8"
            letterSpacing="4"
            fill="#00ff41"
          >
            REVL
          </text>
        )}
      </g>
    </svg>
  );
}
