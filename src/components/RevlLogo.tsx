"use client";

interface RevlLogoProps {
  size?: number;
  className?: string;
}

export default function RevlLogo({ size = 200, className = "" }: RevlLogoProps) {
  // Use a stable ID derived from size so multiple instances don't clash
  const id = `rl${size}`;

  // ─── Path definitions ────────────────────────────────────────────────────
  // All coordinates are in a 200×200 user-space.
  // Face spans ~x:12–188, y:5–193.  No fills — pure stroke line art.

  const bodyPaths: Array<{ d: string; sw: number }> = [
    // ── Face / skull outline ────────────────────────────────────────────────
    // Angular polygon: from left-horn base, down to left ear spike, around jaw,
    // across chin, back up to right ear spike, up to right horn base, across top.
    {
      d: `M 72,40
          C 52,52 36,72 28,98
          L 12,104
          L 28,112
          C 30,136 40,160 56,175
          L 78,188
          L 100,193
          L 122,188
          L 144,175
          C 160,160 170,136 172,112
          L 188,104
          L 172,98
          C 164,72 148,52 128,40
          L 100,30
          Z`,
      sw: 1.5,
    },

    // ── Left horn ──────────────────────────────────────────────────────────
    // Tapered: wide at base (y≈42), narrows to tip at (15,5).
    // Two curves define the horn silhouette.
    {
      d: `M 74,42
          C 62,26 40,12 15,5
          C 24,18 50,30 72,46
          Z`,
      sw: 1.5,
    },

    // ── Right horn (mirror of left) ────────────────────────────────────────
    {
      d: `M 126,42
          C 138,26 160,12 185,5
          C 176,18 150,30 128,46
          Z`,
      sw: 1.5,
    },

    // ── Left brow — heavy, slopes sharply DOWN toward nose (angry V) ───────
    {
      d: `M 44,76 L 90,67`,
      sw: 2.0,
    },

    // ── Right brow ─────────────────────────────────────────────────────────
    {
      d: `M 156,76 L 110,67`,
      sw: 2.0,
    },

    // ── Nose bridge — minimal angular inverted-V ───────────────────────────
    {
      d: `M 96,106 L 100,120 L 104,106`,
      sw: 1.2,
    },

    // ── Upper lip curve ────────────────────────────────────────────────────
    {
      d: `M 46,155 C 72,144 128,144 154,155`,
      sw: 1.5,
    },

    // ── Lower lip / jaw curve ──────────────────────────────────────────────
    {
      d: `M 46,155 C 72,184 128,184 154,155`,
      sw: 1.5,
    },

    // ── Teeth — sharp triangular zigzag within the grin ───────────────────
    // Peaks ride just below the upper lip; points aim downward into the mouth.
    {
      d: `M 64,151
          L 70,169 L 76,151
          L 82,169 L 88,151
          L 94,169 L 100,151
          L 106,169 L 112,151
          L 118,169 L 124,151
          L 130,169 L 136,151`,
      sw: 1.2,
    },

    // ── Left cheekbone crease ──────────────────────────────────────────────
    {
      d: `M 34,115 L 56,142`,
      sw: 1.0,
    },

    // ── Right cheekbone crease ─────────────────────────────────────────────
    {
      d: `M 166,115 L 144,142`,
      sw: 1.0,
    },

    // ── Forehead centre crease — angry V between brows ────────────────────
    {
      d: `M 95,52 L 100,64 L 105,52`,
      sw: 1.0,
    },

    // ── Chin point detail ─────────────────────────────────────────────────
    {
      d: `M 85,183 L 100,192 L 115,183`,
      sw: 1.0,
    },
  ];

  // Eye sockets — separate so they can be coloured #00ff41 and pulse
  const eyePaths: Array<{ d: string; sw: number }> = [
    // Left eye — angular almond, outer corner lower-left, inner corner upper-right
    // This strong upward slant toward the nose reads as menacing / snarling.
    {
      d: `M 46,92
          L 60,82
          L 90,79
          L 88,88
          L 58,91
          Z`,
      sw: 1.6,
    },
    // Right eye (mirror: x → 200-x)
    {
      d: `M 154,92
          L 140,82
          L 110,79
          L 112,88
          L 142,91
          Z`,
      sw: 1.6,
    },
  ];

  const allPaths = [...bodyPaths, ...eyePaths];

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 200 200"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-label="REVL"
    >
      <defs>
        {/* Soft green outer glow on main stroke layer */}
        <filter id={`${id}-g`} x="-25%" y="-25%" width="150%" height="150%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="1.5" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>

        {/* Stronger glow for the eyes */}
        <filter id={`${id}-eg`} x="-60%" y="-60%" width="220%" height="220%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>

        <style>{`
          /* ── Chromatic aberration glitch ── */
          @keyframes ${id}R {
            0%,91%,100% { transform:translate(-2px,0);   opacity:.4;  }
            92%          { transform:translate(-6px,1px); opacity:.65; }
            93%          { transform:translate(0,-1px);   opacity:.18; }
            94%          { transform:translate(-4px,0);   opacity:.5;  }
            95%,96%,97%,98%,99% { transform:translate(-2px,0); opacity:.4; }
          }
          @keyframes ${id}B {
            0%,91%,100% { transform:translate(2px,0);    opacity:.4;  }
            92%          { transform:translate(6px,-1px); opacity:.65; }
            93%          { transform:translate(0,1px);    opacity:.18; }
            94%          { transform:translate(4px,0);    opacity:.5;  }
            95%,96%,97%,98%,99% { transform:translate(2px,0); opacity:.4; }
          }
          /* ── Eye idle pulse ── */
          @keyframes ${id}E {
            0%,100% { opacity:.78; }
            50%      { opacity:1;   }
          }
          .${id}R { animation:${id}R 4s linear infinite; transform:translate(-2px,0); }
          .${id}B { animation:${id}B 4s linear infinite; transform:translate(2px,0);  }
          .${id}E { animation:${id}E 2s ease-in-out infinite; }
        `}</style>
      </defs>

      {/* Pure black background */}
      <rect width="200" height="200" fill="#000" />

      {/* ── Red chromatic aberration layer ──────────────────────────────── */}
      <g stroke="#ff0000" fill="none" className={`${id}R`}>
        {allPaths.map((p, i) => (
          <path key={i} d={p.d} strokeWidth={p.sw} strokeLinejoin="round" strokeLinecap="round" />
        ))}
      </g>

      {/* ── Blue chromatic aberration layer ─────────────────────────────── */}
      <g stroke="#0000ff" fill="none" className={`${id}B`}>
        {allPaths.map((p, i) => (
          <path key={i} d={p.d} strokeWidth={p.sw} strokeLinejoin="round" strokeLinecap="round" />
        ))}
      </g>

      {/* ── Main white/green body layer ──────────────────────────────────── */}
      <g stroke="#e0ffe8" fill="none" filter={`url(#${id}-g)`}>
        {bodyPaths.map((p, i) => (
          <path key={i} d={p.d} strokeWidth={p.sw} strokeLinejoin="round" strokeLinecap="round" />
        ))}
      </g>

      {/* ── Eyes — matrix green, stronger glow, pulse animation ─────────── */}
      <g
        stroke="#00ff41"
        fill="none"
        filter={`url(#${id}-eg)`}
        className={`${id}E`}
      >
        {eyePaths.map((p, i) => (
          <path key={i} d={p.d} strokeWidth={p.sw} strokeLinejoin="round" strokeLinecap="round" />
        ))}
      </g>
    </svg>
  );
}
