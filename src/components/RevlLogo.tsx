"use client";

interface RevlLogoProps {
  size?: number;
  className?: string;
}

/**
 * REVL demon mark — tribal oni/devil face, outline-only line art.
 * Hero element: two bold crescent horns. Wide shield face, pointed chin,
 * sharp ear spikes, narrow slanted eyes, long nose, wide jagged grin.
 * Rendered with red/blue chromatic-aberration glitch layers + green eyes.
 */
export default function RevlLogo({ size = 200, className = "" }: RevlLogoProps) {
  const id = `rl${size}`;

  // All paths in a 200×200 user-space.
  const bodyPaths: Array<{ d: string; sw: number }> = [

    // ── Face / skull silhouette (shield shape, pointed chin) ─────────────
    {
      d: `M 84,56
          C 92,50 108,50 116,56
          C 136,60 150,73 159,89
          L 184,95
          L 161,106
          C 167,128 155,151 133,167
          C 121,177 110,183 100,185
          C 90,183 79,177 67,167
          C 45,151 33,128 39,106
          L 16,95
          L 39,89
          C 48,73 64,60 84,56
          Z`,
      sw: 2.2,
    },

    // ── Left horn — bold thick crescent sweeping up & out to a sharp tip ─
    {
      d: `M 60,64
          C 46,52 36,34 36,14
          C 44,32 62,46 84,56
          Z`,
      sw: 2.4,
    },

    // ── Right horn (mirror) ───────────────────────────────────────────────
    {
      d: `M 140,64
          C 154,52 164,34 164,14
          C 156,32 138,46 116,56
          Z`,
      sw: 2.4,
    },

    // ── Horn inner ridge lines (depth) ───────────────────────────────────
    { d: `M 64,60 C 50,48 42,32 40,16`, sw: 1.1 },
    { d: `M 136,60 C 150,48 158,32 160,16`, sw: 1.1 },

    // ── Heavy brow ridges — steep angry V toward the nose ────────────────
    { d: `M 44,100 L 95,115`, sw: 2.4 },
    { d: `M 156,100 L 105,115`, sw: 2.4 },

    // ── Forehead furrow between the brows ────────────────────────────────
    { d: `M 97,101 L 100,113 L 103,101`, sw: 1.0 },

    // ── Long nose bridge → nostril shelf + curls ─────────────────────────
    { d: `M 96,113 L 89,150`, sw: 1.4 },
    { d: `M 104,113 L 111,150`, sw: 1.4 },
    { d: `M 89,150 C 94,158 106,158 111,150`, sw: 1.4 },
    { d: `M 89,150 C 83,153 84,159 90,158`, sw: 1.1 },
    { d: `M 111,150 C 117,153 116,159 110,158`, sw: 1.1 },

    // ── Angular cheekbone slashes ────────────────────────────────────────
    { d: `M 41,106 L 60,150`, sw: 1.2 },
    { d: `M 159,106 L 140,150`, sw: 1.2 },

    // ── Sinister smile creases (corners curl up toward cheeks) ───────────
    { d: `M 52,152 C 58,142 64,138 73,137`, sw: 1.3 },
    { d: `M 148,152 C 142,142 136,138 127,137`, sw: 1.3 },

    // ── Wide grin — upper lip + lower jaw arcs ────────────────────────────
    { d: `M 52,152 C 74,160 126,160 148,152`, sw: 2.0 },
    { d: `M 52,152 C 74,181 126,181 148,152`, sw: 2.0 },

    // ── Sharp interlocking teeth ──────────────────────────────────────────
    {
      d: `M 58,156 L 66,170 L 74,156 L 82,170 L 90,156
          L 98,170 L 106,156 L 114,170 L 122,156
          L 130,170 L 138,156 L 144,166`,
      sw: 1.4,
    },

    // ── Chin crease ───────────────────────────────────────────────────────
    { d: `M 86,176 L 100,184 L 114,176`, sw: 1.1 },
  ];

  // Eyes — rendered separately in matrix green with a stronger glow + pulse.
  const eyePaths: Array<{ d: string; sw: number }> = [
    // Left — narrow angular almond, slanted toward the nose (menacing)
    { d: `M 40,117 L 64,110 L 88,118 L 64,122 Z`, sw: 2.0 },
    // Right (mirror)
    { d: `M 160,117 L 136,110 L 112,118 L 136,122 Z`, sw: 2.0 },
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
        {/* Subtle green glow around the main strokes */}
        <filter id={`${id}-g`} x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="1.8" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>

        {/* Stronger glow for the eyes */}
        <filter id={`${id}-eg`} x="-70%" y="-70%" width="240%" height="240%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="3.5" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>

        <style>{`
          @keyframes ${id}R {
            0%,90%,100% { transform:translate(-3px,0);    opacity:.4;  }
            91%          { transform:translate(-7px, 2px); opacity:.7;  }
            92%          { transform:translate(-1px,-2px); opacity:.15; }
            93%          { transform:translate(-5px, 1px); opacity:.55; }
            94%,95%,96%,97%,98%,99% { transform:translate(-3px,0); opacity:.4; }
          }
          @keyframes ${id}B {
            0%,90%,100% { transform:translate(3px,0);    opacity:.4;  }
            91%          { transform:translate(7px,-2px); opacity:.7;  }
            92%          { transform:translate(1px, 2px); opacity:.15; }
            93%          { transform:translate(5px,-1px); opacity:.55; }
            94%,95%,96%,97%,98%,99% { transform:translate(3px,0); opacity:.4; }
          }
          @keyframes ${id}E {
            0%,100% { opacity:.75; }
            50%      { opacity:1;   }
          }
          .${id}R { animation:${id}R 4s linear infinite; transform:translate(-3px,0); }
          .${id}B { animation:${id}B 4s linear infinite; transform:translate(3px,0);  }
          .${id}E { animation:${id}E 2s ease-in-out infinite; }
        `}</style>
      </defs>

      {/* Pure black background */}
      <rect width="200" height="200" fill="#000" />

      {/* Red chromatic-aberration layer */}
      <g stroke="#ff0000" fill="none" className={`${id}R`} strokeLinecap="round" strokeLinejoin="round">
        {allPaths.map((p, i) => <path key={i} d={p.d} strokeWidth={p.sw} />)}
      </g>

      {/* Blue chromatic-aberration layer */}
      <g stroke="#0000ff" fill="none" className={`${id}B`} strokeLinecap="round" strokeLinejoin="round">
        {allPaths.map((p, i) => <path key={i} d={p.d} strokeWidth={p.sw} />)}
      </g>

      {/* Main near-white / green-tinted stroke layer */}
      <g stroke="#edfff0" fill="none" filter={`url(#${id}-g)`} strokeLinecap="round" strokeLinejoin="round">
        {bodyPaths.map((p, i) => <path key={i} d={p.d} strokeWidth={p.sw} />)}
      </g>

      {/* Eyes — matrix green, strong glow, slow pulse */}
      <g stroke="#00ff41" fill="none" filter={`url(#${id}-eg)`} className={`${id}E`} strokeLinecap="round" strokeLinejoin="round">
        {eyePaths.map((p, i) => <path key={i} d={p.d} strokeWidth={p.sw} />)}
      </g>
    </svg>
  );
}
