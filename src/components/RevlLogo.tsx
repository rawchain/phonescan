"use client";

interface RevlLogoProps {
  size?: number;
  className?: string;
}

export default function RevlLogo({ size = 200, className = "" }: RevlLogoProps) {
  const id = `rl${size}`;

  // ─────────────────────────────────────────────────────────────────────────
  // All paths in 200×200 user-space.
  // Design: wide oni/demon face — prominent curved horns, massive cheekbones,
  // narrow slanted eyes, long nose bridge → nostrils, wide sinister grin.
  // Chromatic aberration: red layer at −3px, blue at +3px, both 0.4 opacity.
  // Main layer: #eeffee with feGaussianBlur glow. Eyes: #00ff41, stronger glow.
  // ─────────────────────────────────────────────────────────────────────────

  const bodyPaths: Array<{ d: string; sw: number }> = [

    // ── Face / skull silhouette ──────────────────────────────────────────
    // Starts at left horn base, sweeps down to wide cheekbones with small
    // ear spikes, narrows to angular jaw, comes back up mirrored, closes
    // across narrow forehead.
    {
      d: `M 65,36
          C 50,46 36,60 25,78
          L 10,88
          L 25,98
          C 22,118 30,142 50,160
          L 76,174 L 100,179 L 124,174 L 150,160
          C 170,142 178,118 175,98
          L 190,88
          L 175,78
          C 164,60 150,46 135,36
          C 120,26 80,26 65,36
          Z`,
      sw: 2.0,
    },

    // ── Left horn — curved crescent blade ────────────────────────────────
    // Outer edge sweeps up-left to sharp tip; inner edge returns along a
    // tighter curve. Base shares the face outline start point (65,36).
    {
      d: `M 65,36
          C 55,20 40,8 24,4
          C 30,14 50,26 68,42
          Z`,
      sw: 2.0,
    },

    // ── Right horn (mirror) ───────────────────────────────────────────────
    {
      d: `M 135,36
          C 145,20 160,8 176,4
          C 170,14 150,26 132,42
          Z`,
      sw: 2.0,
    },

    // ── Left horn inner-face detail line ─────────────────────────────────
    // Traces the concave inner face of the horn, implying thickness/depth.
    { d: `M 70,42 C 62,28 48,16 32,10`, sw: 1.1 },

    // ── Right horn inner-face detail line ────────────────────────────────
    { d: `M 130,42 C 138,28 152,16 168,10`, sw: 1.1 },

    // ── Left brow ridge — heavy, slopes DOWN sharply toward nose bridge ──
    // Inner corner is lower (angry V-shape with right brow).
    { d: `M 26,90 L 92,103`, sw: 2.2 },

    // ── Right brow ridge ─────────────────────────────────────────────────
    { d: `M 174,90 L 108,103`, sw: 2.2 },

    // ── Left inner brow accent (short downward flick near nose) ──────────
    { d: `M 84,101 L 90,110`, sw: 1.1 },

    // ── Right inner brow accent ───────────────────────────────────────────
    { d: `M 116,101 L 110,110`, sw: 1.1 },

    // ── Nose bridge — two diverging lines running from between brows
    //    all the way down to the nostril shelf ─────────────────────────────
    { d: `M 96,102 L 90,140`, sw: 1.3 },
    { d: `M 104,102 L 110,140`, sw: 1.3 },

    // ── Nostrils — curved shelf connecting bridge bases ───────────────────
    { d: `M 90,140 C 94,148 106,148 110,140`, sw: 1.3 },

    // ── Upper lip — wide arc, peaks at centre ────────────────────────────
    { d: `M 38,152 C 68,141 132,141 162,152`, sw: 1.8 },

    // ── Lower lip / jaw — deep swooping arc ──────────────────────────────
    { d: `M 38,152 C 68,175 132,175 162,152`, sw: 1.8 },

    // ── Teeth — sharp triangular zigzag (7 teeth) ────────────────────────
    // Peaks ride just below upper lip; tips plunge toward lower lip.
    {
      d: `M 56,150
          L 64,167 L 72,150
          L 80,167 L 88,150
          L 96,167 L 104,150
          L 112,167 L 120,150
          L 128,167 L 136,150
          L 144,167 L 150,155`,
      sw: 1.3,
    },

    // ── Left cheekbone structure line ────────────────────────────────────
    // Diagonal slash from below ear spike, through broad cheek, to jaw.
    { d: `M 26,100 L 46,144`, sw: 1.1 },

    // ── Right cheekbone structure line ───────────────────────────────────
    { d: `M 174,100 L 154,144`, sw: 1.1 },

    // ── Chin angular detail ───────────────────────────────────────────────
    { d: `M 78,167 L 90,174 L 100,177 L 110,174 L 122,167`, sw: 1.1 },

    // ── Upper face centre crease (between brows, forehead) ───────────────
    { d: `M 97,58 L 100,70 L 103,58`, sw: 1.0 },
  ];

  const eyePaths: Array<{ d: string; sw: number }> = [
    // ── Left eye — narrow angular almond slit ────────────────────────────
    // Outer corner (left) sits LOWER; inner corner (right, near nose) is
    // HIGHER. This strong upward slant toward the nose reads as menacing.
    { d: `M 30,113 L 52,105 L 90,103 L 88,113 L 52,119 Z`, sw: 1.8 },

    // ── Right eye (mirror) ────────────────────────────────────────────────
    { d: `M 170,113 L 148,105 L 110,103 L 112,113 L 148,119 Z`, sw: 1.8 },
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
        {/* Subtle green glow around main strokes */}
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
          /* Glitch burst every 4 seconds — red layer */
          @keyframes ${id}R {
            0%,90%,100% { transform:translate(-3px,0);    opacity:.4;  }
            91%          { transform:translate(-7px, 2px); opacity:.7;  }
            92%          { transform:translate(-1px,-2px); opacity:.15; }
            93%          { transform:translate(-5px, 1px); opacity:.55; }
            94%,95%,96%,97%,98%,99% { transform:translate(-3px,0); opacity:.4; }
          }
          /* Glitch burst — blue layer (opposite phase) */
          @keyframes ${id}B {
            0%,90%,100% { transform:translate(3px,0);    opacity:.4;  }
            91%          { transform:translate(7px,-2px); opacity:.7;  }
            92%          { transform:translate(1px, 2px); opacity:.15; }
            93%          { transform:translate(5px,-1px); opacity:.55; }
            94%,95%,96%,97%,98%,99% { transform:translate(3px,0); opacity:.4; }
          }
          /* Eye idle pulse — 0.75 → 1.0 opacity */
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

      {/* ── Red chromatic aberration layer ──────────────────────────────── */}
      <g
        stroke="#ff0000"
        fill="none"
        className={`${id}R`}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        {allPaths.map((p, i) => (
          <path key={i} d={p.d} strokeWidth={p.sw} />
        ))}
      </g>

      {/* ── Blue chromatic aberration layer ─────────────────────────────── */}
      <g
        stroke="#0000ff"
        fill="none"
        className={`${id}B`}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        {allPaths.map((p, i) => (
          <path key={i} d={p.d} strokeWidth={p.sw} />
        ))}
      </g>

      {/* ── Main near-white / green-tinted stroke layer ──────────────────── */}
      <g
        stroke="#edfff0"
        fill="none"
        filter={`url(#${id}-g)`}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        {bodyPaths.map((p, i) => (
          <path key={i} d={p.d} strokeWidth={p.sw} />
        ))}
      </g>

      {/* ── Eyes — matrix green, strong glow, slow pulse ─────────────────── */}
      <g
        stroke="#00ff41"
        fill="none"
        filter={`url(#${id}-eg)`}
        className={`${id}E`}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        {eyePaths.map((p, i) => (
          <path key={i} d={p.d} strokeWidth={p.sw} />
        ))}
      </g>
    </svg>
  );
}
