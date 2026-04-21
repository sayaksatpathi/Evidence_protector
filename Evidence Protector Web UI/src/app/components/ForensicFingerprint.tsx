import { Check, Copy } from 'lucide-react';
import { useMemo, useState } from 'react';
import { Button } from './ui/button';

interface ForensicFingerprintProps {
  hash: string;
  label?: string;
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function hexToBytes(hex: string): number[] {
  const clean = hex.trim().toLowerCase().replace(/^0x/, '');
  if (clean.length < 2) return [];
  if (!/^[0-9a-f]+$/.test(clean)) return [];

  const bytes: number[] = [];
  const evenLen = clean.length - (clean.length % 2);
  for (let i = 0; i < evenLen; i += 2) {
    const b = Number.parseInt(clean.slice(i, i + 2), 16);
    if (Number.isFinite(b)) bytes.push(b);
  }
  return bytes;
}

function stringToBytesFallback(value: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < value.length; i++) {
    bytes.push(value.charCodeAt(i) & 0xff);
  }
  return bytes;
}

function bytesFromHash(hash: string): number[] {
  const parsed = hexToBytes(hash);
  if (parsed.length) return parsed;
  return stringToBytesFallback(hash);
}

function buildRandomWalkArt(bytes: number[], width: number, height: number) {
  const grid = Array.from({ length: height }, () => Array.from({ length: width }, () => 0));

  let x = Math.floor(width / 2);
  let y = Math.floor(height / 2);
  const start = { x, y };

  for (const byte of bytes) {
    for (let shift = 0; shift < 8; shift += 2) {
      const dir = (byte >> shift) & 0b11;
      if (dir === 0) y -= 1;
      else if (dir === 1) x += 1;
      else if (dir === 2) y += 1;
      else x -= 1;

      x = clamp(x, 0, width - 1);
      y = clamp(y, 0, height - 1);
      grid[y][x] += 1;
    }
  }

  const end = { x, y };
  return { grid, start, end };
}

const ADJECTIVES = [
  'absurd',
  'ancient',
  'ashen',
  'atomic',
  'bitten',
  'blazing',
  'brass',
  'cobalt',
  'cosmic',
  'cryptic',
  'delta',
  'drift',
  'electric',
  'etched',
  'feral',
  'frozen',
  'ghost',
  'glitch',
  'hollow',
  'hyper',
  'infra',
  'ivory',
  'jagged',
  'kinetic',
  'lunar',
  'mossy',
  'neon',
  'nimbus',
  'noisy',
  'obsidian',
  'omega',
  'orbital',
  'paper',
  'plasma',
  'polar',
  'quiet',
  'radial',
  'raven',
  'rusty',
  'signal',
  'silent',
  'solar',
  'spectral',
  'static',
  'storm',
  'sudden',
  'synthetic',
  'tidal',
  'ultra',
  'velvet',
  'vivid',
  'void',
  'wild',
  'winter',
  'wired',
  'withered',
  'xeno',
  'young',
  'zen',
  'zigzag',
  'hushed',
  'arcane',
  'volatile',
];

const NOUNS = [
  'artifact',
  'asteroid',
  'atlas',
  'beacon',
  'circuit',
  'cipher',
  'codex',
  'comet',
  'constellation',
  'crystal',
  'drone',
  'engine',
  'echo',
  'flare',
  'forgery',
  'fractal',
  'garden',
  'glyph',
  'hammer',
  'helix',
  'horizon',
  'labyrinth',
  'lantern',
  'ledger',
  'meteor',
  'mirror',
  'monolith',
  'nebula',
  'needle',
  'node',
  'oracle',
  'orbit',
  'owl',
  'payload',
  'phantom',
  'prism',
  'protocol',
  'quartz',
  'relay',
  'riddle',
  'rift',
  'router',
  'satellite',
  'scan',
  'signal',
  'siren',
  'spectrum',
  'spiral',
  'stencil',
  'talisman',
  'thread',
  'threshold',
  'timeline',
  'token',
  'torch',
  'vault',
  'vector',
  'verdict',
  'witness',
  'wrench',
  'zenith',
  'ziggurat',
  'checksum',
];

function phraseFromBytes(bytes: number[]): string {
  const b0 = bytes[0] ?? 0;
  const b1 = bytes[1] ?? 0;
  const b2 = bytes[2] ?? 0;
  const b3 = bytes[3] ?? 0;

  const a1 = ADJECTIVES[b0 % ADJECTIVES.length];
  const a2 = ADJECTIVES[(b1 + b3) % ADJECTIVES.length];
  const n1 = NOUNS[b2 % NOUNS.length];

  const suffix = (((b0 << 8) | b1) >>> 0).toString(16).padStart(4, '0');
  return `${a1}-${a2}-${n1}-${suffix}`;
}

export function ForensicFingerprint({ hash, label = 'Forensic Fingerprint' }: ForensicFingerprintProps) {
  const [copied, setCopied] = useState(false);

  const { grid, start, end, phrase, maxCount } = useMemo(() => {
    const bytes = bytesFromHash(hash);
    const width = 17;
    const height = 9;
    const { grid, start, end } = buildRandomWalkArt(bytes, width, height);

    let maxCount = 0;
    for (const row of grid) {
      for (const c of row) maxCount = Math.max(maxCount, c);
    }

    return {
      grid,
      start,
      end,
      phrase: phraseFromBytes(bytes),
      maxCount: Math.max(1, maxCount),
    };
  }, [hash]);

  const cell = 10;
  const w = grid[0]?.length ?? 0;
  const h = grid.length;
  const svgW = w * cell;
  const svgH = h * cell;

  const handleCopy = () => {
    navigator.clipboard.writeText(phrase);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-card border border-border rounded p-4">
      <div className="text-xs text-muted-foreground mb-3">{label}</div>

      <div className="flex items-start gap-4">
        <div className="shrink-0 rounded border border-border bg-background p-2">
          <svg
            width={svgW}
            height={svgH}
            viewBox={`0 0 ${svgW} ${svgH}`}
            className="block"
            shapeRendering="crispEdges"
            aria-label="Deterministic hash fingerprint art"
          >
            <rect x={0} y={0} width={svgW} height={svgH} fill="var(--background)" />

            {grid.map((row, y) =>
              row.map((count, x) => {
                const isStart = start.x === x && start.y === y;
                const isEnd = end.x === x && end.y === y;

                if (isEnd) {
                  return (
                    <rect
                      key={`${x}-${y}`}
                      x={x * cell}
                      y={y * cell}
                      width={cell}
                      height={cell}
                      fill="var(--foreground)"
                      opacity={1}
                    />
                  );
                }

                if (isStart) {
                  return (
                    <rect
                      key={`${x}-${y}`}
                      x={x * cell}
                      y={y * cell}
                      width={cell}
                      height={cell}
                      fill="var(--success)"
                      opacity={1}
                    />
                  );
                }

                if (!count) return null;

                const t = Math.sqrt(count / maxCount);
                const opacity = clamp(0.15 + 0.85 * t, 0.15, 1);

                return (
                  <rect
                    key={`${x}-${y}`}
                    x={x * cell}
                    y={y * cell}
                    width={cell}
                    height={cell}
                    fill="var(--primary)"
                    opacity={opacity}
                  />
                );
              }),
            )}
          </svg>
        </div>

        <div className="flex-1 space-y-2">
          <div className="text-sm text-foreground">
            Same hash → same art. Use it to eyeball-match evidence.
          </div>

          <div className="flex items-center justify-between gap-3 bg-background border border-border rounded px-3 py-2">
            <div className="min-w-0">
              <div className="text-xs text-muted-foreground mb-1">Fingerprint Phrase</div>
              <div className="font-mono text-sm text-foreground truncate" title={phrase}>
                {phrase}
              </div>
            </div>

            <Button
              onClick={handleCopy}
              variant="ghost"
              size="icon"
              aria-label="Copy fingerprint phrase"
              title="Copy fingerprint phrase"
            >
              {copied ? <Check className="text-success" /> : <Copy className="text-muted-foreground" />}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
