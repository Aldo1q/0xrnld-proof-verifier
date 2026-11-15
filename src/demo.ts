// Demo data: a real Groth16 proof generated with the official Agent Games
// Proof Gatekeeper circuit (vkHash 0x6b79c6…d77b0), plus a tampered copy.
// Generated locally by scripts/gen-demo.js — never hand-written.
import * as fs from "node:fs";
import * as path from "node:path";

export interface DemoExample {
  proof: unknown;
  verificationKey: unknown;
  publicSignals: string[];
}

export interface DemoData {
  description: string;
  circuit: string;
  vkHash: string;
  valid: DemoExample;
  tampered: DemoExample & { tamperedNote: string };
  expected: { valid: boolean; tampered: boolean };
  reproduce: string;
}

let cached: DemoData | null = null;

function candidatePaths(): string[] {
  // Works both locally (dist/src -> project root) and on Vercel (the
  // function bundle includes demo/** via vercel.json includeFiles).
  return [
    path.join(process.cwd(), "demo", "example.json"),
    path.join(__dirname, "..", "..", "demo", "example.json"),
    path.join(__dirname, "..", "demo", "example.json"),
  ];
}

export function loadDemo(): DemoData | null {
  if (cached) return cached;
  for (const file of candidatePaths()) {
    try {
      cached = JSON.parse(fs.readFileSync(file, "utf8")) as DemoData;
      return cached;
    } catch {
      // try next candidate
    }
  }
  return null;
}
