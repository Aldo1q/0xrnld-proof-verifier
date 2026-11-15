// Vercel serverless entry for GET/POST on /verify (and /api/verify).
// bodyParser must stay off so large verification keys pass through intact.
import type { IncomingMessage, ServerResponse } from "node:http";
import { InputError, MAX_BODY_BYTES, parseVerifyInput, verifyProof } from "../src/verifier";
import { loadDemo } from "../src/demo";

const SERVICE = "0xrnld-proof-verifier";
const PROTOCOL_VERSION = "v1";

type VercelRequest = IncomingMessage & {
  method?: string;
  query?: Record<string, string | string[]>;
};

type VercelResponse = ServerResponse & {
  status: (code: number) => VercelResponse;
  json: (body: unknown) => void;
  send: (body: string) => void;
};

function readBody(req: VercelRequest): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooLarge = false;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) tooLarge = true;
      else chunks.push(chunk);
    });
    req.on("end", () => {
      if (tooLarge) reject(new InputError(`request body too large (max ${MAX_BODY_BYTES} bytes)`));
      else resolve(Buffer.concat(chunks));
    });
    req.on("error", reject);
  });
}

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (req.method === "GET") {
    const demo = loadDemo();
    res.status(200).json({
      ok: true,
      service: SERVICE,
      protocolVersion: PROTOCOL_VERSION,
      description:
        "Public Groth16 (BN128) zero-knowledge proof verifier. POST a proof + verification key + public signals to /verify.",
      endpoints: {
        verify: "POST /verify  { proof, verificationKey, publicSignals } -> { valid, ... }",
        demo: "GET /demo  worked example (real proof + tampered copy + expected verdicts)",
        health: "GET /health  liveness check",
      },
      demoAvailable: demo !== null,
    });
    return;
  }
  if (req.method !== "POST") {
    res.status(405).json({ error: "method not allowed" });
    return;
  }
  try {
    const raw = await readBody(req);
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.toString("utf8"));
    } catch {
      res.status(400).json({ error: "request body is not valid JSON" });
      return;
    }
    try {
      const input = parseVerifyInput(parsed);
      const result = await verifyProof(input);
      res.status(200).json(result);
    } catch (e) {
      if (e instanceof InputError) {
        res.status(400).json({ error: e.message });
        return;
      }
      res.status(500).json({ error: "internal error" });
    }
  } catch (e) {
    if (e instanceof InputError) {
      res.status(413).json({ error: e.message });
      return;
    }
    res.status(500).json({ error: "internal error" });
  }
}

export const config = { api: { bodyParser: false } };
