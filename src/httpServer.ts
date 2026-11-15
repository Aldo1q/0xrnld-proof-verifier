// Plain Node HTTP server: no framework, no dependencies beyond snarkjs.
// Routes:
//   GET  /        service info + usage
//   GET  /health  liveness check
//   GET  /demo    worked example (real proof + tampered copy + expected verdicts)
//   POST /verify  verify a Groth16 proof { proof, verificationKey, publicSignals }
//   anything else -> 404
//
// Body limit: 1 MB (verification keys/proofs are normally < 100 KB).
// Malformed input -> 400 with a clear message. A well-formed proof that
// does not verify -> 200 { valid: false }. Nothing ever returns a false
// "valid: true".
import * as http from "node:http";
import { InputError, MAX_BODY_BYTES, parseVerifyInput, verifyProof } from "./verifier";
import { loadDemo } from "./demo";

const SERVICE = "0xrnld-proof-verifier";
const PROTOCOL_VERSION = "v1";

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooLarge = false;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (tooLarge) {
        reject(new InputError(`request body too large (max ${MAX_BODY_BYTES} bytes)`));
        return;
      }
      resolve(Buffer.concat(chunks));
    });
    req.on("error", reject);
  });
}

async function handleVerify(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  let raw: Buffer;
  try {
    raw = await readBody(req);
  } catch (e) {
    if (e instanceof InputError) {
      sendJson(res, 413, { error: e.message });
      return;
    }
    sendJson(res, 400, { error: "could not read request body" });
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    sendJson(res, 400, { error: "request body is not valid JSON" });
    return;
  }
  try {
    const input = parseVerifyInput(parsed);
    const result = await verifyProof(input);
    sendJson(res, 200, result);
  } catch (e) {
    if (e instanceof InputError) {
      sendJson(res, 400, { error: e.message });
      return;
    }
    sendJson(res, 500, { error: "internal error" });
  }
}

function handleDemo(res: http.ServerResponse): void {
  const demo = loadDemo();
  if (!demo) {
    sendJson(res, 503, { error: "demo example not available" });
    return;
  }
  sendJson(res, 200, {
    service: SERVICE,
    protocolVersion: PROTOCOL_VERSION,
    description: demo.description,
    circuit: demo.circuit,
    vkHash: demo.vkHash,
    verifyUrl: "/verify",
    expected: demo.expected,
    reproduce: demo.reproduce,
    valid: demo.valid,
    tampered: demo.tampered,
  });
}

function handleInfo(res: http.ServerResponse): void {
  sendJson(res, 200, {
    ok: true,
    service: SERVICE,
    protocolVersion: PROTOCOL_VERSION,
    description:
      "Public Groth16 (BN128) zero-knowledge proof verifier. Send a proof + verification key + public signals and get back whether the proof is valid — reproducible by anyone with snarkjs, no trust needed.",
    endpoints: {
      verify: "POST /verify  { proof, verificationKey, publicSignals } -> { valid, ... }",
      demo: "GET /demo  worked example (real proof + tampered copy + expected verdicts)",
      health: "GET /health  liveness check",
    },
  });
}

export function createHttpServer(): http.Server {
  return http.createServer((req, res) => {
    const url = req.url ?? "/";
    const path = url.split("?")[0];
    if (req.method === "GET" && path === "/") return handleInfo(res);
    if (req.method === "GET" && path === "/health") {
      return sendJson(res, 200, { ok: true, service: SERVICE, protocolVersion: PROTOCOL_VERSION });
    }
    if (req.method === "GET" && path === "/demo") return handleDemo(res);
    if (req.method === "POST" && (path === "/verify" || path === "/api/verify")) {
      void handleVerify(req, res);
      return;
    }
    sendJson(res, 404, { error: "not found" });
  });
}
