// End-to-end harness: boots the real server on an ephemeral port and
// replays verification requests. Exits non-zero if any check fails.
//
//   npm run gen-demo   (once, to create demo/example.json)
//   npm test
//
// Coverage: info/health/demo routes; valid proof -> valid:true; tampered
// public signal -> valid:false; tampered proof element -> valid:false;
// hex field elements accepted; malformed input (missing fields, wrong
// signal count, non-field values, invalid JSON) -> 400, never a verdict;
// unknown route -> 404.
import * as fs from "node:fs";
import * as path from "node:path";
import { createHttpServer } from "../src/httpServer";

const DEMO_FILE = path.join(process.cwd(), "demo", "example.json");

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(name: string, ok: boolean, detail = ""): void {
  if (ok) {
    passed++;
    console.log(`  PASS ${name}`);
  } else {
    failed++;
    failures.push(name);
    console.log(`  FAIL ${name}${detail ? " — " + detail : ""}`);
  }
}

async function req(
  base: string,
  method: string,
  route: string,
  body?: string,
): Promise<{ status: number; text: string; json: unknown }> {
  const res = await fetch(base + route, {
    method,
    headers: { "Content-Type": "application/json" },
    body,
  });
  const text = await res.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    // leave null
  }
  return { status: res.status, text, json };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

async function main(): Promise<void> {
  if (!fs.existsSync(DEMO_FILE)) {
    console.error(`demo file missing: ${DEMO_FILE} — run "npm run gen-demo" first.`);
    process.exit(2);
  }
  const demo = JSON.parse(fs.readFileSync(DEMO_FILE, "utf8")) as {
    valid: { proof: unknown; verificationKey: unknown; publicSignals: string[] };
    tampered: { proof: unknown; verificationKey: unknown; publicSignals: string[] };
  };

  const server = createHttpServer();
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  if (typeof address !== "object" || address === null) throw new Error("no listen address");
  const base = `http://127.0.0.1:${address.port}`;

  // Routes
  const info = await req(base, "GET", "/");
  check("GET / returns service info", info.status === 200 && isRecord(info.json) && info.json.ok === true);
  const health = await req(base, "GET", "/health");
  check("GET /health ok", health.status === 200 && isRecord(health.json) && health.json.ok === true);
  const demoRes = await req(base, "GET", "/demo");
  check(
    "GET /demo returns valid + tampered examples",
    demoRes.status === 200 &&
      isRecord(demoRes.json) &&
      isRecord(demoRes.json.valid) &&
      isRecord(demoRes.json.tampered),
  );
  const notFound = await req(base, "GET", "/nope");
  check("GET /nope -> 404", notFound.status === 404);

  // Valid proof
  const validRes = await req(base, "POST", "/verify", JSON.stringify(demo.valid));
  check(
    "valid proof -> valid:true",
    validRes.status === 200 &&
      isRecord(validRes.json) &&
      validRes.json.valid === true &&
      typeof validRes.json.ms === "number",
    `status=${validRes.status} body=${validRes.text.slice(0, 200)}`,
  );

  // Tampered public signal
  const tampRes = await req(base, "POST", "/verify", JSON.stringify(demo.tampered));
  check(
    "tampered public signal -> valid:false",
    tampRes.status === 200 && isRecord(tampRes.json) && tampRes.json.valid === false,
    `status=${tampRes.status} body=${tampRes.text.slice(0, 200)}`,
  );

  // Tampered proof element (pi_a[0] + 1)
  const tamperedProof = JSON.parse(JSON.stringify(demo.valid)) as typeof demo.valid;
  const piA = (tamperedProof.proof as { pi_a: string[] }).pi_a;
  piA[0] = (BigInt(piA[0]) + 1n).toString(10);
  const tampProofRes = await req(base, "POST", "/verify", JSON.stringify(tamperedProof));
  check(
    "tampered proof element -> valid:false",
    tampProofRes.status === 200 && isRecord(tampProofRes.json) && tampProofRes.json.valid === false,
    `status=${tampProofRes.status} body=${tampProofRes.text.slice(0, 200)}`,
  );

  // Hex field elements accepted (same valid proof, signals as 0x-hex)
  const hexInput = JSON.parse(JSON.stringify(demo.valid)) as typeof demo.valid;
  hexInput.publicSignals = hexInput.publicSignals.map((s) => "0x" + BigInt(s).toString(16));
  const hexRes = await req(base, "POST", "/verify", JSON.stringify(hexInput));
  check(
    "hex public signals accepted -> valid:true",
    hexRes.status === 200 && isRecord(hexRes.json) && hexRes.json.valid === true,
    `status=${hexRes.status} body=${hexRes.text.slice(0, 200)}`,
  );

  // Malformed inputs -> 400, never a verdict
  const cases: Array<[string, unknown]> = [
    ["missing proof", { verificationKey: demo.valid.verificationKey, publicSignals: demo.valid.publicSignals }],
    ["missing verificationKey", { proof: demo.valid.proof, publicSignals: demo.valid.publicSignals }],
    ["missing publicSignals", { proof: demo.valid.proof, verificationKey: demo.valid.verificationKey }],
    [
      "publicSignals wrong length",
      { proof: demo.valid.proof, verificationKey: demo.valid.verificationKey, publicSignals: ["1"] },
    ],
    [
      "non-field-element signal",
      {
        proof: demo.valid.proof,
        verificationKey: demo.valid.verificationKey,
        publicSignals: demo.valid.publicSignals.map((s, i) => (i === 0 ? "not-a-number" : s)),
      },
    ],
    ["empty object", {}],
    ["wrong curve", { proof: demo.valid.proof, verificationKey: { ...(demo.valid.verificationKey as object), curve: "bls12381" }, publicSignals: demo.valid.publicSignals }],
  ];
  for (const [name, body] of cases) {
    const r = await req(base, "POST", "/verify", JSON.stringify(body));
    check(
      `malformed (${name}) -> 400, no verdict`,
      r.status === 400 && isRecord(r.json) && typeof r.json.error === "string" && r.json.valid === undefined,
      `status=${r.status} body=${r.text.slice(0, 160)}`,
    );
  }
  const badJson = await req(base, "POST", "/verify", "{not json");
  check("invalid JSON -> 400", badJson.status === 400);

  server.close();
  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.log(`failures: ${failures.join(", ")}`);
    process.exit(1);
  }
  // Explicit exit: undici keep-alive sockets from fetch() keep the event
  // loop alive otherwise.
  process.exit(0);
}

main().catch((e) => {
  console.error("harness crashed:", e);
  process.exit(1);
});
