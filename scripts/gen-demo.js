// Generate demo/example.json: a REAL Groth16 proof from the official Agent
// Games Proof Gatekeeper circuit, plus a tampered copy (one public signal
// changed) so the demo shows both a valid and an invalid verdict.
//
// Local-only script: it reuses the gatekeeper repo's compiled helpers and
// public circuit artifacts. Nothing secret is involved — the "secret" below
// is a fixed demo string used only to derive the circuit salt for this
// example proof, and the proof itself is public data.
const fs = require("node:fs");
const path = require("node:path");

const GK = "/home/hatch/workspace/zkverify-gatekeeper/repo";
const { hashStringToField } = require(path.join(GK, "dist/src/field.js"));
const { deriveSalt } = require(path.join(GK, "dist/src/hmac.js"));
const { toCircuitSignals } = require(path.join(GK, "dist/src/policy.js"));
const { prove, loadVerificationKey } = require(path.join(GK, "dist/src/prover.js"));

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ALICE = "0x1111111111111111111111111111111111111111";
const TASK_ID = "proofcheck-demo-1";
const DEMO_SALT_SEED = "proofcheck-demo";

(async () => {
  const circuitsDir = path.join(GK, "circuits");
  const taskIdField = hashStringToField(TASK_ID);
  const salt = deriveSalt(DEMO_SALT_SEED, TASK_ID);
  const inputs = toCircuitSignals(
    {
      registeredVk: VK,
      proofVk: VK,
      minimum: 1000n,
      publicBalance: 1460n,
      expiryBlock: 8430000n,
      currentBlock: 8420000n,
      recipient: ALICE,
      conditionRecipient: ALICE,
      amount: 500n,
      maxTransfer: 1000n,
      proofTx: "0x" + "a".repeat(64),
    },
    taskIdField,
    salt,
    "APPROVE",
  );
  console.log("generating proof with the official gatekeeper circuit ...");
  const { proof, publicSignals } = await prove(inputs, circuitsDir);
  const verificationKey = loadVerificationKey(circuitsDir);

  // Tampered copy: change public signal [4] (publicBalance 1460 -> 1461).
  // The proof binds all signals, so this must fail verification.
  const tamperedSignals = [...publicSignals];
  tamperedSignals[4] = "1461";

  const out = {
    description:
      "A real Groth16 proof generated with the official zkVerify Agent Games Proof Gatekeeper circuit (a valid APPROVE decision: balance 1460 >= minimum 1000, recipient matches, not expired). The tampered copy changes one public signal (publicBalance 1460 -> 1461); the same proof must then fail verification.",
    circuit: "Proof Gatekeeper (official Agent Games circuit)",
    vkHash: VK,
    valid: { proof, verificationKey, publicSignals },
    tampered: {
      proof,
      verificationKey,
      publicSignals: tamperedSignals,
      tamperedNote: "publicSignals[4] (publicBalance) changed from 1460 to 1461",
    },
    expected: { valid: true, tampered: false },
    reproduce:
      "POST the `valid` object to /verify and expect { valid: true }. POST the `tampered` object and expect { valid: false }. Or verify locally: snarkjs.groth16.verify(verificationKey, publicSignals, proof).",
  };
  const dest = path.join(__dirname, "..", "demo", "example.json");
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, JSON.stringify(out, null, 2) + "\n");
  console.log(`saved: ${dest} (${fs.statSync(dest).size} bytes)`);
  console.log(`publicSignals: ${JSON.stringify(publicSignals)}`);
  // Explicit exit: snarkjs/circomlibjs leave handles that keep the
  // event loop alive otherwise.
  process.exit(0);
})().catch((e) => {
  console.error("gen-demo failed:", e);
  process.exit(1);
});
