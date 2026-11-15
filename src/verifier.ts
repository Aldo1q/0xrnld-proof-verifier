// ProofCheck — public Groth16 (BN128) proof verifier.
//
// Input:  { proof, verificationKey, publicSignals }
// Output: { valid: true|false, protocol, curve, nPublic, ms, verifiedAt, reason? }
//
// Fail-closed by design:
//  - Malformed input (missing fields, wrong shapes, non-field elements,
//    publicSignals length != vk.nPublic) -> InputError (HTTP 400), never
//    a verdict. A malformed request is not a "valid: false" proof.
//  - Well-formed input that does not verify -> { valid: false }.
//  - snarkjs throwing during verification (e.g. a point off-curve) is a
//    cryptographically invalid proof -> { valid: false }, never an error
//    that could be mistaken for a pass.
//
// The verdict is reproducible by anyone: the same proof + vk + signals
// verified locally with `snarkjs.groth16.verify` gives the same answer.
// No trust in this agent is required — that is the whole point.

import * as snarkjs from "snarkjs";

/** BN128 (alt_bn128) scalar field prime. */
export const FIELD_PRIME = BigInt(
  "21888242871839275222246405745257275088696311157297823662689037894645226208583",
);

export const MAX_BODY_BYTES = 1_048_576; // 1 MB — vks/proofs are normally < 100 KB.

export class InputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InputError";
  }
}

export interface NormalisedProof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
}

export interface NormalisedVk {
  protocol: "groth16";
  curve: "bn128";
  nPublic: number;
  vk_alpha_1: string[];
  vk_beta_2: string[][];
  vk_gamma_2: string[][];
  vk_delta_2: string[][];
  vk_alphabeta_12: string[][][];
  IC: string[][];
}

export interface VerifyInput {
  proof: NormalisedProof;
  verificationKey: NormalisedVk;
  publicSignals: string[];
}

export interface VerifyResult {
  valid: boolean;
  protocol: "groth16";
  curve: "bn128";
  nPublic: number;
  ms: number;
  verifiedAt: string;
  reason: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const DEC_RE = /^(0|[1-9][0-9]*)$/;
const HEX_RE = /^0x[0-9a-fA-F]+$/;

/**
 * Normalise one field element to a canonical decimal string.
 * Accepts decimal strings, 0x-hex strings, and safe-integer numbers.
 * Rejects anything that is not a valid BN128 field element.
 */
export function normaliseFieldElement(value: unknown, where: string): string {
  let n: bigint;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new InputError(`${where}: not a valid field element (${String(value)})`);
    }
    n = BigInt(value);
  } else if (typeof value === "string") {
    if (DEC_RE.test(value)) {
      n = BigInt(value);
    } else if (HEX_RE.test(value)) {
      n = BigInt(value);
    } else {
      throw new InputError(`${where}: not a valid field element (${JSON.stringify(value)})`);
    }
  } else {
    throw new InputError(`${where}: not a valid field element (expected a decimal or 0x-hex string)`);
  }
  if (n >= FIELD_PRIME) {
    throw new InputError(`${where}: value is outside the BN128 field`);
  }
  return n.toString(10);
}

function normaliseG1Point(value: unknown, where: string): string[] {
  if (!Array.isArray(value) || value.length !== 3) {
    throw new InputError(`${where}: expected a G1 point [x, y, z] (3 field elements)`);
  }
  return value.map((el, i) => normaliseFieldElement(el, `${where}[${i}]`));
}

function normaliseG2Point(value: unknown, where: string): string[][] {
  if (!Array.isArray(value) || value.length !== 3) {
    throw new InputError(`${where}: expected a G2 point [[x0,x1],[y0,y1],[z0,z1]]`);
  }
  return value.map((row, i) => {
    if (!Array.isArray(row) || row.length !== 2) {
      throw new InputError(`${where}[${i}]: expected a pair of field elements`);
    }
    return row.map((el, j) => normaliseFieldElement(el, `${where}[${i}][${j}]`));
  });
}

function normaliseAlphaBeta12(value: unknown, where: string): string[][][] {
  // vk_alphabeta_12 is NOT a single G2 point: it is a pair of G2 points
  // (the precomputed e(alpha, beta) line coefficients), i.e. an array of
  // exactly 2 G2 points, each [[x0,x1],[y0,y1],[z0,z1]].
  if (!Array.isArray(value) || value.length !== 2) {
    throw new InputError(`${where}: expected an array of 2 G2 points`);
  }
  return value.map((pt, i) => normaliseG2Point(pt, `${where}[${i}]`));
}

function normaliseProof(proof: unknown): NormalisedProof {
  if (!isRecord(proof)) throw new InputError("proof: expected an object { pi_a, pi_b, pi_c }");
  if (proof.protocol !== undefined && proof.protocol !== "groth16") {
    throw new InputError(`proof.protocol: expected "groth16", got ${JSON.stringify(proof.protocol)}`);
  }
  if (proof.curve !== undefined && proof.curve !== "bn128") {
    throw new InputError(`proof.curve: expected "bn128", got ${JSON.stringify(proof.curve)}`);
  }
  return {
    pi_a: normaliseG1Point(proof.pi_a, "proof.pi_a"),
    pi_b: normaliseG2Point(proof.pi_b, "proof.pi_b"),
    pi_c: normaliseG1Point(proof.pi_c, "proof.pi_c"),
  };
}

function normaliseVerificationKey(vk: unknown): NormalisedVk {
  if (!isRecord(vk)) {
    throw new InputError("verificationKey: expected an object (snarkjs verification key format)");
  }
  if (vk.protocol !== "groth16") {
    throw new InputError(`verificationKey.protocol: expected "groth16", got ${JSON.stringify(vk.protocol)}`);
  }
  if (vk.curve !== "bn128") {
    throw new InputError(`verificationKey.curve: expected "bn128", got ${JSON.stringify(vk.curve)}`);
  }
  if (typeof vk.nPublic !== "number" || !Number.isSafeInteger(vk.nPublic) || vk.nPublic < 0) {
    throw new InputError("verificationKey.nPublic: expected a non-negative integer");
  }
  if (!Array.isArray(vk.IC)) {
    throw new InputError("verificationKey.IC: expected an array of G1 points");
  }
  if (vk.IC.length !== vk.nPublic + 1) {
    throw new InputError(
      `verificationKey.IC: expected ${vk.nPublic + 1} points (nPublic + 1), got ${vk.IC.length}`,
    );
  }
  return {
    protocol: "groth16",
    curve: "bn128",
    nPublic: vk.nPublic,
    vk_alpha_1: normaliseG1Point(vk.vk_alpha_1, "verificationKey.vk_alpha_1"),
    vk_beta_2: normaliseG2Point(vk.vk_beta_2, "verificationKey.vk_beta_2"),
    vk_gamma_2: normaliseG2Point(vk.vk_gamma_2, "verificationKey.vk_gamma_2"),
    vk_delta_2: normaliseG2Point(vk.vk_delta_2, "verificationKey.vk_delta_2"),
    vk_alphabeta_12: normaliseAlphaBeta12(vk.vk_alphabeta_12, "verificationKey.vk_alphabeta_12"),
    IC: vk.IC.map((pt, i) => normaliseG1Point(pt, `verificationKey.IC[${i}]`)),
  };
}

/** Parse + validate a raw request body into a normalised verify input. Throws InputError. */
export function parseVerifyInput(body: unknown): VerifyInput {
  if (!isRecord(body)) {
    throw new InputError("request body must be a JSON object { proof, verificationKey, publicSignals }");
  }
  if (body.proof === undefined) throw new InputError("proof: missing (expected { pi_a, pi_b, pi_c })");
  if (body.verificationKey === undefined) {
    throw new InputError("verificationKey: missing (expected a snarkjs verification key object)");
  }
  if (body.publicSignals === undefined) {
    throw new InputError("publicSignals: missing (expected an array of field elements)");
  }
  const verificationKey = normaliseVerificationKey(body.verificationKey);
  const proof = normaliseProof(body.proof);
  if (!Array.isArray(body.publicSignals)) {
    throw new InputError("publicSignals: expected an array of field elements");
  }
  if (body.publicSignals.length !== verificationKey.nPublic) {
    throw new InputError(
      `publicSignals: expected ${verificationKey.nPublic} elements (verificationKey.nPublic), got ${body.publicSignals.length}`,
    );
  }
  const publicSignals = body.publicSignals.map((el, i) =>
    normaliseFieldElement(el, `publicSignals[${i}]`),
  );
  return { proof, verificationKey, publicSignals };
}

/** Verify a normalised input with snarkjs. Never throws for an invalid proof. */
export async function verifyProof(input: VerifyInput): Promise<VerifyResult> {
  const started = Date.now();
  let valid = false;
  let reason: string;
  try {
    valid = await snarkjs.groth16.verify(input.verificationKey, input.publicSignals, input.proof);
    reason = valid
      ? "proof verifies against the verification key and public signals"
      : "proof does not verify against the verification key and public signals";
  } catch (e) {
    // A point off-curve or a pairing failure is a cryptographically
    // invalid proof, not a server error — report it as invalid.
    valid = false;
    reason = `verification failed: ${e instanceof Error ? e.message : String(e)}`;
  }
  return {
    valid,
    protocol: "groth16",
    curve: "bn128",
    nPublic: input.verificationKey.nPublic,
    ms: Date.now() - started,
    verifiedAt: new Date().toISOString(),
    reason,
  };
}
