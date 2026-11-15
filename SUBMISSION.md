# Wildcard submission — ProofCheck (public ZK proof verifier)

## Agent link

- **Repository:** https://github.com/Aldo1q/0xrnld-proof-verifier
- **Public endpoint:** https://0xrnld-proof-verifier.vercel.app
- **Demo:** `GET https://0xrnld-proof-verifier.vercel.app/demo` (real proof + tampered copy + expected verdicts)

## Use case

**Problem.** A zero-knowledge proof is only useful if someone checks it.
Today, checking a Groth16 proof means installing snarkjs, finding the right
verification key, and running the verifier yourself — so in practice most
proofs are never checked by the people who rely on them. Agents, apps, and
users are asked to trust claims ("this payment is valid", "this credential
is real") backed by proofs they cannot easily verify.

**Who it helps.** Anyone handed a ZK proof: an app or agent that must decide
whether to act on a proof-backed claim, and any user who was told "this is
proven" and wants an independent check without setting up a toolchain.

**What it does.** ProofCheck is a public agent that verifies any Groth16
(BN128) proof. `POST /verify` with `{ proof, verificationKey,
publicSignals }` returns `{ valid: true|false, ... }` in well under a
second. No sign-up, no API key, no trust required — the verdict is
reproducible by anyone with snarkjs, so you never have to take the agent's
word for it.

## Build context

- **Stack:** TypeScript + Node (no framework), `snarkjs@0.7.6` for
  verification, deployed on Vercel (serverless function + catch-all server
  entry). Stateless: no database, no keys, no secrets.
- **How it works:** (1) strict validation of every field — proof shape
  (`pi_a`/`pi_b`/`pi_c`), verification-key shape (`nPublic`, `vk_alpha_1`,
  `vk_beta_2`, `vk_gamma_2`, `vk_delta_2`, `vk_alphabeta_12`, `IC` with
  `nPublic + 1` entries), every value a valid BN128 field element, and
  `publicSignals` exactly `nPublic` long; (2) fail closed — malformed
  input returns HTTP 400 with a clear message, never a verdict;
  (3) `snarkjs.groth16.verify` on the normalised inputs; a well-formed
  proof that does not verify returns `{ valid: false }`.
- **Key decisions:** verification only (no proof generation — the agent's
  job is to *check*, not to prove); decimal and `0x`-hex field elements
  both accepted; 1 MB body limit; deterministic — the same inputs always
  give the same verdict.
- **Tests:** 16 end-to-end checks (`npm test`, all passing) covering a real
  valid proof, a tampered public signal, a tampered proof element, hex
  inputs, and seven malformed-input shapes (all 400, never a verdict).

## zkVerify (optional)

The claim this agent makes — "this proof is valid" — is itself checkable:
anyone can reproduce the verdict offline with snarkjs, and the demo proof
is a real proof from the official Agent Games Proof Gatekeeper circuit
(verification-key hash
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`).
That is the same Groth16/BN128 system zkVerify verifies on-chain — this
agent is the off-chain, anyone-can-run counterpart for the same check.

## Demo (copy-paste)

```bash
# 1. See the worked example (real proof + tampered copy)
curl -s https://0xrnld-proof-verifier.vercel.app/demo

# 2. Valid proof -> expect { "valid": true }
curl -s -X POST https://0xrnld-proof-verifier.vercel.app/verify \
  -H 'Content-Type: application/json' \
  -d "$(curl -s https://0xrnld-proof-verifier.vercel.app/demo | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>console.log(JSON.stringify(JSON.parse(d).valid)))")"

# 3. Tampered proof -> expect { "valid": false }
curl -s -X POST https://0xrnld-proof-verifier.vercel.app/verify \
  -H 'Content-Type: application/json' \
  -d "$(curl -s https://0xrnld-proof-verifier.vercel.app/demo | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>console.log(JSON.stringify(JSON.parse(d).tampered)))")"
```
