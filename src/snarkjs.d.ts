declare module "snarkjs" {
  const snarkjs: {
    groth16: {
      fullProve: (input: Record<string, unknown>, wasm: string, zkey: string) => Promise<{
        proof: { pi_a: unknown[]; pi_b: unknown[][]; pi_c: unknown[] };
        publicSignals: unknown[];
      }>;
      verify: (vk: unknown, publicSignals: unknown[], proof: unknown) => Promise<boolean>;
    };
    zKey: {
      exportVerificationKey: (zkey: string) => Promise<unknown>;
    };
  };
  export = snarkjs;
}
