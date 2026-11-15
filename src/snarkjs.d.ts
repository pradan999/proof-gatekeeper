/** snarkjs ships no TypeScript declarations; minimal local shim. */
declare module "snarkjs" {
  export namespace groth16 {
    function fullProve(
      input: Record<string, unknown>,
      wasmPath: string,
      zkeyPath: string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    function verify(vk: unknown, publicSignals: string[], proof: unknown): Promise<boolean>;
  }
}
