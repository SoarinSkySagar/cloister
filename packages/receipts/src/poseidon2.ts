/**
 * Poseidon2 over the BLS12-381 scalar field with gnark-crypto's default parameters (width 2,
 * 6 full + 50 partial rounds, S-box x^5), as used by circuits/ledger. No Node imports: it runs in the
 * browser. It must reproduce every value in spec/vectors/inclusion.json (see test/inclusion.test.ts).
 *
 * Round keys are the Keccak-256 chain of the seed string, exactly as gnark-crypto's initRC derives them:
 * r_0 = keccak256(seed), r_i = keccak256(r_{i-1}), key_i = r_i mod p, consumed in round order
 * (2 keys per full round, 1 per partial round).
 */
import { keccak_256 } from "@noble/hashes/sha3";

export const P = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
const FULL = 6, PARTIAL = 50;
const SEED = `Poseidon2-BLS12_381[t=2,rF=${FULL},rP=${PARTIAL},d=5]`;

const bytesToBig = (b: Uint8Array) => b.reduce((n, x) => (n << 8n) | BigInt(x), 0n);

let keys: bigint[][] | undefined;
function roundKeys(): bigint[][] {
  if (keys) return keys;
  let r = keccak_256(new TextEncoder().encode(SEED));
  const next = () => { r = keccak_256(r); return bytesToBig(r) % P; };
  const out: bigint[][] = [];
  for (let i = 0; i < FULL / 2; i++) out.push([next(), next()]);
  for (let i = 0; i < PARTIAL; i++) out.push([next()]);
  for (let i = 0; i < FULL / 2; i++) out.push([next(), next()]);
  return (keys = out);
}

const sbox = (x: bigint) => { const x2 = (x * x) % P, x4 = (x2 * x2) % P; return (x4 * x) % P; };

/** Width-2 permutation in place on [a, b]. */
function permute(s: [bigint, bigint]) {
  const ks = roundKeys();
  const external = () => { const t = (s[0] + s[1]) % P; s[0] = (t + s[0]) % P; s[1] = (t + s[1]) % P; };
  const internal = () => { const sum = (s[0] + s[1]) % P; s[0] = (s[0] + sum) % P; s[1] = (2n * s[1] + sum) % P; };
  const full = (i: number) => { s[0] = sbox((s[0] + ks[i]![0]!) % P); s[1] = sbox((s[1] + ks[i]![1]!) % P); external(); };
  external();
  for (let i = 0; i < FULL / 2; i++) full(i);
  for (let i = FULL / 2; i < FULL / 2 + PARTIAL; i++) { s[0] = sbox((s[0] + ks[i]![0]!) % P); internal(); }
  for (let i = FULL / 2 + PARTIAL; i < FULL + PARTIAL; i++) full(i);
}

/** The 2-to-1 compression of tree nodes: out = right + permute([left, right])[1]. */
export function compress(left: bigint, right: bigint): bigint {
  const s: [bigint, bigint] = [left % P, right % P];
  permute(s);
  return (right + s[1]) % P;
}

/** Merkle-Damgard over field elements with a zero IV (record and account leaves). */
export function md(fields: bigint[]): bigint {
  let h = 0n;
  for (const f of fields) h = compress(h, f);
  return h;
}
