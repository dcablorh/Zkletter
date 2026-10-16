import { buildPoseidon } from "circomlibjs";
import { bytesToBigInt, fromHex, sha256 } from "./hash";
import { canonicalize, Fields } from "./canonical";

// BN254 scalar field modulus.
export const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const DOM_FIELDS = 1n;
export const DOM_FILE = 2n;
export const DOM_NODE = 3n;

let poseidonP: ReturnType<typeof buildPoseidon> | undefined;
export async function poseidon(inputs: bigint[]): Promise<bigint> {
  poseidonP ??= buildPoseidon();
  const p = await poseidonP;
  return p.F.toObject(p(inputs));
}

const MASK128 = (1n << 128n) - 1n;
/** Split a 32-byte digest into two 128-bit field elements (hi, lo). */
export function splitDigest(d: Uint8Array): [bigint, bigint] {
  if (d.length !== 32) throw new Error("digest must be 32 bytes");
  const v = bytesToBigInt(d);
  return [v >> 128n, v & MASK128];
}

export async function fieldsDigest(fields: Fields): Promise<Uint8Array> {
  return sha256(canonicalize(fields));
}

export async function fileDigest(bytes: Uint8Array): Promise<Uint8Array> {
  return sha256(bytes);
}

/** Reference numbers are mapped into the field via SHA-256 (reduced mod p). */
export async function refToField(refNo: string): Promise<bigint> {
  return bytesToBigInt(await sha256(refNo.normalize("NFC").trim())) % FIELD_P;
}

export interface LeafInput {
  issuerId: string; // 0x-prefixed 32-byte Sui object id
  refNo: string;
  digest: Uint8Array; // fieldsDigest or fileDigest
  salt: bigint; // 128-bit
}

async function leaf(dom: bigint, i: LeafInput): Promise<bigint> {
  if (i.salt < 0n || i.salt > MASK128) throw new Error("salt must be 128 bits");
  const id = fromHex(i.issuerId);
  if (id.length !== 32) throw new Error("issuerId must be 32 bytes");
  const [idHi, idLo] = splitDigest(id);
  const [dHi, dLo] = splitDigest(i.digest);
  return poseidon([dom, idHi, idLo, await refToField(i.refNo), dHi, dLo, i.salt]);
}

export const leafFields = (i: LeafInput) => leaf(DOM_FIELDS, i);
export const leafFile = (i: LeafInput) => leaf(DOM_FILE, i);

export function randomSalt(): bigint {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return bytesToBigInt(b);
}
