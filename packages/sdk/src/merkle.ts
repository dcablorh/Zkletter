import { DOM_NODE, poseidon } from "./commit";

export const DEFAULT_DEPTH = 20;

async function node(l: bigint, r: bigint) {
  return poseidon([DOM_NODE, l, r]);
}

async function zeros(depth: number): Promise<bigint[]> {
  const z: bigint[] = [0n];
  for (let i = 0; i < depth; i++) z.push(await node(z[i], z[i]));
  return z;
}

export interface MerkleProof {
  index: number;
  siblings: bigint[];
}

export interface MerkleTree {
  root: bigint;
  depth: number;
  proof(index: number): MerkleProof;
}

export async function buildTree(leaves: bigint[], depth = DEFAULT_DEPTH): Promise<MerkleTree> {
  if (leaves.length > 2 ** depth) throw new Error("too many leaves for depth");
  const z = await zeros(depth);
  const levels: bigint[][] = [leaves.slice()];
  for (let d = 0; d < depth; d++) {
    const cur = levels[d];
    const next: bigint[] = [];
    for (let i = 0; i < cur.length; i += 2) {
      next.push(await node(cur[i], i + 1 < cur.length ? cur[i + 1] : z[d]));
    }
    levels.push(next);
  }
  const root = levels[depth][0] ?? z[depth];
  return {
    root,
    depth,
    proof(index: number): MerkleProof {
      if (index < 0 || index >= leaves.length) throw new Error("index out of range");
      const siblings: bigint[] = [];
      let idx = index;
      for (let d = 0; d < depth; d++) {
        const sib = idx ^ 1;
        siblings.push(sib < levels[d].length ? levels[d][sib] : z[d]);
        idx >>= 1;
      }
      return { index, siblings };
    },
  };
}

export async function rootFromProof(leafValue: bigint, p: MerkleProof): Promise<bigint> {
  let cur = leafValue;
  let idx = p.index;
  for (const sib of p.siblings) {
    cur = idx & 1 ? await node(sib, cur) : await node(cur, sib);
    idx >>= 1;
  }
  return cur;
}
