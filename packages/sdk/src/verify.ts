import { Fields } from "./canonical";
import { fieldsDigest, fileDigest, leafFields, leafFile } from "./commit";
import { MerkleProof, rootFromProof } from "./merkle";
import { QrPayload } from "./qr";

export type Verdict = "valid" | "altered";

export interface VerifyInput {
  qr: QrPayload;
  content: { fields: Fields } | { file: Uint8Array };
  proof: MerkleProof;
  /** Roots anchored on Sui by this issuer (read from chain by the caller). */
  anchoredRoots: bigint[];
}

/** Pure content/commitment check. Issuer status and revocation are checked by the caller against Sui. */
export async function verifyContent(i: VerifyInput): Promise<Verdict> {
  const base = { issuerId: i.qr.issuerId, refNo: i.qr.refNo, salt: i.qr.salt };
  const leaf =
    "fields" in i.content
      ? await leafFields({ ...base, digest: await fieldsDigest(i.content.fields) })
      : await leafFile({ ...base, digest: await fileDigest(i.content.file) });
  const root = await rootFromProof(leaf, i.proof);
  return i.anchoredRoots.includes(root) ? "valid" : "altered";
}
