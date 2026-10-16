import { describe, expect, it } from "vitest";
import {
  buildTree, canonicalize, decodeQr, encodeQr, fieldsDigest, leafFields, rootFromProof,
  verifyContent, randomSalt, Fields,
} from "../src";

const issuerId = "0x" + "ab".repeat(32);
const fields: Fields = {
  ref_no: "MOH/2026/0042",
  recipient: "  Jane   Doe ",
  date: "2026-10-16",
  amount: "4000",
};

async function issue(f: Fields, refNo: string) {
  const salt = randomSalt();
  const digest = await fieldsDigest(f);
  const leaf = await leafFields({ issuerId, refNo, digest, salt });
  return { salt, leaf };
}

describe("canonicalize", () => {
  it("is order-independent and normalizes whitespace", () => {
    expect(canonicalize({ b: "x  y", a: "1" })).toBe(canonicalize({ a: "1", b: " x y " }));
    expect(canonicalize(fields)).toBe(
      '{"amount":"4000","date":"2026-10-16","recipient":"Jane Doe","ref_no":"MOH/2026/0042"}',
    );
  });
  it("rejects bad field names", () => {
    expect(() => canonicalize({ "Bad Name": "x" })).toThrow();
  });
});

describe("issue and verify", () => {
  it("verifies genuine content, rejects altered content and wrong QR", async () => {
    const a = await issue(fields, "MOH/2026/0042");
    const other = await issue({ ...fields, recipient: "Bob" }, "MOH/2026/0043");
    const tree = await buildTree([a.leaf, other.leaf], 4);
    const qr = { issuerId, refNo: "MOH/2026/0042", salt: a.salt, mode: "paper" as const };
    const proof = tree.proof(0);
    const roots = [tree.root];

    expect(await verifyContent({ qr, content: { fields }, proof, anchoredRoots: roots })).toBe("valid");
    // QR copied onto a fake letter: content differs.
    expect(
      await verifyContent({ qr, content: { fields: { ...fields, amount: "9000" } }, proof, anchoredRoots: roots }),
    ).toBe("altered");
    // Genuine content, wrong salt.
    expect(
      await verifyContent({ qr: { ...qr, salt: qr.salt + 1n }, content: { fields }, proof, anchoredRoots: roots }),
    ).toBe("altered");
    // Unanchored root.
    expect(await verifyContent({ qr, content: { fields }, proof, anchoredRoots: [] })).toBe("altered");
  });

  it("merkle proofs round-trip for every index", async () => {
    const leaves = [1n, 2n, 3n, 4n, 5n];
    const tree = await buildTree(leaves, 5);
    for (let i = 0; i < leaves.length; i++) {
      expect(await rootFromProof(leaves[i], tree.proof(i))).toBe(tree.root);
    }
  });
});

describe("qr", () => {
  it("round-trips and keeps salt in the fragment", () => {
    const p = { issuerId, refNo: "MOH/2026/0042", salt: 0xdeadbeefn, mode: "paper" as const };
    const url = encodeQr(p);
    expect(url.split("#")[1]).toContain("s=deadbeef");
    expect(url.split("#")[0]).not.toContain("deadbeef");
    expect(decodeQr(url)).toEqual(p);
  });
  it("rejects malformed urls", () => {
    expect(() => decodeQr("https://x.com/a/b#s=1&m=paper")).toThrow();
  });
});
