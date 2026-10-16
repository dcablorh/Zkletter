export interface QrPayload {
  issuerId: string; // 0x + 64 hex
  refNo: string;
  salt: bigint;
  mode: "paper" | "file";
}

export const VERIFY_BASE = "https://verify.zkletter.app/v1";

/** The salt lives in the URL fragment so it is never sent to any server. */
export function encodeQr(p: QrPayload, base = VERIFY_BASE): string {
  return `${base}/${p.issuerId}/${encodeURIComponent(p.refNo)}#s=${p.salt.toString(16)}&m=${p.mode}`;
}

export function decodeQr(url: string): QrPayload {
  const u = new URL(url);
  const parts = u.pathname.split("/").filter(Boolean);
  const n = parts.length;
  if (n < 3 || parts[n - 3] !== "v1") throw new Error("not a Zkletter URL");
  const issuerId = parts[n - 2];
  if (!/^0x[0-9a-f]{64}$/.test(issuerId)) throw new Error("bad issuer id");
  const params = new URLSearchParams(u.hash.replace(/^#/, ""));
  const s = params.get("s");
  const mode = params.get("m");
  if (!s || !/^[0-9a-f]{1,32}$/.test(s)) throw new Error("bad salt");
  if (mode !== "paper" && mode !== "file") throw new Error("bad mode");
  return { issuerId, refNo: decodeURIComponent(parts[n - 1]), salt: BigInt("0x" + s), mode };
}
