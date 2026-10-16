# Zkletter: Design Spec (v0.1)

Verifiable official letters for institutions, built on Sui. Anyone can check that a
letter is authentic and came from the expected institution, without the letter's
content ever being published.

## 1. Problem

Forged notices and letters circulate because a reader cannot tell (a) who really
issued a document or (b) whether it was altered. A QR code or logo on paper proves
nothing: it can be copied onto a fake letter.

## 2. Goals and non-goals

Goals
- A verifier can confirm: *this exact content was issued by institution X, on date Y,
  and has not been revoked.*
- Content stays private. Only commitments are published on-chain.
- A QR code copied onto a different letter must fail verification.
- Institutions can issue at volume cheaply (batched anchoring).
- Works from paper with a phone camera, no wallet needed by the verifier.

Non-goals (v1)
- Proving an institution is legitimate beyond the curated registry (trust anchor is
  governance plus domain proof; see 4.1).
- Preventing a faithful copy of a genuine letter from being shown by the wrong person
  (mitigated, see 8).
- Hiding *which* letter is being checked from the public verifier (v2, ZK).

## 3. Core idea

> The QR carries the secret needed to **recompute** a commitment. The verifier supplies
> the letter's content. Authenticity = recomputed commitment is in a Merkle tree the
> institution anchored on Sui.

A copied QR fails because the fake letter's content produces a different commitment.

## 4. Actors and components

| Component | Responsibility |
|---|---|
| Registry admin (multisig) | Approves institutions, can suspend them |
| Institution | Issues letters, anchors batches, revokes |
| Holder / recipient | Holds the letter (paper or PDF) |
| Verifier | Scans QR, supplies content, gets a verdict |
| Indexer | Public service that serves Merkle paths and chain state |
| Sui Move package | Registry, anchoring, revocation, (v2) proof verification |

### 4.1 Institution trust anchor

An institution is trusted only if **both** hold:
1. It has an `Issuer` entry approved by the admin multisig in `IssuerRegistry`.
2. It proves control of its domain: DNS TXT `zkletter-issuer=<issuer object id>` and
   `https://<domain>/.well-known/zkletter.json` listing the same id. Admin checks this
   at approval; the verifier app re-checks it when showing the result.

The verifier always displays the issuer's registered name and domain. Users are taught
to trust the verifier result, never the paper.

### 4.2 Key management

- `IssuerCap` (owned object) authorises management of the issuer.
- `SignerCap`s are delegated, expiring, individually revocable capabilities for staff
  or systems that anchor batches. No single employee holds the master key.
- Issuer can rotate keys; all changes are events on-chain.

## 5. Letter format and commitment

### 5.1 Canonical record

Each letter type has a **template** that defines a typed set of `fields` (ref number,
recipient name/ID, date, title, key figures, deadline, ...). Canonicalization:

1. Fields encoded as JSON, keys sorted, per RFC 8785 (JCS).
2. Strings Unicode NFC, whitespace-trimmed and collapsed, dates ISO-8601, numbers as
   decimal strings.
3. `fields_digest = SHA-256(canonical_json)`.

For digital letters the issuer also produces the PDF. `file_digest = SHA-256(pdf bytes)`.

Rule for template authors: **everything substantive must be in the fields.** Text not
covered by the fields is only protected in digital (file) mode.

### 5.2 Commitments

For each letter the issuer samples a fresh 128-bit `salt` and creates two leaves:

```
leaf_fields = Poseidon(DOM_FIELDS, issuer_id, ref_no, fields_digest, salt)
leaf_file   = Poseidon(DOM_FILE,   issuer_id, ref_no, file_digest,   salt)   // digital only
```

Poseidon over BN254 is used for leaves and the tree so that v2 ZK circuits need no
migration (Sui provides `sui::poseidon`). Digests are split into field elements.
Domain separators (`DOM_*`) prevent cross-use of leaves.

### 5.3 Batching

The institution accumulates leaves and periodically builds a Poseidon Merkle tree
(depth 20, about one million letters per batch), then calls `anchor(root, count)`.
Only the root goes on-chain. Merkle paths are published to the indexer; a path alone
reveals nothing without the salt and content.

## 6. QR payload

The QR encodes a short HTTPS URL, with the secret in the fragment so it is never sent
to any server:

```
https://verify.zkletter.app/v1/<issuer_id>/<ref_no>#s=<salt>&k=<key_id>&m=<mode>
```

- `salt`: required to recompute the commitment.
- Merkle path and batch are fetched from the indexer by `(issuer_id, ref_no)`.
- A digital letter additionally embeds both leaves' metadata in the PDF.

## 7. Verification algorithm

Inputs: QR payload plus the letter content (fields from OCR/form, or the PDF file).

1. Parse QR; extract `issuer_id`, `ref_no`, `salt`.
2. Fetch `Issuer` from Sui; require status `Active`. Check the domain proof; display
   issuer name and domain.
3. Canonicalize the supplied content and compute the digest:
   - **Paper mode:** user confirms OCR-extracted fields; compute `fields_digest`.
   - **Digital mode:** hash the uploaded PDF; compute `file_digest`.
4. Recompute the leaf with the salt.
5. Fetch the Merkle path from the indexer; recompute the root.
6. Check that the root is an anchored batch of this issuer on Sui.
7. Check the leaf is not in the issuer's revocation table.
8. Verdict:
   - Valid: content matches an authentic record from the issuer.
   - Invalid content: root check failed (content or QR was altered or copied).
   - Revoked / issuer suspended / not found.

The verification runs in the client; the indexer is untrusted (everything it returns is
checked against Sui).

## 8. Threat model

| Threat | Result |
|---|---|
| QR copied onto a different letter | Fails at step 5: different content gives a different leaf |
| Content altered after issue | Fails the same way |
| Fake QR pointing at a look-alike institution | Fails at step 2: issuer not in registry or domain proof mismatch. Verdict always shows registered name and domain |
| Phishing verifier page | One canonical verifier domain; ship signed/open-source client; educate users to type or scan only that domain |
| Compromised staff member | Scoped, expiring `SignerCap`s; revoke the cap; revoke affected letters |
| Compromised institution key | Admin can suspend the issuer; rotation flow; all past anchors remain auditable |
| Faithful copy of a genuine letter, presented by the wrong person | Authentic content, so it verifies. Mitigations: recipient name/ID is a required field the relying party checks; expiry field; optional on-chain `consume(leaf)` for single-use documents; verifier service shows verification count |
| Free text not covered by fields (paper mode) | Template rule in 5.1: all substantive content must be in fields; otherwise only digital mode protects it |
| Salt leaks with the paper letter | Salt only lets someone check that exact content; it does not reveal content and cannot forge another letter |
| Brute-forcing content from the leaf | 128-bit salt makes guessing infeasible |
| Indexer lies or censors | Lies are detected (checked against Sui); censorship is mitigated by anyone being able to run an indexer from chain events plus issuer-published paths |
| Registry admin abuse | Multisig, timelock on approvals, public events; governance upgrade path in v3 |

## 9. On-chain design (Move)

Package `zkletter`:

- `registry`
  - `IssuerRegistry` (shared): `Table<ID, Issuer>`.
  - `Issuer`: name, domain, status (`Active | Suspended`), key info.
  - `AdminCap`; `approve_issuer`, `suspend_issuer`, `reinstate_issuer`.
  - Admin is a multisig address.
- `anchor`
  - `BatchAnchor` object per batch: `issuer_id`, `root`, `count`, `timestamp`, `seq`.
  - `anchor(&IssuerCap | &SignerCap, root, count)` emits `BatchAnchored`.
  - Only issuers with status `Active` can anchor.
- `revocation`
  - `Revocations` (shared, per issuer): `Table<leaf, RevocationInfo>`.
  - `revoke(cap, leaf, reason_code)`; `consume(cap, leaf)` for single-use.
- `signers`
  - `SignerCap { issuer_id, expires_at }`; `delegate`, `revoke_signer`.
- (v2) `verifier`
  - `sui::groth16` verification key per circuit; `verify_letter_proof(...)`.

Events are the source for indexers. No letter content or salts are ever on-chain.

## 10. Layered roadmap

### v1: Anchored provenance (no ZK)
Everything above. Deliberately simple and auditable.

### v2: Private verification (ZK, Groth16)
Two proofs only:

- **Circuit A (membership):** prove knowledge of `(fields_digest, salt, path)` such that
  the leaf is in an anchored root of issuer X. The verifier learns only "valid letter
  from X", not the leaf or `ref_no`.
- **Circuit B (field predicates):** extends A with statements about committed fields
  (date within a range, amount >= N, field equals a value) without revealing them.
  Fields are committed individually (per-field leaves under `fields_digest`) so a
  predicate can open one field without opening the rest.

Out of scope for ZK: a non-revocation proof. Revocation stays a plain on-chain
lookup (see caveat below).

- Browser proving with snarkjs WASM; on-chain check with `sui::groth16` (BN254).
- Needs a trusted setup (reuse Powers of Tau plus a phase-2 ceremony) and an audit.

Caveat: because revocation is a plain lookup keyed by leaf, a private (ZK) verification
cannot check it without revealing the leaf. In v2 the holder therefore either (a) accepts
a linkable revocation check, or (b) the issuer publishes a revocation root that a future
circuit can use. Decision deferred; see open questions.

### v3: Ecosystem
Seal-encrypted letter delivery via Walrus, zkLogin for recipients, governance for the
registry, multi-chain verifier SDKs.

## 11. Repo layout (planned)

```
contracts/        Sui Move package (registry, anchor, revocation, signers)
circuits/         circom circuits and ceremony notes (v2)
packages/sdk/     canonicalization, commitments, Merkle, QR encode/decode, verify
apps/issuer/      institution console (templates, batch issue, revoke)
apps/verify/      public verifier (scan QR, OCR, upload PDF, verdict)
services/indexer/ event indexer and Merkle-path API
docs/             this spec, threat model, runbooks
```

## 12. Milestones

1. **M0:** spec review, fix hash/field choices, set up toolchain (Sui CLI, Node, circom).
2. **M1:** `packages/sdk` (canonicalize, Poseidon commitments, Merkle, QR) with test
   vectors shared by TS and Move.
3. **M2:** Move package with unit tests; deploy to testnet.
4. **M3:** indexer plus verifier app (paper and digital modes).
5. **M4:** issuer console (template editor, bulk issue, QR/PDF generation, revoke).
6. **M5:** pilot with one institution; external review of the commitment scheme and
   contracts.
7. **M6+:** v2 circuits, trusted setup, audit, mainnet.

## 13. Open questions

1. Final template set for the pilot (admission, tax notices, official summons?).
2. Paper OCR vs. fully manual field entry for the first release.
3. Registry governance model after the pilot.
4. Whether to require `consume` semantics for specific letter types.
5. Hosting and operator of the canonical verifier domain.
6. How private (ZK) verification should handle revocation (see v2 caveat).
