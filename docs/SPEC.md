# Zkletter: Design Spec (v0.2, ZK-first)

Institutions issue official letters; holders prove in zero knowledge that a letter is
genuine and un-revoked; Sui verifies the proof. Superseded: v0.1 (anchored provenance
with non-ZK verification) was dropped because the project's purpose is to show ZK at work.

## 1. Problem

Forged notices circulate because nobody can tell who issued a document or whether it was
altered. A QR code or logo can be copied onto a fake.

## 2. Goals and non-goals

Goals
- Verification is a ZK proof checked by `sui::groth16`. No verification path reveals the
  letter or which letter it is.
- A QR copied onto a different letter cannot produce a valid proof.
- Revocation is respected inside the proof.
- Field predicates (date range, threshold, equality) can be proven without revealing the
  field.
- Institutions issue in batches; only roots go on-chain.
- The app teaches: it shows private vs public inputs, proof size and the on-chain check.

Non-goals
- Judging whether an institution is legitimate beyond the curated registry.
- Stopping a genuine letter's rightful holder from proving it (that is the feature).
- Production-grade trusted setup (the demo uses a dev ceremony).

## 3. Actors

| Actor | Role |
|---|---|
| Registry admin (multisig) | Approves, suspends, reinstates institutions |
| Institution | Issues letters, anchors batches, updates status roots |
| Holder | Has the letter and QR; generates proofs in the browser |
| Verifier | Receives a proof link; checks it on Sui |
| Indexer | Serves Merkle paths; untrusted, everything is checked against Sui |

Institution trust anchor: an admin-approved `Issuer` in `IssuerRegistry` plus a domain
proof (DNS TXT `zkletter-issuer=<id>` and `/.well-known/zkletter.json`). The verifier
app always displays the issuer's registered name and domain.

## 4. Data model

### 4.1 Field encoding
A template defines up to 8 ordered field slots. Each value becomes a BN254 field element:
- integers and dates (as `YYYYMMDD`): the integer itself (enables range proofs),
- text and identifiers: `SHA-256(NFC(trim(value))) mod p` (enables equality proofs),
- unused slots: 0.

`fields_commit = Poseidon(f1, ..., f8)`.

### 4.2 Leaf
```
leaf = Poseidon(DOM_LEAF, issuer_hi, issuer_lo, ref_field, fields_commit, salt)
```
`salt` is a fresh 128-bit random value. `issuer_hi/lo` split the 32-byte issuer id into two
128-bit field elements. `ref_field = SHA-256(ref_no) mod p`.

### 4.3 Trees (per batch, depth 20, Poseidon, `node = Poseidon(DOM_NODE, l, r)`)
- **Letters tree:** leaves are letter leaves.
- **Status tree:** same positions; leaf value `0` = active, `1` = revoked, `2` = consumed.
  The issuer updates it and anchors the new status root when it revokes.

Zero subtrees pad both trees. Merkle paths are public data and reveal nothing without the
salt and content.

### 4.4 QR payload
```
https://verify.zkletter.app/v1/<issuer_id>/<ref_no>#s=<salt>&i=<index>&b=<batch_seq>
```
The salt stays in the fragment and is never sent to a server.

## 5. Circuits (circom 2, Groth16, BN254)

### 5.1 `letter_valid`
- Private: `f[8]`, `salt`, `ref_field`, `index` bits, `letters_path[20]`, `status_path[20]`.
- Public: `issuer_hi`, `issuer_lo`, `letters_root`, `status_root`, `context`.
- Constraints:
  1. `fields_commit = Poseidon(f)`.
  2. `leaf = Poseidon(DOM_LEAF, issuer_hi, issuer_lo, ref_field, fields_commit, salt)`.
  3. `MerkleRoot(leaf, index, letters_path) == letters_root`.
  4. `MerkleRoot(0, index, status_path) == status_root` (status is active).
- `context` is a verifier nonce; it is constrained (squared) so it is bound to the proof.

### 5.2 `letter_predicates`
`letter_valid` plus a predicate selector over named slots, with public parameters:
- `range`: `lo <= f[k] <= hi` (circomlib `LessEqThan`, 32 bits for dates and amounts),
- `eq`: `f[k] == public_value` (for hashed identifiers),
- `ge`: `f[k] >= threshold`.

Public outputs add the predicate parameters; the field values stay private.

### 5.3 Setup
Powers of Tau (reuse a public ptau file) plus a per-circuit phase 2 contribution. The demo
uses a single-party dev setup, labelled as such in the UI. Production needs a multi-party
ceremony and an audit.

## 6. Sui contracts (Move)

- `registry` (built): issuers, `AdminCap`, `IssuerCap`, `SignerCap` with expiry and
  revocation, cap rotation.
- `anchor` (to change): per `(issuer, seq)` record `{ letters_root, status_root, count,
  anchored_at }`; `update_status_root(cap, seq, new_status_root)` for revocation. Latest
  status root per batch is the only acceptable one for verification.
- `revocation` (to change): replaced by status-root updates; no per-letter lookup.
- `verifier` (new): stores the verifying keys; `verify_letter_valid(...)` and
  `verify_predicates(...)` call `sui::groth16`, check that the issuer is active, the
  letters root is anchored and the status root is the batch's current one, then emit
  `LetterProofVerified { issuer_id, context, kind }`.

Proof and verifying-key bytes must be converted from snarkjs JSON to the compressed
arkworks encoding Sui expects (public inputs are 32-byte little-endian field elements).

## 7. Flows

**Issue.** Institution fills template, SDK builds leaf, batch trees are built, `anchor`
records both roots, QR/PDF generated per letter.

**Prove.** Holder opens the QR, supplies the letter's field values (typed or OCR and
confirmed), the app fetches paths from the indexer, snarkjs WASM proves locally, the app
produces a proof link: `{ kind, proof, public_inputs }`.

**Verify.** The verifier page submits the proof to the `verifier` module (or simulates the
call). On success it shows issuer name and domain, the verified predicate, and the
transaction digest.

**Revoke.** The institution flips a status leaf to `1`, recomputes the status root and calls
`update_status_root`. Older proofs against the stale status root stop verifying.

## 8. Threat model

| Threat | Result |
|---|---|
| QR copied onto a fake letter | Prover cannot satisfy the circuit; no proof exists |
| Altered field values | Different `fields_commit`, leaf not in tree, no proof |
| Proof replayed to another verifier | `context` public input binds it to one verifier |
| Proof for a revoked letter | Status leaf non-zero, no proof; stale status roots rejected on-chain |
| Fake institution | Not in registry or domain mismatch; verdict shows registered name and domain |
| Compromised staff key | Scoped, expiring, revocable `SignerCap`; rotate to invalidate all caps |
| Compromised institution key | Admin suspends issuer; rotation; anchors stay auditable |
| Indexer lies | Paths that don't hash to an anchored root fail in the circuit |
| Faithful copy shown by a different person | Provable only by someone who knows the content and salt; bind with a recipient-id predicate and `context` |
| Malicious trusted setup | Demo-only setup labelled; multi-party ceremony before production |
| Phishing verifier site | Single canonical domain; the proof check is on-chain and reproducible |

## 9. Repo layout

```
contracts/        Move: registry, anchor, verifier
circuits/         circom: letter_valid, letter_predicates, setup scripts
packages/sdk/     encoding, commitments, trees, witness builder, proof/VK converters
apps/web/         issuer console, holder prover, verifier, "Under the hood" explainer
services/indexer/ Merkle path API over Sui events
docs/             SPEC.md, PLAN.md
```

## 10. Milestones

Z0 spec; Z1 SDK v2; Z2 circuits and local proofs; Z3 contracts with on-chain
verification; Z4 apps; Z5 testnet demo and review. See `PLAN.md`.

## 11. Open questions

1. Final slot layout for the demo template (suggested: ref, recipient_id, issue_date,
   expiry_date, amount, category).
2. Paper input: typed fields or OCR plus confirm.
3. Whether to ship a verifier-challenge flow (verifier shows a nonce QR) or a free
   `context` string for the demo.
4. Pilot institution, or a fictional one for the showcase.
