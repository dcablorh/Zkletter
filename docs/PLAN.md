# Zkletter: Plan (ZK-first)

Companion to `SPEC.md`. This is what we are building and how.

## 1. What we are building

Zkletter is a **showcase of zero-knowledge proofs solving a real problem**: fake official
letters. An institution issues a letter. Anyone holding it can prove, with a ZK proof
checked on Sui, that:

> "This is a genuine, un-revoked letter from institution X" (and optionally a fact
> about it, such as "dated within 2026"), **without revealing the letter or which
> letter it is.**

There is no non-ZK verification path. The proof is the verification. That is the point
of the project, and the app should make the mechanics visible to people watching.

## 2. The two proofs

1. **Letter-valid proof.** In zero knowledge, the holder shows that they know a letter
   (content plus a secret salt) whose commitment sits in a Merkle tree that the
   institution anchored on Sui, **and** that the letter is not revoked in the issuer's
   status tree. Public: issuer, the two roots, a verifier-chosen context. Private:
   everything else, including which leaf.
2. **Field-predicate proof.** The same statement plus a claim about committed fields,
   for example `date in [2026-01-01, 2026-12-31]`, `amount >= 1000`, or
   `recipient_id == hash(my id)`, without revealing the field values.

## 3. How it works

**Issue (institution)**
1. Fill a letter template. Each field becomes a field element (dates and amounts as
   integers, text as a hash-to-field).
2. `fields_commit = Poseidon(f1..f8)`; `leaf = Poseidon(DOM, issuer_id, ref_no,
   fields_commit, salt)`.
3. Put the leaf in the batch's **letters tree** and a `0` in the parallel **status tree**
   (same index). Anchor both roots on Sui. The letter gets a QR carrying the salt and
   position (in the URL fragment, never sent to a server).

**Prove (holder, in the browser)**
1. Scan the QR; the app asks for or OCRs the letter's fields and fetches the Merkle
   paths for the leaf.
2. snarkjs generates a Groth16 proof locally. Nothing private leaves the device.
3. The app outputs a short proof link or QR (about 300 bytes) with the public inputs.

**Verify (anyone)**
1. Open the proof. The app calls the Move `verifier` module, which runs
   `sui::groth16` on-chain, and checks the roots against the anchor book and the
   issuer against the registry.
2. Verdict: **Valid proof from X / Invalid / Unknown issuer or stale root**, always
   showing the issuer's registered name and domain.

**Why a copied QR fails.** The QR holds only the salt and position. To prove anything the
prover needs content that hashes to a leaf in the tree. A fake letter has no such leaf,
so no valid proof exists.

**Why a replayed proof is limited.** A `context` (verifier nonce or session id) is a
public input, so a proof made for one verifier is useless for another.

## 4. The showcase layer

The app has an "Under the hood" view:
- Splits each screen into **private inputs** (stay in the browser), **public inputs**
  and the **proof** (about 128 bytes).
- Shows proving time and the on-chain verification transaction.
- A "try to cheat" button: tamper a field or use a stolen QR on a fake letter and show
  that no proof can be generated.

## 5. Stack

| Layer | Choice |
|---|---|
| Chain | Sui, Move, `sui::groth16` (BN254) |
| Circuits | circom 2, snarkjs (Groth16), circomlib Poseidon and comparators |
| SDK | TypeScript: field encoding, commitments, trees, witness builder, proof helpers |
| Apps | Next.js: issuer console, holder prover, verifier page, explainer |
| Indexer | Node service over Sui events: Merkle paths for letters and status trees |
| Trusted setup | snarkjs dev ceremony for the demo; a real multi-party ceremony before production |

Already built and reused: the institution registry, signer delegation, batch anchoring
(contracts), and Poseidon commitments and Merkle trees (SDK). To change: see section 7.

## 6. Delivery plan

| Milestone | Outcome | Done when |
|---|---|---|
| **Z0** Spec | ZK-first design agreed | This plan and SPEC accepted |
| **Z1** SDK v2 | Field-element encoding, new leaf, letters and status trees, witness builder | Tests pass; test vectors exported |
| **Z2** Circuits | `letter_valid`, then `letter_predicates`; dev trusted setup | Local prove and verify with snarkjs; tampered input cannot prove |
| **Z3** Contracts | Anchor stores both roots; status-root updates; `verifier` module with VK | Move tests pass; on-chain verification of a real snarkjs proof on testnet |
| **Z4** Apps | Issuer console, holder prover, verifier page, explainer | End-to-end demo: issue, prove, verify, cheat attempt fails |
| **Z5** Demo and hardening | Deploy to testnet, review of circuits and contracts, README | Demo script rehearsed |

Critical path: Z1 -> Z2 -> Z3. The riskiest step is Z3: converting snarkjs proofs and
verification keys to the byte format Sui expects.

## 7. Changes to what we already built

- **SDK:** replace the SHA-256 `fields_digest` with `Poseidon(f1..f8)` over typed field
  elements, so circuits can open individual fields. Keep SHA-256/QR/canonical helpers
  where they still help. Add status tree and witness generation.
- **Contracts:** `revocation` no longer exposes a per-letter lookup (it would reveal
  which letter is checked). It becomes a per-batch **status root** the issuer updates.
  `anchor` stores `(letters_root, status_root)` per batch. New `verifier` module.
- **Docs:** SPEC rewritten (done with this plan).

## 8. Risks

| Risk | Handling |
|---|---|
| snarkjs to Sui byte-format conversion | Do it first in Z3 with a tiny circuit; test against the Sui verifier |
| Browser proving too slow | Depth-20 trees and 8 fields keep it to a few seconds; hash text off-circuit |
| Trusted setup | Dev ceremony clearly labelled as demo-only |
| Fake institution | Admin-approved registry plus domain proof; verdict always shows name and domain |
| Faithful copy of a genuine letter | Proof can be bound to the holder with a recipient-id predicate and a context |
| Status root freshness | Verifier requires the latest status root; stale proofs are rejected |

## 9. Next step

Z1: rework the SDK commitment scheme, then Z2: write the `letter_valid` circuit.
