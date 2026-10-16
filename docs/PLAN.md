# Zkletter: What We Are Building and How

Companion to `SPEC.md` (technical detail). This file is the plan.

## 1. What we are building

**Zkletter lets an institution issue official letters that anyone can verify as
authentic and from the expected source, without the letter's content being published.**

- **Issuers:** institutions only (ministries, universities, agencies). Individuals do not
  issue.
- **Letters:** official notices, mostly addressed to individuals.
- **Verifiers:** anyone, from a phone, with no wallet and no account.
- **Chain:** Sui. Only commitments (hashes) go on-chain, never content.

### The promise to a verifier

> This exact content was issued by institution X on date Y and has not been revoked.

### The attack we must beat

Copying a real QR code onto a fake letter. A QR alone proves nothing, so ours carries
a secret and the verifier must supply the letter's content. A different letter gives a
different hash and fails.

## 2. How it works (one page)

**Issue**
1. The institution fills a letter template (ref number, recipient, date, key facts).
2. The system canonicalizes it, adds a random salt, and computes a Poseidon commitment
   (a "leaf"). Digital letters also get a second leaf over the PDF bytes.
3. Leaves are batched into a Merkle tree and only the **root** is anchored on Sui,
   signed by the institution.
4. The letter is printed or sent with a QR: `issuer_id`, `ref_no`, `salt` (in the URL
   fragment, never sent to a server).

**Verify**
1. Scan the QR. The app loads the issuer from Sui and checks it is approved and its
   domain proof matches.
2. The verifier supplies the content (confirms OCR'd fields for paper, or uploads the
   PDF). The app recomputes the leaf and the Merkle root.
3. It checks the root is anchored by that issuer and the letter is not revoked.
4. Verdict: **Valid / Altered or copied / Revoked / Unknown issuer**, always showing the
   issuer's registered name and domain.

**Trust anchor:** the institution registry (admin multisig approval plus DNS and
`.well-known` domain proof). The verifier app, not the paper, is what users trust.

## 3. Scope

### Version 1: anchored provenance (no ZK)
Issuer registry, signer delegation, batch anchoring, revocation, SDK, indexer, public
verifier (paper and PDF modes), issuer console, one pilot institution.

### Version 2: private verification (ZK, Groth16 on Sui)
Exactly two proofs:
1. **Membership:** "this is a valid letter from institution X" without revealing which
   letter. Plan: this proof also covers not-revoked, which needs the issuer to publish a
   revocation root. (Decision pending, see section 7.)
2. **Field predicates:** prove a fact about a committed field (date within range,
   amount >= N) without revealing it. Needs per-field commitments.

### Not building
Individual issuers, open registration, content storage on-chain, a token, wallet
requirements for verifiers, other ZK features.

## 4. How we are building it

### Stack
| Layer | Choice |
|---|---|
| Chain / contracts | Sui, Move |
| Hashing | SHA-256 for documents; Poseidon (BN254) for leaves and tree |
| ZK (v2) | circom, snarkjs, Groth16, `sui::groth16` for on-chain verify |
| SDK | TypeScript (browser and Node) |
| Apps | Next.js, `@mysten/sui`, `@mysten/dapp-kit` |
| Indexer | Node service over Sui events plus a Postgres store |
| Optional later | Walrus (storage), Seal (encrypted delivery), zkLogin |

### Repo layout
```
contracts/        Move package: registry, anchor, revocation, signers
packages/sdk/     canonicalize, commitments, Merkle, QR, verify
apps/issuer/      institution console
apps/verify/      public verifier
services/indexer/ events and Merkle-path API
circuits/         v2 circuits and ceremony notes
docs/             SPEC.md, PLAN.md
```

### Engineering rules
- One set of **shared test vectors** (fields, salt, expected digests, leaves, roots)
  used by both the TypeScript SDK and the Move tests. This stops the two sides from
  drifting apart.
- The indexer is untrusted: the client re-verifies everything against Sui.
- Templates must put all substantive text in committed fields.
- Test and build on Sui testnet before any mainnet step. External review of the
  commitment scheme and contracts precedes mainnet.

## 5. Delivery plan

| Milestone | Outcome | Done when |
|---|---|---|
| **M0** Foundations | Toolchain, hash and field choices frozen, test vectors drafted | SPEC signed off |
| **M1** SDK | Canonicalize, commit, Merkle, QR encode/decode | Vectors pass; tamper tests fail as expected |
| **M2** Contracts | Registry, anchor, revoke, signers, with Move tests | Deployed to testnet; vectors match SDK |
| **M3** Indexer and verifier | Scan, OCR/confirm or upload, verdict screen | A forged QR-on-fake-letter is rejected end to end |
| **M4** Issuer console | Templates, bulk issue, QR/PDF output, revoke | Issue and revoke 10k letters in a batch |
| **M5** Pilot | One real institution issues real notices | Feedback incorporated; security review done |
| **M6** ZK (v2) | Membership and predicate circuits, trusted setup, audit | Private verification works in-browser in acceptable time |
| **M7** Mainnet | Launch with audited contracts and circuits | Audit findings closed |

Critical path: M1 -> M2 -> M3. The pilot (M5) is the gate before investing in ZK.

## 6. Risks and how we handle them

| Risk | Handling |
|---|---|
| Fake institution | Curated registry plus domain proof; verifier always shows name and domain |
| Paper OCR errors change the hash | Short, typed, OCR-friendly fields; user confirms before hashing |
| Faithful copy of a real letter | Recipient-ID field, expiry, optional single-use `consume`, verification count |
| Phishing verifier site | One canonical domain; open-source client |
| Key compromise | Scoped, expiring signer caps; suspend and rotate |
| Groth16 trusted setup and proving cost | Reuse Powers of Tau, run a phase-2 ceremony, keep circuits small, hash documents off-circuit |
| Admin abuse | Multisig, public events, timelock; governance upgrade later |

## 7. Decisions still needed

1. **Revocation under ZK:** recommend the issuer publishes a revocation root and the
   membership proof also proves non-revocation. The alternative is a linkable lookup.
2. **Pilot institution** and first letter template.
3. **Paper input:** OCR plus confirm, or manual entry, for the first release.
4. **Registry governance** after the pilot.
5. **Who operates** the canonical verifier domain.

## 8. Immediate next step

Start M1: scaffold `packages/sdk`, write the canonicalization and commitment code, and
produce the shared test vectors.
