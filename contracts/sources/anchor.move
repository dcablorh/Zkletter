/// Batch anchoring: an issuer publishes the Merkle root of a batch of letter commitments.
/// Only roots go on-chain; no content, salts or leaves.
module zkletter::anchor;

use sui::clock::Clock;
use sui::event;
use sui::table::{Self, Table};
use zkletter::registry::{Self, IssuerRegistry, IssuerCap, SignerCap};

const EAlreadyAnchored: u64 = 1;
const EInvalidRoot: u64 = 2;
const EInvalidCount: u64 = 3;

/// BN254 scalar field modulus. Roots are Poseidon outputs, so must be below it.
const FIELD_P: u256 =
    21888242871839275222246405745257275088548364400416034343698204186575808495617;
/// Tree depth 20.
const MAX_BATCH: u64 = 1_048_576;

public struct AnchorBook has key {
    id: UID,
    anchors: Table<AnchorKey, AnchorInfo>,
    next_seq: Table<ID, u64>,
}

public struct AnchorKey has copy, drop, store {
    issuer_id: ID,
    root: u256,
}

public struct AnchorInfo has copy, drop, store {
    count: u64,
    seq: u64,
    anchored_at_ms: u64,
}

public struct BatchAnchored has copy, drop {
    issuer_id: ID,
    root: u256,
    count: u64,
    seq: u64,
    anchored_at_ms: u64,
    sender: address,
}

fun init(ctx: &mut TxContext) {
    transfer::share_object(AnchorBook {
        id: object::new(ctx),
        anchors: table::new(ctx),
        next_seq: table::new(ctx),
    });
}

public fun anchor_with_cap(
    cap: &IssuerCap,
    reg: &IssuerRegistry,
    book: &mut AnchorBook,
    root: u256,
    count: u64,
    clock: &Clock,
    ctx: &TxContext,
) {
    let issuer_id = registry::authorize_cap(reg, cap);
    record(book, issuer_id, root, count, clock, ctx);
}

public fun anchor_with_signer(
    signer: &SignerCap,
    reg: &IssuerRegistry,
    book: &mut AnchorBook,
    root: u256,
    count: u64,
    clock: &Clock,
    ctx: &TxContext,
) {
    let issuer_id = registry::authorize_signer(reg, signer, clock);
    record(book, issuer_id, root, count, clock, ctx);
}

fun record(
    book: &mut AnchorBook,
    issuer_id: ID,
    root: u256,
    count: u64,
    clock: &Clock,
    ctx: &TxContext,
) {
    assert!(root > 0 && root < FIELD_P, EInvalidRoot);
    assert!(count > 0 && count <= MAX_BATCH, EInvalidCount);
    let key = AnchorKey { issuer_id, root };
    assert!(!book.anchors.contains(key), EAlreadyAnchored);

    if (!book.next_seq.contains(issuer_id)) book.next_seq.add(issuer_id, 0);
    let seq_ref = book.next_seq.borrow_mut(issuer_id);
    let seq = *seq_ref;
    *seq_ref = seq + 1;

    let now = clock.timestamp_ms();
    book.anchors.add(key, AnchorInfo { count, seq, anchored_at_ms: now });
    event::emit(BatchAnchored {
        issuer_id,
        root,
        count,
        seq,
        anchored_at_ms: now,
        sender: ctx.sender(),
    });
}

/// Verifiers: was `root` anchored by `issuer_id`?
public fun is_anchored(book: &AnchorBook, issuer_id: ID, root: u256): bool {
    book.anchors.contains(AnchorKey { issuer_id, root })
}

public fun anchored_at_ms(book: &AnchorBook, issuer_id: ID, root: u256): u64 {
    book.anchors.borrow(AnchorKey { issuer_id, root }).anchored_at_ms
}

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) { init(ctx) }
