/// Revocation / consumption of individual letters, keyed by (issuer, leaf).
/// Keying by issuer stops one institution from pre-revoking another's leaves.
module zkletter::revocation;

use sui::clock::Clock;
use sui::event;
use sui::table::{Self, Table};
use zkletter::registry::{Self, IssuerRegistry, IssuerCap, SignerCap};

const EAlreadyMarked: u64 = 1;

const KIND_REVOKED: u8 = 0;
const KIND_CONSUMED: u8 = 1;

public struct RevocationBook has key {
    id: UID,
    entries: Table<LeafKey, Entry>,
}

public struct LeafKey has copy, drop, store {
    issuer_id: ID,
    leaf: u256,
}

public struct Entry has copy, drop, store {
    kind: u8,
    /// Issuer-defined reason code (e.g. 1 = issued in error, 2 = superseded, 3 = withdrawn).
    reason_code: u8,
    at_ms: u64,
}

public struct LetterRevoked has copy, drop {
    issuer_id: ID,
    leaf: u256,
    reason_code: u8,
    at_ms: u64,
}

public struct LetterConsumed has copy, drop {
    issuer_id: ID,
    leaf: u256,
    at_ms: u64,
}

fun init(ctx: &mut TxContext) {
    transfer::share_object(RevocationBook { id: object::new(ctx), entries: table::new(ctx) });
}

public fun revoke_with_cap(
    cap: &IssuerCap,
    reg: &IssuerRegistry,
    book: &mut RevocationBook,
    leaf: u256,
    reason_code: u8,
    clock: &Clock,
) {
    let issuer_id = registry::authorize_cap(reg, cap);
    mark(book, issuer_id, leaf, KIND_REVOKED, reason_code, clock);
}

public fun revoke_with_signer(
    signer: &SignerCap,
    reg: &IssuerRegistry,
    book: &mut RevocationBook,
    leaf: u256,
    reason_code: u8,
    clock: &Clock,
) {
    let issuer_id = registry::authorize_signer(reg, signer, clock);
    mark(book, issuer_id, leaf, KIND_REVOKED, reason_code, clock);
}

/// Mark a single-use letter as used.
public fun consume_with_cap(
    cap: &IssuerCap,
    reg: &IssuerRegistry,
    book: &mut RevocationBook,
    leaf: u256,
    clock: &Clock,
) {
    let issuer_id = registry::authorize_cap(reg, cap);
    mark(book, issuer_id, leaf, KIND_CONSUMED, 0, clock);
}

public fun consume_with_signer(
    signer: &SignerCap,
    reg: &IssuerRegistry,
    book: &mut RevocationBook,
    leaf: u256,
    clock: &Clock,
) {
    let issuer_id = registry::authorize_signer(reg, signer, clock);
    mark(book, issuer_id, leaf, KIND_CONSUMED, 0, clock);
}

fun mark(
    book: &mut RevocationBook,
    issuer_id: ID,
    leaf: u256,
    kind: u8,
    reason_code: u8,
    clock: &Clock,
) {
    let key = LeafKey { issuer_id, leaf };
    assert!(!book.entries.contains(key), EAlreadyMarked);
    let at_ms = clock.timestamp_ms();
    book.entries.add(key, Entry { kind, reason_code, at_ms });
    if (kind == KIND_REVOKED) {
        event::emit(LetterRevoked { issuer_id, leaf, reason_code, at_ms });
    } else {
        event::emit(LetterConsumed { issuer_id, leaf, at_ms });
    };
}

public fun is_revoked(book: &RevocationBook, issuer_id: ID, leaf: u256): bool {
    let key = LeafKey { issuer_id, leaf };
    book.entries.contains(key) && book.entries.borrow(key).kind == KIND_REVOKED
}

public fun is_consumed(book: &RevocationBook, issuer_id: ID, leaf: u256): bool {
    let key = LeafKey { issuer_id, leaf };
    book.entries.contains(key) && book.entries.borrow(key).kind == KIND_CONSUMED
}

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) { init(ctx) }
