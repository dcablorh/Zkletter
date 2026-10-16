/// Institution registry: admin-approved issuers, issuer caps, delegated signers.
module zkletter::registry;

use std::string::String;
use sui::clock::Clock;
use sui::event;
use sui::table::{Self, Table};

// === Errors ===
const ENotFound: u64 = 1;
const ENotActive: u64 = 2;
const EStaleCap: u64 = 3;
const EExpired: u64 = 4;
const ERevokedSigner: u64 = 5;
const EWrongIssuer: u64 = 6;
const EBadExpiry: u64 = 7;
const EAlreadyStatus: u64 = 8;

// === Status ===
const STATUS_ACTIVE: u8 = 0;
const STATUS_SUSPENDED: u8 = 1;

// === Objects ===

/// Held by the registry admin (intended to be a multisig address).
public struct AdminCap has key, store { id: UID }

public struct IssuerRegistry has key {
    id: UID,
    issuers: Table<ID, Issuer>,
}

public struct Issuer has store {
    name: String,
    domain: String,
    status: u8,
    /// Bumped on rotation; invalidates older IssuerCaps and all SignerCaps.
    cap_version: u64,
    approved_at_ms: u64,
    revoked_signers: Table<ID, bool>,
}

/// Master capability of one institution. `issuer_id` is the stable id used in commitments.
public struct IssuerCap has key, store {
    id: UID,
    issuer_id: ID,
    cap_version: u64,
}

/// Delegated, expiring, individually revocable authority to anchor batches.
public struct SignerCap has key, store {
    id: UID,
    issuer_id: ID,
    cap_version: u64,
    expires_at_ms: u64,
}

// === Events ===
public struct IssuerApproved has copy, drop { issuer_id: ID, name: String, domain: String }
public struct IssuerSuspended has copy, drop { issuer_id: ID }
public struct IssuerReinstated has copy, drop { issuer_id: ID }
public struct IssuerCapRotated has copy, drop { issuer_id: ID, cap_version: u64 }
public struct SignerDelegated has copy, drop { issuer_id: ID, signer_id: ID, expires_at_ms: u64 }
public struct SignerRevoked has copy, drop { issuer_id: ID, signer_id: ID }

fun init(ctx: &mut TxContext) {
    transfer::transfer(AdminCap { id: object::new(ctx) }, ctx.sender());
    transfer::share_object(IssuerRegistry { id: object::new(ctx), issuers: table::new(ctx) });
}

// === Admin ===

/// Approve an institution. The returned cap should be sent to the institution's address.
public fun approve_issuer(
    _: &AdminCap,
    reg: &mut IssuerRegistry,
    name: String,
    domain: String,
    clock: &Clock,
    ctx: &mut TxContext,
): IssuerCap {
    // A fresh UID gives a unique, stable 32-byte issuer id.
    let uid = object::new(ctx);
    let issuer_id = uid.to_inner();
    uid.delete();
    reg.issuers.add(issuer_id, Issuer {
        name,
        domain,
        status: STATUS_ACTIVE,
        cap_version: 0,
        approved_at_ms: clock.timestamp_ms(),
        revoked_signers: table::new(ctx),
    });
    let issuer = reg.issuers.borrow(issuer_id);
    event::emit(IssuerApproved { issuer_id, name: issuer.name, domain: issuer.domain });
    IssuerCap { id: object::new(ctx), issuer_id, cap_version: 0 }
}

public fun approve_issuer_to(
    admin: &AdminCap,
    reg: &mut IssuerRegistry,
    name: String,
    domain: String,
    recipient: address,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let cap = approve_issuer(admin, reg, name, domain, clock, ctx);
    transfer::public_transfer(cap, recipient);
}

public fun suspend_issuer(_: &AdminCap, reg: &mut IssuerRegistry, issuer_id: ID) {
    let issuer = borrow_mut(reg, issuer_id);
    assert!(issuer.status == STATUS_ACTIVE, EAlreadyStatus);
    issuer.status = STATUS_SUSPENDED;
    event::emit(IssuerSuspended { issuer_id });
}

public fun reinstate_issuer(_: &AdminCap, reg: &mut IssuerRegistry, issuer_id: ID) {
    let issuer = borrow_mut(reg, issuer_id);
    assert!(issuer.status == STATUS_SUSPENDED, EAlreadyStatus);
    issuer.status = STATUS_ACTIVE;
    event::emit(IssuerReinstated { issuer_id });
}

/// Key rotation / compromise recovery: invalidates every previously issued
/// IssuerCap and SignerCap for this issuer and returns a fresh IssuerCap.
public fun rotate_cap(
    _: &AdminCap,
    reg: &mut IssuerRegistry,
    issuer_id: ID,
    ctx: &mut TxContext,
): IssuerCap {
    let issuer = borrow_mut(reg, issuer_id);
    issuer.cap_version = issuer.cap_version + 1;
    let cap_version = issuer.cap_version;
    event::emit(IssuerCapRotated { issuer_id, cap_version });
    IssuerCap { id: object::new(ctx), issuer_id, cap_version }
}

// === Issuer: delegation ===

public fun delegate_signer(
    cap: &IssuerCap,
    reg: &IssuerRegistry,
    expires_at_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext,
): SignerCap {
    let issuer_id = authorize_cap(reg, cap);
    assert!(expires_at_ms > clock.timestamp_ms(), EBadExpiry);
    let signer = SignerCap {
        id: object::new(ctx),
        issuer_id,
        cap_version: cap.cap_version,
        expires_at_ms,
    };
    event::emit(SignerDelegated { issuer_id, signer_id: object::id(&signer), expires_at_ms });
    signer
}

public fun revoke_signer(cap: &IssuerCap, reg: &mut IssuerRegistry, signer_id: ID) {
    let issuer_id = authorize_cap(reg, cap);
    let issuer = borrow_mut(reg, issuer_id);
    if (!issuer.revoked_signers.contains(signer_id)) {
        issuer.revoked_signers.add(signer_id, true);
    };
    event::emit(SignerRevoked { issuer_id, signer_id });
}

// === Authorization (used by anchor / revocation) ===

/// Returns the issuer id if `cap` is current and the issuer is active.
public(package) fun authorize_cap(reg: &IssuerRegistry, cap: &IssuerCap): ID {
    let issuer = borrow(reg, cap.issuer_id);
    assert!(issuer.cap_version == cap.cap_version, EStaleCap);
    assert!(issuer.status == STATUS_ACTIVE, ENotActive);
    cap.issuer_id
}

/// Returns the issuer id if `signer` is current, unexpired, unrevoked and the issuer is active.
public(package) fun authorize_signer(reg: &IssuerRegistry, signer: &SignerCap, clock: &Clock): ID {
    let issuer = borrow(reg, signer.issuer_id);
    assert!(issuer.cap_version == signer.cap_version, EStaleCap);
    assert!(issuer.status == STATUS_ACTIVE, ENotActive);
    assert!(clock.timestamp_ms() < signer.expires_at_ms, EExpired);
    assert!(!issuer.revoked_signers.contains(object::id(signer)), ERevokedSigner);
    signer.issuer_id
}

// === Views ===

public fun issuer_exists(reg: &IssuerRegistry, issuer_id: ID): bool {
    reg.issuers.contains(issuer_id)
}

public fun is_active(reg: &IssuerRegistry, issuer_id: ID): bool {
    reg.issuers.contains(issuer_id) && reg.issuers.borrow(issuer_id).status == STATUS_ACTIVE
}

public fun issuer_name(reg: &IssuerRegistry, issuer_id: ID): String { borrow(reg, issuer_id).name }

public fun issuer_domain(reg: &IssuerRegistry, issuer_id: ID): String {
    borrow(reg, issuer_id).domain
}

public fun cap_issuer_id(cap: &IssuerCap): ID { cap.issuer_id }

public fun signer_issuer_id(signer: &SignerCap): ID { signer.issuer_id }

// === Internal ===

fun borrow(reg: &IssuerRegistry, issuer_id: ID): &Issuer {
    assert!(reg.issuers.contains(issuer_id), ENotFound);
    reg.issuers.borrow(issuer_id)
}

fun borrow_mut(reg: &mut IssuerRegistry, issuer_id: ID): &mut Issuer {
    assert!(reg.issuers.contains(issuer_id), ENotFound);
    reg.issuers.borrow_mut(issuer_id)
}

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) { init(ctx) }
