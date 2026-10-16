#[test_only]
module zkletter::zkletter_tests;

use std::string;
use sui::clock::{Self, Clock};
use sui::test_scenario::{Self as ts, Scenario};
use zkletter::anchor::{Self, AnchorBook};
use zkletter::registry::{Self, AdminCap, IssuerRegistry, IssuerCap, SignerCap};
use zkletter::revocation::{Self, RevocationBook};

const ADMIN: address = @0xA;
const INST: address = @0xB;
const ROOT: u256 = 12345;

fun setup(): (Scenario, Clock) {
    let mut s = ts::begin(ADMIN);
    registry::init_for_testing(s.ctx());
    anchor::init_for_testing(s.ctx());
    revocation::init_for_testing(s.ctx());
    s.next_tx(ADMIN);
    let clock = clock::create_for_testing(s.ctx());
    let admin = s.take_from_sender<AdminCap>();
    let mut reg = s.take_shared<IssuerRegistry>();
    registry::approve_issuer_to(
        &admin,
        &mut reg,
        string::utf8(b"Ministry of Health"),
        string::utf8(b"moh.gov.example"),
        INST,
        &clock,
        s.ctx(),
    );
    ts::return_shared(reg);
    s.return_to_sender(admin);
    s.next_tx(INST);
    (s, clock)
}

#[test]
fun anchor_with_cap_works() {
    let (mut s, clock) = setup();
    let cap = s.take_from_sender<IssuerCap>();
    let reg = s.take_shared<IssuerRegistry>();
    let mut book = s.take_shared<AnchorBook>();
    let id = registry::cap_issuer_id(&cap);

    anchor::anchor_with_cap(&cap, &reg, &mut book, ROOT, 3, &clock, s.ctx());
    assert!(anchor::is_anchored(&book, id, ROOT));
    assert!(!anchor::is_anchored(&book, id, ROOT + 1));
    assert!(registry::is_active(&reg, id));

    ts::return_shared(book);
    ts::return_shared(reg);
    s.return_to_sender(cap);
    clock.destroy_for_testing();
    s.end();
}

#[test, expected_failure(abort_code = zkletter::anchor::EAlreadyAnchored)]
fun duplicate_root_aborts() {
    let (mut s, clock) = setup();
    let cap = s.take_from_sender<IssuerCap>();
    let reg = s.take_shared<IssuerRegistry>();
    let mut book = s.take_shared<AnchorBook>();
    anchor::anchor_with_cap(&cap, &reg, &mut book, ROOT, 3, &clock, s.ctx());
    anchor::anchor_with_cap(&cap, &reg, &mut book, ROOT, 3, &clock, s.ctx());
    abort 99
}

#[test, expected_failure(abort_code = zkletter::anchor::EInvalidRoot)]
fun root_outside_field_aborts() {
    let (mut s, clock) = setup();
    let cap = s.take_from_sender<IssuerCap>();
    let reg = s.take_shared<IssuerRegistry>();
    let mut book = s.take_shared<AnchorBook>();
    let too_big: u256 =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    anchor::anchor_with_cap(&cap, &reg, &mut book, too_big, 3, &clock, s.ctx());
    abort 99
}

#[test, expected_failure(abort_code = zkletter::registry::ENotActive)]
fun suspended_issuer_cannot_anchor() {
    let (mut s, clock) = setup();
    let cap = s.take_from_sender<IssuerCap>();
    let id = registry::cap_issuer_id(&cap);

    s.next_tx(ADMIN);
    let admin = s.take_from_sender<AdminCap>();
    let mut reg = s.take_shared<IssuerRegistry>();
    registry::suspend_issuer(&admin, &mut reg, id);
    assert!(!registry::is_active(&reg, id));
    let mut book = s.take_shared<AnchorBook>();

    anchor::anchor_with_cap(&cap, &reg, &mut book, ROOT, 3, &clock, s.ctx());
    abort 99
}

#[test]
fun signer_can_anchor_then_expires() {
    let (mut s, mut clock) = setup();
    let cap = s.take_from_sender<IssuerCap>();
    let mut reg = s.take_shared<IssuerRegistry>();
    let mut book = s.take_shared<AnchorBook>();
    let id = registry::cap_issuer_id(&cap);

    let signer = registry::delegate_signer(&cap, &reg, 1000, &clock, s.ctx());
    anchor::anchor_with_signer(&signer, &reg, &mut book, ROOT, 5, &clock, s.ctx());
    assert!(anchor::is_anchored(&book, id, ROOT));
    assert!(registry::signer_issuer_id(&signer) == id);

    // Revoking a signer is idempotent.
    registry::revoke_signer(&cap, &mut reg, object::id(&signer));
    registry::revoke_signer(&cap, &mut reg, object::id(&signer));
    clock.set_for_testing(2000);

    transfer::public_transfer(signer, INST);
    ts::return_shared(book);
    ts::return_shared(reg);
    s.return_to_sender(cap);
    clock.destroy_for_testing();
    s.end();
}

#[test, expected_failure(abort_code = zkletter::registry::EExpired)]
fun expired_signer_aborts() {
    let (mut s, mut clock) = setup();
    let cap = s.take_from_sender<IssuerCap>();
    let reg = s.take_shared<IssuerRegistry>();
    let mut book = s.take_shared<AnchorBook>();
    let signer = registry::delegate_signer(&cap, &reg, 1000, &clock, s.ctx());
    clock.set_for_testing(1000);
    anchor::anchor_with_signer(&signer, &reg, &mut book, ROOT, 5, &clock, s.ctx());
    abort 99
}

#[test, expected_failure(abort_code = zkletter::registry::ERevokedSigner)]
fun revoked_signer_aborts() {
    let (mut s, clock) = setup();
    let cap = s.take_from_sender<IssuerCap>();
    let mut reg = s.take_shared<IssuerRegistry>();
    let mut book = s.take_shared<AnchorBook>();
    let signer = registry::delegate_signer(&cap, &reg, 1000, &clock, s.ctx());
    registry::revoke_signer(&cap, &mut reg, object::id(&signer));
    anchor::anchor_with_signer(&signer, &reg, &mut book, ROOT, 5, &clock, s.ctx());
    abort 99
}

#[test, expected_failure(abort_code = zkletter::registry::EStaleCap)]
fun rotation_invalidates_old_cap_and_signers() {
    let (mut s, clock) = setup();
    let old_cap = s.take_from_sender<IssuerCap>();
    let id = registry::cap_issuer_id(&old_cap);

    s.next_tx(ADMIN);
    let admin = s.take_from_sender<AdminCap>();
    let mut reg = s.take_shared<IssuerRegistry>();
    let new_cap = registry::rotate_cap(&admin, &mut reg, id, s.ctx());
    // New cap works.
    let mut book = s.take_shared<AnchorBook>();
    anchor::anchor_with_cap(&new_cap, &reg, &mut book, ROOT, 1, &clock, s.ctx());
    // Old cap is stale.
    anchor::anchor_with_cap(&old_cap, &reg, &mut book, ROOT + 1, 1, &clock, s.ctx());
    abort 99
}

#[test]
fun revoke_and_consume() {
    let (mut s, clock) = setup();
    let cap = s.take_from_sender<IssuerCap>();
    let reg = s.take_shared<IssuerRegistry>();
    let mut rev = s.take_shared<RevocationBook>();
    let id = registry::cap_issuer_id(&cap);

    assert!(!revocation::is_revoked(&rev, id, 7));
    revocation::revoke_with_cap(&cap, &reg, &mut rev, 7, 1, &clock);
    assert!(revocation::is_revoked(&rev, id, 7));
    assert!(!revocation::is_consumed(&rev, id, 7));

    revocation::consume_with_cap(&cap, &reg, &mut rev, 8, &clock);
    assert!(revocation::is_consumed(&rev, id, 8));
    assert!(!revocation::is_revoked(&rev, id, 8));

    ts::return_shared(rev);
    ts::return_shared(reg);
    s.return_to_sender(cap);
    clock.destroy_for_testing();
    s.end();
}

#[test, expected_failure(abort_code = zkletter::revocation::EAlreadyMarked)]
fun double_revoke_aborts() {
    let (mut s, clock) = setup();
    let cap = s.take_from_sender<IssuerCap>();
    let reg = s.take_shared<IssuerRegistry>();
    let mut rev = s.take_shared<RevocationBook>();
    revocation::revoke_with_cap(&cap, &reg, &mut rev, 7, 1, &clock);
    revocation::revoke_with_cap(&cap, &reg, &mut rev, 7, 1, &clock);
    abort 99
}
