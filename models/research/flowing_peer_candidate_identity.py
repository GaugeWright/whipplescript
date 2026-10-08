#!/usr/bin/env python3
"""Bounded FB-6 counterexample: a carried line is not a unit roster.

Run: python3 models/research/flowing_peer_candidate_identity.py

The v1 carrier commits to manifests and file bytes. Its sender cut IDs and
change IDs are advisory. This model holds those bytes fixed while varying the
peer, source unit, custody epoch, and Hold. It asks whether a Home could admit
the returned line from its carriage digest alone. The answer is no: distinct
work obligations produce the same carriage header.

The safe predicate models the additional facts an authenticated review
revision and final gate would have to bind and recheck. It deliberately keeps
the peer's claimed identity separate from the transport-authenticated peer,
and reads Hold from current Home authority rather than from peer input.
Neither the carrier nor this model implements those proofs or a production
admission route.
"""

from dataclasses import dataclass, replace
from itertools import product


SENT_BASE = "sha256:home-sent-base"
RETURNED_STEP = (("method.whip", "content:unchanged-by-unit-identity"),)
FILE_DIGEST = (("content:unchanged-by-unit-identity", "sha256:file-bytes"),)


@dataclass(frozen=True)
class Carrier:
    kind: str = "peer_line"
    base: str = SENT_BASE
    steps: tuple = (RETURNED_STEP,)
    file_digests: tuple = FILE_DIGEST

    def identity(self) -> tuple:
        # Represents the canonical header's identity-bearing fields. The
        # actual wire codec and SHA-256 are exercised by cut_carriage tests.
        return self.kind, self.base, self.steps, self.file_digests


@dataclass(frozen=True)
class PeerWork:
    peer: str
    unit: str
    custody_epoch: int
    carrier: Carrier = Carrier()


@dataclass(frozen=True)
class HomeAuthority:
    assigned_peer: str
    authorized_units: frozenset[str]
    custody_epoch: int
    held_units: frozenset[str]


@dataclass(frozen=True)
class ReviewRevision:
    carrier_identity: tuple
    sent_base: str
    peer: str
    unit: str
    custody_epoch: int
    gate_base: str


def prepare(work: PeerWork, trunk: str) -> ReviewRevision:
    return ReviewRevision(
        carrier_identity=work.carrier.identity(),
        sent_base=work.carrier.base,
        peer=work.peer,
        unit=work.unit,
        custody_epoch=work.custody_epoch,
        gate_base=trunk,
    )


def digest_only_admits(work: PeerWork, review: ReviewRevision, trunk: str) -> bool:
    return (
        work.carrier.identity() == review.carrier_identity
        and work.carrier.base == review.sent_base
        and trunk == review.gate_base
    )


def bound_admits(
    work: PeerWork,
    review: ReviewRevision,
    trunk: str,
    authenticated_peer: str,
    home: HomeAuthority,
) -> bool:
    return (
        digest_only_admits(work, review, trunk)
        and work.peer == review.peer == authenticated_peer == home.assigned_peer
        and work.unit == review.unit
        and work.unit in home.authorized_units
        and work.custody_epoch == review.custody_epoch == home.custody_epoch
        and work.unit not in home.held_units
    )


def main() -> None:
    good = PeerWork(peer="assigned-peer", unit="unit-a", custody_epoch=7)
    review = prepare(good, trunk="trunk-7")
    home = HomeAuthority("assigned-peer", frozenset({"unit-a"}), 7, frozenset())
    assert bound_admits(good, review, "trunk-7", "assigned-peer", home)

    variants = [
        (PeerWork(peer, unit, epoch), authenticated_peer, held)
        for peer, authenticated_peer, unit, epoch, held in product(
            ("assigned-peer", "other-peer"),
            ("assigned-peer", "other-peer"),
            ("unit-a", "unit-b"),
            (7, 8),
            (False, True),
        )
    ]
    assert len(variants) == 32
    assert len({work.carrier.identity() for work, _, _ in variants}) == 1
    weak_false_accepts = [
        (work, authenticated_peer, held)
        for work, authenticated_peer, held in variants
        if digest_only_admits(work, review, "trunk-7")
        and not bound_admits(
            work,
            review,
            "trunk-7",
            authenticated_peer,
            replace(home, held_units=frozenset({"unit-a"}) if held else frozenset()),
        )
    ]
    assert len(weak_false_accepts) == 31
    assert sum(
        bound_admits(
            work,
            review,
            "trunk-7",
            authenticated_peer,
            replace(home, held_units=frozenset({"unit-a"}) if held else frozenset()),
        )
        for work, authenticated_peer, held in variants
    ) == 1

    # These changes can happen after the review revision was captured. The
    # peer's unchanged claim and carriage cannot witness the Home's new state.
    taken_over = replace(home, assigned_peer="other-peer", custody_epoch=8)
    returned_to_peer = replace(taken_over, assigned_peer="assigned-peer", custody_epoch=9)
    for changed_home in (
        replace(home, held_units=frozenset({"unit-a"})),
        replace(home, custody_epoch=8),
        taken_over,
        # Assignment can return to the same peer after an intervening change.
        # The epoch still distinguishes that new grant from the old one.
        returned_to_peer,
        replace(home, authorized_units=frozenset()),
    ):
        assert digest_only_admits(good, review, "trunk-7")
        assert not bound_admits(good, review, "trunk-7", "assigned-peer", changed_home)
    assert not bound_admits(good, review, "trunk-7", "other-peer", home)
    assert not bound_admits(good, review, "trunk-8", "assigned-peer", home)
    # An unrelated Hold does not invalidate this unit's otherwise ready gate.
    assert bound_admits(
        good,
        review,
        "trunk-7",
        "assigned-peer",
        replace(home, held_units=frozenset({"unit-b"})),
    )

    print("FB-6 peer candidate: 32 claimed/authenticated/Home states share one carrier identity")
    print("  digest-only gate falsely accepts 31; bound final gate accepts 1")
    print("  later Home Hold, custody or assignment change, and trunk move each refuse")


if __name__ == "__main__":
    main()
