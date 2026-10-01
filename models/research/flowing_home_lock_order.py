#!/usr/bin/env python3
"""Bounded final Home -> norm -> ref schedule for one flowing admission.

Run: python3 models/research/flowing_home_lock_order.py

The gate has already checked an immutable selected prefix against Home seal 0,
norm revision 0 and source policy epoch 0. At final admission it takes each
authority's exclusion in order, recaptures affected premises, then advances
the ref and unit disposition together. A next-epoch Home entry unrelated to
the candidate may continue. This is a lock schedule and identity model, not
the native/hosted locks, certificate issuer or full source-content model.
"""

from collections import deque
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class State:
    gate: str = "new"  # new, home, norm, ref, checked, stale, done
    other: str = "new"  # new, home, norm, ref, reverse_ref, reverse_home, done
    home_owner: int = -1
    norm_owner: int = -1
    ref_owner: int = -1
    home_affected: int = 0
    home_next_epoch: int = 0
    norm_revision: int = 0
    source_epoch: int = 0
    source_held: bool = False
    trunk: int = 0
    unit: str = "owed"
    admission: tuple[int, int, int, bool, bool, bool, bool, bool, bool] | None = None
    home_up: bool = True
    norm_up: bool = True
    ref_up: bool = True
    outage_used: tuple[bool, bool, bool] = (False, False, False)
    home_change_used: bool = False
    norm_change_used: bool = False
    hold_used: bool = False
    next_entry_used: bool = False


def release_gate(state, phase, defect=""):
    return replace(
        state, gate=phase,
        home_owner=(0 if defect == "retain_home_on_outage" and
                    phase == "stale" and state.home_owner == 0 else
                    -1 if state.home_owner == 0 else state.home_owner),
        norm_owner=-1 if state.norm_owner == 0 else state.norm_owner,
        ref_owner=-1 if state.ref_owner == 0 else state.ref_owner,
    )


def steps(s: State, defect: str = ""):
    # The Home door may admit a later, unrelated epoch entry without changing
    # the sealed candidate. An affected dependency/policy change is different.
    if s.home_up and s.home_owner == -1 and not s.next_entry_used:
        yield "next-epoch entry", replace(
            s, home_next_epoch=s.home_next_epoch + 1, next_entry_used=True)
    if s.home_up and s.home_owner == -1 and not s.home_change_used:
        yield "affected Home change", replace(
            s, home_affected=s.home_affected + 1, home_change_used=True)
    if s.norm_up and s.norm_owner == -1 and not s.norm_change_used:
        yield "norm revocation", replace(
            s, norm_revision=s.norm_revision + 1, norm_change_used=True)
    if s.ref_up and s.ref_owner == -1 and not s.hold_used:
        yield "source Hold", replace(
            s, source_held=True, source_epoch=s.source_epoch + 1,
            hold_used=True)

    # A second operation requiring all authorities uses the same order. The
    # reverse-order mutant models a ref holder waiting for Home exclusion.
    if s.other == "new":
        if defect == "reverse_order" and s.ref_up and s.ref_owner == -1:
            yield "other takes ref first", replace(
                s, other="reverse_ref", ref_owner=1)
        elif defect != "reverse_order" and s.home_up and s.home_owner == -1:
            yield "other takes Home", replace(s, other="home", home_owner=1)
    if s.other == "home" and s.norm_up and s.norm_owner == -1:
        yield "other takes norm", replace(s, other="norm", norm_owner=1)
    if s.other == "norm" and s.ref_up and s.ref_owner == -1:
        yield "other takes ref", replace(s, other="ref", ref_owner=1)
    if s.other == "reverse_ref" and s.home_up and s.home_owner == -1:
        yield "other takes Home second", replace(
            s, other="reverse_home", home_owner=1)
    if s.other == "reverse_home" and s.norm_up and s.norm_owner == -1:
        yield "other takes norm third", replace(
            s, other="ref", norm_owner=1)
    if s.other == "ref" and s.home_up and s.norm_up and s.ref_up:
        yield "other commits", replace(
            s, other="done", home_affected=s.home_affected + 1,
            norm_revision=s.norm_revision + 1,
            source_epoch=s.source_epoch + 1,
            home_owner=-1, norm_owner=-1, ref_owner=-1)

    if s.gate == "new" and s.home_owner == -1 and (
            s.home_up or defect == "fail_open_home"):
        yield "gate takes Home", replace(s, gate="home", home_owner=0)
    if s.gate == "home" and s.norm_up and s.norm_owner == -1:
        yield "gate takes norm", replace(s, gate="norm", norm_owner=0)
    if s.gate == "norm" and s.ref_up and s.ref_owner == -1:
        yield "gate takes ref", replace(s, gate="ref", ref_owner=0)
    if s.gate == "ref":
        current = (s.home_affected, s.norm_revision)
        source_current = s.source_epoch == 0 and not s.source_held
        if ((s.home_up or defect == "fail_open_home") and s.norm_up and
                s.ref_up and
                ((current == (0, 0) and
                  (source_current or defect == "ignore_hold")) or
                 defect == "skip_recap")):
            yield "recapture", replace(
                s, gate="checked",
                home_owner=(-1 if defect == "release_home_early"
                            else s.home_owner),
                norm_owner=(-1 if defect == "release_norm_early"
                            else s.norm_owner))
        else:
            yield "stale", release_gate(s, "stale")
    if (s.gate == "checked" and s.ref_up and s.norm_up and
            (s.home_up or defect == "fail_open_home")):
        yield "cas", release_gate(replace(
            s, gate="done", trunk=1,
            unit=("owed" if defect == "omit_unit_receipt" else "accounted"),
            admission=(s.home_affected, s.norm_revision, s.source_epoch,
                       s.source_held, s.home_owner == 0, s.norm_owner == 0,
                       s.ref_owner == 0, s.home_up, s.norm_up)), "done")

    for index, name in enumerate(("Home", "norm", "ref")):
        field = ("home_up", "norm_up", "ref_up")[index]
        if getattr(s, field) and not s.outage_used[index]:
            used = list(s.outage_used)
            used[index] = True
            yield f"{name} outage", replace(
                s, **{field: False, "outage_used": tuple(used)})
        if not getattr(s, field):
            yield f"{name} recovers", replace(s, **{field: True})
    if s.gate in ("home", "norm", "ref", "checked") and not (
            s.home_up and s.norm_up and s.ref_up):
        yield "abort on outage", release_gate(s, "stale", defect)


def violation(s: State):
    if (s.gate in ("norm", "ref") and s.other == "reverse_ref" and
            s.home_owner == 0 and s.ref_owner == 1):
        return "Home/ref circular wait"
    if s.gate == "stale" and 0 in (s.home_owner, s.norm_owner, s.ref_owner):
        return "aborted gate stranded authority exclusion"
    if s.other == "done" and 1 in (s.home_owner, s.norm_owner, s.ref_owner):
        return "completed writer stranded authority exclusion"
    if s.trunk != int(s.admission is not None):
        return "trunk and admission entry split"
    if s.admission is not None:
        home, norm, source, held, home_lock, norm_lock, ref_lock, home_up, norm_up = s.admission
        if (home, norm, source) != (0, 0, 0) or held:
            return "changed Home, norm or source premise admitted"
        if not (home_lock and norm_lock and ref_lock and home_up and norm_up):
            return "CAS lacked a live authority exclusion"
        if s.unit != "accounted":
            return "trunk CAS omitted the selected unit receipt"
    return None


def scenario(events, defect=""):
    state = State()
    for wanted in events:
        matches = [after for event, after in steps(state, defect)
                   if event == wanted]
        assert len(matches) == 1, (wanted, state)
        state = matches[0]
        if not defect:
            assert violation(state) is None, (wanted, state)
    return state


def explore(defect="", depth=10):
    start = State()
    queue = deque([(start, ())])
    seen = {start}
    while queue:
        state, trace = queue.popleft()
        if problem := violation(state):
            return len(seen), problem, trace
        if len(trace) == depth:
            continue
        for event, after in steps(state, defect):
            if after not in seen:
                seen.add(after)
                queue.append((after, trace + (event,)))
    return len(seen), None, ()


def main():
    ordinary = scenario(("gate takes Home", "gate takes norm",
                         "gate takes ref", "recapture", "cas"))
    assert ordinary.trunk == 1 and ordinary.unit == "accounted"
    later = scenario(("next-epoch entry", "gate takes Home", "gate takes norm",
                      "gate takes ref", "recapture", "cas"))
    assert later.home_next_epoch == 1 and later.trunk == 1
    competing = scenario(("other takes Home", "other takes norm",
                          "other takes ref", "other commits",
                          "gate takes Home", "gate takes norm",
                          "gate takes ref", "stale"))
    assert competing.gate == "stale" and competing.trunk == 0
    outage = scenario(("gate takes Home", "gate takes norm", "ref outage",
                       "abort on outage", "norm revocation"))
    assert outage.gate == "stale" and outage.norm_revision == 1
    unavailable_home = scenario(("Home outage",))
    assert "gate takes Home" not in {event for event, _ in steps(unavailable_home)}
    recovered_home = scenario(("Home outage", "Home recovers",
                               "gate takes Home", "gate takes norm",
                               "gate takes ref", "recapture", "cas"))
    assert recovered_home.trunk == 1
    unavailable_norm = scenario(("gate takes Home", "norm outage"))
    assert "gate takes norm" not in {event for event, _ in steps(unavailable_norm)}
    recovered_norm = scenario(("gate takes Home", "norm outage",
                               "abort on outage", "norm recovers",
                               "other takes Home", "other takes norm",
                               "other takes ref", "other commits"))
    assert recovered_norm.other == "done" and recovered_norm.home_owner == -1

    count, error, _ = explore()
    assert error is None, error
    print(f"Home/norm/ref flowing order: {count} safe states through ten transitions")
    for defect, expected in (
        ("reverse_order", "Home/ref circular wait"),
        ("skip_recap", "changed Home, norm or source premise admitted"),
        ("release_home_early", "CAS lacked a live authority exclusion"),
        ("release_norm_early", "CAS lacked a live authority exclusion"),
        ("ignore_hold", "changed Home, norm or source premise admitted"),
        ("fail_open_home", "CAS lacked a live authority exclusion"),
        ("retain_home_on_outage", "aborted gate stranded authority exclusion"),
        ("omit_unit_receipt", "trunk CAS omitted the selected unit receipt"),
    ):
        count, error, trace = explore(defect)
        assert error == expected, (defect, count, error, trace)
        print(f"  {defect}: {error} via {' -> '.join(trace)}")


if __name__ == "__main__":
    main()
