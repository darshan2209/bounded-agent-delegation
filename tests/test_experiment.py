"""The experiment as an executable claim.

These tests are the falsifiable form of the result reported in Section 5.5 of
the dissertation. If the control does not behave as claimed, they fail.
"""
from __future__ import annotations

import os
import sys
import time

import jwt
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lab import chain, policy as policy_mod  # noqa: E402
from lab.jwtutil import KeyPair, audiences_of, mint, scopes_of  # noqa: E402
from lab.services import (AGENT, ATTACKER, HUMAN, RESOURCE_A, RESOURCE_B,  # noqa: E402
                          Broker, ExchangeRefused, IdentityProvider, LogSink,
                          Resource)


# --------------------------------------------------------------- the headline
def test_baseline_chain_completes():
    """With implicit scope inheritance the chain runs to completion."""
    result, _ = chain.run("passthrough")
    assert result.completed is True
    assert result.broke_at is None
    assert all(stage.succeeded for stage in result.stages)


def test_treatment_chain_breaks_at_the_delegation_step():
    """The pre-registered success criterion: failure at a named step."""
    result, _ = chain.run("enforcing")
    assert result.completed is False
    assert result.broke_at == "T1078.004", (
        "the criterion is failure at the delegation step specifically, "
        f"not merely somewhere; got {result.broke_at}"
    )


def test_theft_still_succeeds_in_both_runs():
    """The control stops the pivot, not the theft. Claiming otherwise would overstate it."""
    for mode in ("passthrough", "enforcing"):
        result, _ = chain.run(mode)
        steal = next(s for s in result.stages if s.technique == "T1528")
        present = next(s for s in result.stages if s.technique == "T1550.001")
        assert steal.succeeded, f"{mode}: token theft should succeed"
        assert present.succeeded, f"{mode}: the stolen token is valid for its own audience"


def test_no_secrets_harvested_under_treatment():
    base, _ = chain.run("passthrough")
    treat, _ = chain.run("enforcing")
    assert len(base.secrets_harvested) > 0
    assert treat.secrets_harvested == []


# ------------------------------------------------- the four bounded properties
@pytest.fixture()
def rig():
    keys = KeyPair()
    log = LogSink()
    pol = policy_mod.load(mode_override="enforcing")
    broker = Broker(keys, pol, log)
    grant = IdentityProvider(keys, log).issue_broad_grant()
    return keys, log, broker, grant


def test_audience_is_pinned_to_a_single_resource(rig):
    keys, _, broker, grant = rig
    token = broker.exchange(subject_token=grant, actor=AGENT,
                            audience=RESOURCE_A, scope=["records:read:single"])
    assert audiences_of(keys.verify(token)) == {RESOURCE_A}


def test_pinned_token_is_rejected_by_a_second_resource(rig):
    keys, log, broker, grant = rig
    token = broker.exchange(subject_token=grant, actor=AGENT,
                            audience=RESOURCE_A, scope=["records:read:single"])
    other = Resource("resource-b", RESOURCE_B, keys, log)
    result = other.read_one(token, 1)
    assert result.ok is False
    assert result.reason == "audience mismatch"


def test_scope_is_least_and_never_inherited(rig):
    keys, _, broker, grant = rig
    token = broker.exchange(subject_token=grant, actor=AGENT,
                            audience=RESOURCE_A, scope=["records:read:single"])
    granted = scopes_of(keys.verify(token))
    assert granted == {"records:read:single"}
    assert "records:bulkQuery" not in granted, "the inherited broad scope must not pass through"


def test_scope_escalation_is_refused(rig):
    _, _, broker, grant = rig
    with pytest.raises(ExchangeRefused, match="scope escalation refused"):
        broker.exchange(subject_token=grant, actor=AGENT, audience=RESOURCE_A,
                        scope=["records:bulkQuery"])


def test_lifetime_is_minutes_not_days(rig):
    keys, _, broker, grant = rig
    token = broker.exchange(subject_token=grant, actor=AGENT,
                            audience=RESOURCE_A, scope=["records:read:single"])
    claims = keys.verify(token)
    ttl = claims["exp"] - claims["iat"]
    assert ttl <= 900, "a bounded token must expire in minutes"


def test_act_claim_records_the_delegation(rig):
    keys, _, broker, grant = rig
    token = broker.exchange(subject_token=grant, actor=AGENT,
                            audience=RESOURCE_A, scope=["records:read:single"])
    claims = keys.verify(token)
    assert claims["act"]["sub"] == AGENT, "the actor must be named in the act claim"
    assert claims["sub"] == HUMAN, "the principal must remain the human subject"


def test_may_act_refuses_an_unauthorised_actor(rig):
    _, log, broker, grant = rig
    with pytest.raises(ExchangeRefused, match="may_act"):
        broker.exchange(subject_token=grant, actor=ATTACKER, audience=RESOURCE_A,
                        scope=["records:read:single"])
    refusals = [e for e in log.of_type("refuse") if e.get("may_act_matched") is False]
    assert len(refusals) == 1, "the refusal must be logged as a distinct reviewable event"


def test_expired_bounded_token_is_rejected(rig):
    keys, log, _, _ = rig
    stale = mint(keys, subject=HUMAN, audience=RESOURCE_A,
                 scope=["records:read:single"], ttl_seconds=-1, actor=AGENT)
    resource = Resource("resource-a", RESOURCE_A, keys, log)
    result = resource.read_one(stale, 1)
    assert result.ok is False
    assert result.reason == "token expired"


# ---------------------------------------------------------------- determinism
def test_result_is_deterministic_across_runs():
    outcomes = {chain.run("enforcing")[0].broke_at for _ in range(5)}
    assert outcomes == {"T1078.004"}


# ----------------------------------------------------------------- ablation
def _ablated(props: set[str]):
    """Run the treatment with the named bounded-token properties switched off."""
    original = policy_mod.load

    def patched(path=policy_mod.POLICY_PATH, mode_override=None):
        pol = original(path, mode_override=mode_override)
        pol.ablate = frozenset(props)
        return pol

    policy_mod.load = patched
    try:
        return chain.run("enforcing")[0]
    finally:
        policy_mod.load = original


def test_least_scope_is_the_load_bearing_property():
    """Disabling least scope alone restores the chain; the others do not."""
    assert _ablated({"scope"}).completed is True


def test_audience_pinning_still_blocks_the_harvest():
    """Without audience pinning the pivot succeeds, but the harvest does not.

    The break moves from T1078.004 to T1552: the attacker reaches a valid cloud
    account on the second resource, yet the bulk query that feeds the harvest is
    still refused, so no secrets are taken.
    """
    result = _ablated({"audience"})
    assert result.completed is False
    assert result.broke_at == "T1552"
    assert result.secrets_harvested == []


def test_ttl_and_may_act_alone_do_not_restore_the_chain():
    """Honest negative result.

    This chain replays the stolen token immediately and does not need the broker
    to escalate, so neither the short lifetime nor the may_act gate is exercised
    by it. They guard variants this chain does not contain, which the
    dissertation states rather than claiming all four properties are load-bearing.
    """
    assert _ablated({"ttl"}).completed is False
    assert _ablated({"may_act"}).completed is False


def test_disabling_everything_reproduces_the_baseline():
    result = _ablated({"audience", "scope", "ttl", "may_act"})
    assert result.completed is True
