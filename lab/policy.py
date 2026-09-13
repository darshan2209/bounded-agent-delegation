"""Broker policy: the control under test, loaded from policy/broker-policy.yaml.

Each stanza of the policy closes one property of the transitive-delegation
primitive defined in the dissertation:

    audience  -> revocation boundary
    scope     -> delegated scope
    lifetime  -> trust-compounding step
    act/may_act -> principal
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import yaml

POLICY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "policy", "broker-policy.yaml",
)


@dataclass
class Policy:
    mode: str = "enforcing"                     # passthrough | enforcing
    audience_pin: str = "single"
    audience_allowed: list[str] = field(default_factory=list)
    scope_strategy: str = "least"
    scope_inherit_from_subject: bool = False
    scope_allowed: list[str] = field(default_factory=list)
    ttl_seconds: int = 300
    refresh_allowed: bool = False
    act_required: bool = True
    may_act: dict[str, list[str]] = field(default_factory=dict)
    # Ablation: names of bounded-token properties to switch off, so that the
    # contribution of each can be measured independently. See attack/ablation.py.
    ablate: frozenset[str] = frozenset()

    def enforces(self, prop: str) -> bool:
        """Is this bounded-token property active in the current configuration?"""
        return self.enforcing and prop not in self.ablate

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforcing"

    def actor_may_act_for(self, actor: str, subject: str) -> bool:
        """RFC 8693 may_act: is this actor pre-authorised to act for this subject?"""
        return actor in self.may_act.get(subject, [])

    def granted_scope(self, requested: list[str]) -> list[str]:
        """Least privilege: intersect the request with what policy allows."""
        if self.scope_strategy == "least":
            return [s for s in requested if s in self.scope_allowed] or list(self.scope_allowed)
        return list(requested)

    def audience_ok(self, requested: str) -> bool:
        return requested in self.audience_allowed


def load(path: str = POLICY_PATH, mode_override: str | None = None) -> Policy:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    bt = raw.get("bounded_token", {})
    may_act: dict[str, list[str]] = {}
    for entry in raw.get("may_act", []):
        may_act[entry["subject"]] = list(entry.get("actors", []))

    return Policy(
        mode=mode_override or os.environ.get("BROKER_MODE") or raw.get("mode", "enforcing"),
        audience_pin=bt.get("audience", {}).get("pin", "single"),
        audience_allowed=list(bt.get("audience", {}).get("allowed", [])),
        scope_strategy=bt.get("scope", {}).get("strategy", "least"),
        scope_inherit_from_subject=bool(bt.get("scope", {}).get("inherit_from_subject", False)),
        scope_allowed=list(bt.get("scope", {}).get("allowed", [])),
        ttl_seconds=int(bt.get("lifetime", {}).get("ttl_seconds", 300)),
        refresh_allowed=bool(bt.get("lifetime", {}).get("refresh_allowed", False)),
        act_required=bool(bt.get("act_claim", {}).get("required", True)),
        may_act=may_act,
    )
