"""The five laboratory components.

    IdentityProvider  issues the initial grant
    Broker            RFC 8693 token exchange, the component under test
    Resource          a protected API; two instances model the wider API surface
    LogSink           captures every issuance, exchange, refusal and presentation
    Agent             the over-scoped workload that calls the resource

The components are plain classes so the experiment can run in-process and
deterministically. `lab/serve.py` wraps the same objects in an HTTP layer for
the container demo, so the logic under test is identical either way.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

import jwt

from .jwtutil import KeyPair, audiences_of, mint, scopes_of, seconds_remaining
from .policy import Policy

# Audiences. RESOURCE_A is the resource the delegation is intended for.
# RESOURCE_B models the wider cloud API surface an attacker pivots to.
RESOURCE_A = "https://resource.local/api"
RESOURCE_B = "https://admin.local/api"

HUMAN = "user:analyst@corp.local"
AGENT = "agent:report-builder"
ATTACKER = "actor:unc6395"


# --------------------------------------------------------------------------- log
@dataclass
class LogSink:
    """Captures the telemetry the dissertation compares between runs."""

    events: list[dict] = field(default_factory=list)

    def emit(self, event_type: str, **fields) -> None:
        self.events.append({"ts": round(time.time(), 3), "event_type": event_type, **fields})

    def of_type(self, event_type: str) -> list[dict]:
        return [e for e in self.events if e["event_type"] == event_type]

    def dump(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.events, fh, indent=2)


# --------------------------------------------------------------------------- idp
class IdentityProvider:
    """Issues the initial grant to the agent.

    In the baseline this is the field condition Gravitee (2026) reports: a broad,
    long-lived, audience-unrestricted token. In the treatment the agent receives
    the same broad grant, because the experiment must not advantage the treatment
    by handing the agent a weaker starting credential; what changes is that the
    agent may no longer present it to a resource directly.
    """

    def __init__(self, keys: KeyPair, log: LogSink) -> None:
        self.keys = keys
        self.log = log

    def issue_broad_grant(self, subject: str = HUMAN, actor: str = AGENT) -> str:
        token = mint(
            self.keys,
            subject=subject,
            audience=[RESOURCE_A, RESOURCE_B],      # audience-unrestricted in practice
            scope=["records:read:all", "records:bulkQuery", "jobs:delete", "admin:read"],
            ttl_seconds=60 * 60 * 24 * 30,          # 30 days, refresh-backed in the field
            actor=actor,
            may_act=None,
        )
        self.log.emit("issue", subject=subject, actor=actor,
                      audience=[RESOURCE_A, RESOURCE_B], ttl_seconds=60 * 60 * 24 * 30,
                      note="broad standing grant (field condition)")
        return token


# ------------------------------------------------------------------------ broker
class ExchangeRefused(Exception):
    """Raised when the broker refuses to mint a token."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Broker:
    """RFC 8693 token exchange. The component under test.

    In `passthrough` mode it returns the presented token unchanged, which is the
    baseline condition: implicit scope inheritance. In `enforcing` mode it mints
    a bounded token whose four properties each close one property of the
    transitive-delegation primitive.
    """

    GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"

    def __init__(self, keys: KeyPair, policy: Policy, log: LogSink) -> None:
        self.keys = keys
        self.policy = policy
        self.log = log

    def exchange(self, *, subject_token: str, actor: str, audience: str,
                 scope: list[str]) -> str:
        try:
            claims = self.keys.verify(subject_token)
        except jwt.PyJWTError as exc:
            self.log.emit("refuse", actor=actor, reason=f"subject token invalid: {exc}")
            raise ExchangeRefused(f"subject token invalid: {exc}") from exc

        subject = claims.get("sub", "")

        if not self.policy.enforcing:
            # Pass-through: implicit scope inheritance, the dominant field pattern.
            self.log.emit("exchange", mode="passthrough", actor=actor, subject=subject,
                          audience=list(audiences_of(claims)),
                          scope=sorted(scopes_of(claims)),
                          note="no down-scoping, no audience pinning, no act claim")
            return subject_token

        # --- enforcing -----------------------------------------------------
        # principal: may_act pre-authorises who may act for this subject
        if self.policy.enforces("may_act") and not self.policy.actor_may_act_for(actor, subject):
            self.log.emit("refuse", actor=actor, subject=subject,
                          reason="may_act: actor not authorised to act for subject",
                          may_act_matched=False)
            raise ExchangeRefused("may_act: actor not authorised to act for subject")

        # revocation boundary: exactly one audience, and it must be allowed
        if self.policy.audience_pin == "single" and not isinstance(audience, str):
            self.log.emit("refuse", actor=actor, subject=subject,
                          reason="audience must be a single value")
            raise ExchangeRefused("audience must be a single value")
        if self.policy.enforces("audience") and not self.policy.audience_ok(audience):
            self.log.emit("refuse", actor=actor, subject=subject, audience=audience,
                          reason="audience not permitted by policy")
            raise ExchangeRefused(f"audience not permitted by policy: {audience}")

        # delegated scope: least privilege, never the inherited scope
        if self.policy.enforces("scope"):
            granted = self.policy.granted_scope(scope)
        else:
            # Ablated: the inherited scope passes through, as it does in the field.
            granted = sorted(scopes_of(claims))
        escalation = (sorted(set(scope) - set(self.policy.scope_allowed))
                      if self.policy.enforces("scope") else [])
        if escalation:
            self.log.emit("refuse", actor=actor, subject=subject,
                          requested_scope=sorted(scope), refused_scope=escalation,
                          reason="scope escalation refused")
            raise ExchangeRefused(f"scope escalation refused: {escalation}")

        token = mint(
            self.keys,
            subject=subject,
            # single pinned audience, unless that property is ablated
            audience=(audience if self.policy.enforces("audience")
                      else list(audiences_of(claims))),
            scope=granted,                           # least scope
            ttl_seconds=(self.policy.ttl_seconds if self.policy.enforces("ttl")
                         else 60 * 60 * 24 * 30),    # short lifetime
            actor=actor,                             # audited act claim
            may_act=actor,
        )
        self.log.emit("exchange", mode="enforcing", actor=actor, subject=subject,
                      audience=audience, scope=granted,
                      ttl_seconds=self.policy.ttl_seconds, act_claim=True,
                      may_act_matched=True)
        return token


# ---------------------------------------------------------------------- resource
@dataclass
class ResourceResult:
    ok: bool
    reason: str = ""
    records: list[dict] = field(default_factory=list)


class Resource:
    """A protected API that validates audience, scope and expiry.

    `RESOURCE_A` stands in for the Salesforce object store of the UNC6395 case.
    `RESOURCE_B` stands in for the wider cloud API surface the attacker pivots to.
    """

    def __init__(self, name: str, audience: str, keys: KeyPair, log: LogSink) -> None:
        self.name = name
        self.audience = audience
        self.keys = keys
        self.log = log
        # Records seeded with the embedded secrets the T1552 stage harvests.
        self.records = [
            {"id": 1, "account": "Northwind", "notes": "prod key AKIAI44QH8DHBEXAMPLE"},
            {"id": 2, "account": "Contoso", "notes": "snowflake token sfw_7f2c1a64"},
            {"id": 3, "account": "Fabrikam", "notes": "nothing sensitive here"},
        ]
        self.query_jobs = [{"job": "bulk-001"}, {"job": "bulk-002"}]

    # A broad scope subsumes the narrow operation it contains, which is how a
    # real over-scoped grant behaves: records:read:all covers a single read.
    SUBSUMES = {
        "records:read:single": {"records:read:single", "records:read:all"},
        "records:bulkQuery": {"records:bulkQuery"},
        "jobs:delete": {"jobs:delete"},
    }

    def _check(self, token: str, required_scope: str) -> tuple[dict | None, str]:
        try:
            claims = self.keys.verify(token, audience=self.audience)
        except jwt.InvalidAudienceError:
            return None, "audience mismatch"
        except jwt.ExpiredSignatureError:
            return None, "token expired"
        except jwt.PyJWTError as exc:
            return None, f"invalid token: {exc}"
        satisfying = self.SUBSUMES.get(required_scope, {required_scope})
        if not (scopes_of(claims) & satisfying):
            return None, f"insufficient scope: {required_scope} not granted"
        return claims, ""

    def read_one(self, token: str, record_id: int) -> ResourceResult:
        claims, err = self._check(token, "records:read:single")
        self.log.emit("present", resource=self.name, operation="read_one",
                      ok=not err, reason=err,
                      ttl_remaining=seconds_remaining(claims) if claims else None,
                      act=(claims or {}).get("act"))
        if err:
            return ResourceResult(False, err)
        return ResourceResult(True, records=[r for r in self.records if r["id"] == record_id])

    def bulk_query(self, token: str) -> ResourceResult:
        """The stage the pivot needs. Requires the broad bulk-query scope."""
        claims, err = self._check(token, "records:bulkQuery")
        self.log.emit("present", resource=self.name, operation="bulk_query",
                      ok=not err, reason=err,
                      act=(claims or {}).get("act"))
        if err:
            return ResourceResult(False, err)
        return ResourceResult(True, records=list(self.records))

    def delete_jobs(self, token: str) -> ResourceResult:
        claims, err = self._check(token, "jobs:delete")
        self.log.emit("present", resource=self.name, operation="delete_jobs",
                      ok=not err, reason=err)
        if err:
            return ResourceResult(False, err)
        self.query_jobs.clear()
        return ResourceResult(True)


# ------------------------------------------------------------------------- agent
class Agent:
    """The over-scoped AI-agent workload.

    In the baseline it holds the broad grant and presents it directly. In the
    treatment it must obtain a bounded token from the broker before each call,
    which is the single variable that changes between runs.
    """

    def __init__(self, broker: Broker, log: LogSink) -> None:
        self.broker = broker
        self.log = log
        self.held_token: str | None = None

    def acquire(self, grant: str, *, audience: str, scope: list[str]) -> str:
        token = self.broker.exchange(subject_token=grant, actor=AGENT,
                                     audience=audience, scope=scope)
        self.held_token = token
        return token
