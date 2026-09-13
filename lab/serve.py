"""Run one laboratory component as an HTTP service.

    python -m lab.serve idp         # authorisation server, sole signing authority
    python -m lab.serve broker      # RFC 8693 exchange, the component under test
    python -m lab.serve resource-a  # the intended resource
    python -m lab.serve resource-b  # the wider API surface the attacker pivots to
    python -m lab.serve logsink     # telemetry collector

Every service verifies tokens against the IdP's published JWKS, so the trust
relationships in the container topology are the same ones a real estate has.
"""
from __future__ import annotations

import json
import os
import sys
import time

import jwt
from jwt.algorithms import RSAAlgorithm

from .http_common import get, make_server, post, serve_forever
from .jwtutil import KeyPair, mint, scopes_of
from .policy import load as load_policy
from .services import AGENT, RESOURCE_A, RESOURCE_B, ExchangeRefused, Resource

PORTS = {"idp": 18081, "broker": 18082, "resource-a": 18083,
         "resource-b": 18084, "logsink": 18085}


def _host(service: str) -> str:
    """In compose each service is a DNS name; locally everything is localhost."""
    return os.environ.get(f"{service.upper().replace('-', '_')}_HOST",
                          f"127.0.0.1:{PORTS[service]}")


def _remote_log(event_type: str, **fields) -> None:
    try:
        post(f"http://{_host('logsink')}/events",
             {"ts": round(time.time(), 3), "event_type": event_type, **fields}, timeout=2.0)
    except OSError:
        pass  # the experiment must not fail because telemetry is unavailable


# ------------------------------------------------------------------------ idp
def run_idp() -> None:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    keys = KeyPair()
    public_jwk = json.loads(RSAAlgorithm.to_jwk(load_pem_public_key(keys.public_pem)))
    public_jwk["kid"] = "lab-key-1"
    public_jwk["alg"] = "RS256"
    public_jwk["use"] = "sig"

    def jwks(_body, _query):
        return 200, {"keys": [public_jwk]}

    def grant(_body, _query):
        token = mint(keys, subject="user:analyst@corp.local",
                     audience=[RESOURCE_A, RESOURCE_B],
                     scope=["records:read:all", "records:bulkQuery",
                            "jobs:delete", "admin:read"],
                     ttl_seconds=60 * 60 * 24 * 30, actor=AGENT)
        _remote_log("issue", subject="user:analyst@corp.local", actor=AGENT,
                    note="broad standing grant (field condition)")
        return 200, {"access_token": token, "token_type": "Bearer"}

    def mint_bounded(body, _query):
        """Internal endpoint. Only the policy-enforcing broker calls this."""
        token = mint(keys, subject=body["subject"], audience=body["audience"],
                     scope=body["scope"], ttl_seconds=body["ttl_seconds"],
                     actor=body.get("actor"), may_act=body.get("may_act"))
        return 200, {"access_token": token}

    serve_forever(make_server(PORTS["idp"], {
        ("GET", "/jwks"): jwks,
        ("POST", "/token/grant"): grant,
        ("POST", "/token/mint"): mint_bounded,
    }), "idp")


# --------------------------------------------------------------------- broker
def run_broker() -> None:
    policy = load_policy()
    verifier = _JwksVerifier()

    def exchange(body, _query):
        """RFC 8693 token exchange, policy-enforced."""
        if body.get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange":
            return 400, {"error": "unsupported_grant_type"}
        actor = body.get("actor_token_sub", AGENT)
        audience = body.get("audience", "")
        requested = body.get("scope", "").split()

        try:
            claims = verifier.verify(body.get("subject_token", ""))
        except jwt.PyJWTError as exc:
            _remote_log("refuse", actor=actor, reason=f"subject token invalid: {exc}")
            return 400, {"error": "invalid_request", "reason": str(exc)}
        subject = claims.get("sub", "")

        if not policy.enforcing:
            _remote_log("exchange", mode="passthrough", actor=actor, subject=subject,
                        note="no down-scoping, no audience pinning, no act claim")
            return 200, {"access_token": body["subject_token"],
                         "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"}

        try:
            if not policy.actor_may_act_for(actor, subject):
                raise ExchangeRefused("may_act: actor not authorised to act for subject")
            if not policy.audience_ok(audience):
                raise ExchangeRefused(f"audience not permitted by policy: {audience}")
            escalation = sorted(set(requested) - set(policy.scope_allowed))
            if escalation:
                raise ExchangeRefused(f"scope escalation refused: {escalation}")
        except ExchangeRefused as exc:
            _remote_log("refuse", actor=actor, subject=subject, reason=exc.reason,
                        may_act_matched=policy.actor_may_act_for(actor, subject))
            return 403, {"error": "access_denied", "reason": exc.reason}

        status, payload = post(f"http://{_host('idp')}/token/mint", {
            "subject": subject, "audience": audience,
            "scope": policy.granted_scope(requested),
            "ttl_seconds": policy.ttl_seconds, "actor": actor, "may_act": actor,
        })
        if status != 200:
            return 502, {"error": "mint_failed"}
        _remote_log("exchange", mode="enforcing", actor=actor, subject=subject,
                    audience=audience, scope=policy.granted_scope(requested),
                    ttl_seconds=policy.ttl_seconds, act_claim=True, may_act_matched=True)
        return 200, {"access_token": payload["access_token"],
                     "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                     "expires_in": policy.ttl_seconds}

    serve_forever(make_server(PORTS["broker"], {("POST", "/token"): exchange}), "broker")


# ------------------------------------------------------------------- resource
class _JwksVerifier:
    """Fetches and caches the IdP's public key, as a resource server would."""

    def __init__(self) -> None:
        self._key = None

    def _load(self):
        if self._key is None:
            for _ in range(30):
                status, payload = get(f"http://{_host('idp')}/jwks")
                if status == 200 and payload.get("keys"):
                    self._key = RSAAlgorithm.from_jwk(json.dumps(payload["keys"][0]))
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("could not reach the IdP JWKS endpoint")
        return self._key

    def verify(self, token: str, audience: str | None = None) -> dict:
        return jwt.decode(token, self._load(), algorithms=["RS256"], audience=audience,
                          options={"require": ["exp", "iat", "sub", "aud"],
                                   "verify_aud": audience is not None})


class _ResourceState:
    """The seeded records and query jobs the chain operates on."""

    def __init__(self) -> None:
        self.records = [
            {"id": 1, "account": "Northwind", "notes": "prod key AKIAI44QH8DHBEXAMPLE"},
            {"id": 2, "account": "Contoso", "notes": "snowflake token sfw_7f2c1a64"},
            {"id": 3, "account": "Fabrikam", "notes": "nothing sensitive here"},
        ]
        self.query_jobs = [{"job": "bulk-001"}, {"job": "bulk-002"}]


def run_resource(name: str, audience: str) -> None:
    verifier = _JwksVerifier()
    # Seeded data only. Token verification here goes through the IdP's JWKS,
    # so this instance is never asked to sign anything.
    state = _ResourceState()

    def check(body, required_scope):
        try:
            claims = verifier.verify(body.get("access_token", ""), audience=audience)
        except jwt.InvalidAudienceError:
            return None, "audience mismatch"
        except jwt.ExpiredSignatureError:
            return None, "token expired"
        except jwt.PyJWTError as exc:
            return None, f"invalid token: {exc}"
        satisfying = Resource.SUBSUMES.get(required_scope, {required_scope})
        if not (scopes_of(claims) & satisfying):
            return None, f"insufficient scope: {required_scope} not granted"
        return claims, ""

    def read_one(body, _q):
        claims, err = check(body, "records:read:single")
        _remote_log("present", resource=name, operation="read_one", ok=not err, reason=err,
                    act=(claims or {}).get("act"))
        if err:
            return 403, {"error": "forbidden", "reason": err}
        rid = int(body.get("id", 1))
        return 200, {"records": [r for r in state.records if r["id"] == rid]}

    def bulk_query(body, _q):
        claims, err = check(body, "records:bulkQuery")
        _remote_log("present", resource=name, operation="bulk_query", ok=not err, reason=err,
                    act=(claims or {}).get("act"))
        if err:
            return 403, {"error": "forbidden", "reason": err}
        return 200, {"records": state.records}

    def delete_jobs(body, _q):
        _claims, err = check(body, "jobs:delete")
        _remote_log("present", resource=name, operation="delete_jobs", ok=not err, reason=err)
        if err:
            return 403, {"error": "forbidden", "reason": err}
        state.query_jobs.clear()
        return 200, {"deleted": True}

    serve_forever(make_server(PORTS[name], {
        ("POST", "/records/read"): read_one,
        ("POST", "/records/bulkQuery"): bulk_query,
        ("DELETE", "/jobs"): delete_jobs,
    }), name)


# -------------------------------------------------------------------- logsink
def run_logsink() -> None:
    events: list[dict] = []

    def ingest(body, _q):
        events.append(body)
        return 202, {"accepted": True}

    def dump(_body, _q):
        return 200, {"events": events, "count": len(events)}

    serve_forever(make_server(PORTS["logsink"], {
        ("POST", "/events"): ingest,
        ("GET", "/events"): dump,
    }), "logsink")


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in PORTS:
        print(f"usage: python -m lab.serve [{' | '.join(PORTS)}]", file=sys.stderr)
        return 2
    service = sys.argv[1]
    if service == "idp":
        run_idp()
    elif service == "broker":
        run_broker()
    elif service == "resource-a":
        run_resource("resource-a", RESOURCE_A)
    elif service == "resource-b":
        run_resource("resource-b", RESOURCE_B)
    elif service == "logsink":
        run_logsink()
    return 0


if __name__ == "__main__":
    sys.exit(main())
