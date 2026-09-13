"""Print the seeded principals, audiences and the initial grant shape.

The laboratory is stateless and builds its own keypair at start-up, so there is
nothing to persist. This script exists so a replicator can see exactly what the
environment starts from before running either driver.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lab import policy as policy_mod  # noqa: E402
from lab.jwtutil import KeyPair, scopes_of  # noqa: E402
from lab.services import (AGENT, ATTACKER, HUMAN, RESOURCE_A, RESOURCE_B,  # noqa: E402
                          IdentityProvider, LogSink)


def main() -> None:
    keys = KeyPair()
    log = LogSink()
    grant = IdentityProvider(keys, log).issue_broad_grant()
    claims = keys.verify(grant)
    pol = policy_mod.load()

    print("Principals")
    print(f"  human principal : {HUMAN}")
    print(f"  agent           : {AGENT}")
    print(f"  attacker        : {ATTACKER}")
    print()
    print("Audiences")
    print(f"  resource-a (intended) : {RESOURCE_A}")
    print(f"  resource-b (pivot)    : {RESOURCE_B}")
    print()
    print("Initial standing grant (the field condition)")
    print(f"  sub   : {claims['sub']}")
    print(f"  aud   : {claims['aud']}")
    print(f"  scope : {sorted(scopes_of(claims))}")
    print(f"  ttl   : {claims['exp'] - claims['iat']} seconds")
    print(f"  act   : {claims.get('act')}")
    print()
    print("Broker policy (the control under test)")
    print(f"  mode              : {pol.mode}")
    print(f"  audience pin      : {pol.audience_pin} -> {pol.audience_allowed}")
    print(f"  scope strategy    : {pol.scope_strategy} -> {pol.scope_allowed}")
    print(f"  inherit subject   : {pol.scope_inherit_from_subject}")
    print(f"  ttl               : {pol.ttl_seconds} seconds (refresh: {pol.refresh_allowed})")
    print(f"  act claim required: {pol.act_required}")
    print(f"  may_act           : {pol.may_act}")


if __name__ == "__main__":
    main()
