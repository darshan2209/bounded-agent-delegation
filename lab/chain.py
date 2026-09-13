"""The reconstructed UNC6395 kill chain, executed against the laboratory.

Five stages, mapped to MITRE ATT&CK for Enterprise v19. The same script runs in
both configurations; only the shape of the token the agent holds differs.

    T1528     Steal Application Access Token
    T1550.001 Use Alternate Authentication Material: Application Access Token
    T1078.004 Valid Accounts: Cloud Accounts          <- the delegation step
    T1552     Unsecured Credentials
    T1070     Indicator Removal

The mapping is analyst-derived. GTIG's reporting described the behaviours but
published no technique identifiers; see Section 5.4 of the dissertation.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from .jwtutil import KeyPair
from .policy import Policy
from .services import (AGENT, ATTACKER, HUMAN, RESOURCE_A, RESOURCE_B, Agent,
                       Broker, ExchangeRefused, IdentityProvider, LogSink,
                       Resource)

SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("snowflake_token", re.compile(r"sfw_[0-9a-f]{8}")),
]


@dataclass
class Stage:
    technique: str
    name: str
    reached: bool = False
    succeeded: bool = False
    detail: str = ""


@dataclass
class ChainResult:
    mode: str
    completed: bool = False
    broke_at: str | None = None
    broke_reason: str = ""
    secrets_harvested: list[str] = field(default_factory=list)
    stages: list[Stage] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "mode": self.mode,
            "completed": self.completed,
            "broke_at": self.broke_at,
            "broke_reason": self.broke_reason,
            "secrets_harvested": self.secrets_harvested,
            "stages": [asdict(s) for s in self.stages],
        }


def run(mode: str, policy_path: str | None = None) -> tuple[ChainResult, LogSink]:
    """Execute the chain in `passthrough` (baseline) or `enforcing` (treatment)."""
    from . import policy as policy_mod

    keys = KeyPair()
    log = LogSink()
    pol: Policy = policy_mod.load(policy_path or policy_mod.POLICY_PATH, mode_override=mode)

    idp = IdentityProvider(keys, log)
    broker = Broker(keys, pol, log)
    resource_a = Resource("resource-a", RESOURCE_A, keys, log)
    resource_b = Resource("resource-b", RESOURCE_B, keys, log)
    agent = Agent(broker, log)

    result = ChainResult(mode=mode)

    def stage(technique: str, name: str) -> Stage:
        s = Stage(technique=technique, name=name, reached=True)
        result.stages.append(s)
        return s

    # The agent starts from the broad standing grant in both runs.
    grant = idp.issue_broad_grant()

    # The agent acquires whatever the configuration gives it. In the treatment
    # this is a bounded token; in the baseline the broker passes the grant back.
    agent.acquire(grant, audience=RESOURCE_A, scope=["records:read:single"])
    stolen = agent.held_token or ""

    # --- T1528 -------------------------------------------------------------
    s1 = stage("T1528", "Steal Application Access Token")
    s1.succeeded = bool(stolen)
    s1.detail = "attacker obtains the token the agent currently holds"

    # --- T1550.001 ---------------------------------------------------------
    # The theft succeeds in both runs: the token is valid for its own audience.
    s2 = stage("T1550.001", "Use Application Access Token")
    probe = resource_a.read_one(stolen, 1)
    s2.succeeded = probe.ok
    s2.detail = probe.reason or "token accepted by its intended audience"

    # --- T1078.004 ---------------------------------------------------------
    # The delegation step. The attacker tries to operate as a broadly privileged
    # cloud account: a bulk query against resource A, then a pivot to resource B.
    s3 = stage("T1078.004", "Valid Accounts: Cloud Accounts")
    bulk = resource_a.bulk_query(stolen)
    pivot = resource_b.read_one(stolen, 1)

    # The attacker also tries to trade the stolen token up at the broker.
    escalated = False
    escalation_reason = ""
    try:
        broker.exchange(subject_token=stolen, actor=ATTACKER, audience=RESOURCE_B,
                        scope=["records:bulkQuery", "admin:read"])
        escalated = True
    except ExchangeRefused as exc:
        escalation_reason = exc.reason

    s3.succeeded = bulk.ok or pivot.ok or escalated
    if not s3.succeeded:
        s3.detail = (f"bulk query: {bulk.reason}; pivot to second resource: "
                     f"{pivot.reason}; broker escalation: {escalation_reason}")
        result.broke_at = "T1078.004"
        result.broke_reason = bulk.reason or pivot.reason
        result.completed = False
        return result, log
    s3.detail = "operating as a broadly privileged cloud identity"

    # --- T1552 -------------------------------------------------------------
    s4 = stage("T1552", "Unsecured Credentials")
    harvested: list[str] = []
    for record in bulk.records:
        for label, pattern in SECRET_PATTERNS:
            for hit in pattern.findall(record.get("notes", "")):
                harvested.append(f"{label}:{hit}")
    result.secrets_harvested = harvested
    s4.succeeded = bool(harvested)
    s4.detail = f"{len(harvested)} embedded secret(s) mined from exported records"

    # --- T1070 -------------------------------------------------------------
    s5 = stage("T1070", "Indicator Removal")
    wipe = resource_a.delete_jobs(stolen)
    s5.succeeded = wipe.ok
    s5.detail = wipe.reason or "query-job records deleted"

    result.completed = all(s.succeeded for s in result.stages)
    if not result.completed:
        failed = next(s for s in result.stages if not s.succeeded)
        result.broke_at = failed.technique
        result.broke_reason = failed.detail
    return result, log
