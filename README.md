# Bounded Agent Delegation

Reference implementation and reproducibility artefacts for the M.Sc. dissertation
**"From Silent Controls to Exploitable Paths: A Structured Gap Analysis of Non-Human Identity
Governance Across Eight Security and AI-Governance Instruments, with Experimental Validation"**
(Gisma University of Applied Sciences, M598, 2026).

## What this demonstrates

A single bounded-delegation control, configured according to **RFC 8693 OAuth 2.0 Token Exchange**,
breaks the non-human-identity kill chain reconstructed from the August 2025 UNC6395 / Salesloft Drift
campaign, at one identifiable step.

The experiment is a two-configuration controlled test. Exactly one variable changes between runs:
the shape of the token the agent holds.

| Technique | Baseline (pass-through) | Treatment (enforcing) |
|-----------|-------------------------|------------------------|
| `T1528` Steal Application Access Token | reached | reached |
| `T1550.001` Use Application Access Token | reached | reached |
| `T1078.004` Valid Accounts: Cloud Accounts | reached | **blocked** |
| `T1552` Unsecured Credentials | reached | not reached |
| `T1070` Indicator Removal | reached | not reached |
| **chain** | **COMPLETES** | **BROKEN at T1078.004** |
| secrets harvested | 2 | 0 |

The theft succeeds in both runs. The control stops the pivot, not the theft, and claiming otherwise
would overstate it. There is a test that asserts exactly this (`test_theft_still_succeeds_in_both_runs`).

Three distinct defences fire at the delegation step, one per property of the bounded token:

```
bulk query        -> insufficient scope: records:bulkQuery not granted   (least scope)
pivot to resource-b -> audience mismatch                                 (single pinned audience)
broker escalation -> may_act: actor not authorised to act for subject    (principal)
```

## Quick start

No Docker required. Only three third-party packages, all on PyPI.

```bash
pip install -r requirements.txt

python scripts/seed.py         # show the principals, audiences and the starting grant
python attack/baseline.py      # expected: chain COMPLETES
python attack/treatment.py     # expected: chain FAILS at the delegation step
python attack/compare.py       # the before/after table above
python -m pytest tests/ -v     # 20 tests, including the HTTP topology
python attack/ablation.py      # which property carries the result
```

Container topology, five services, one per component:

```bash
docker compose up -d
docker compose run --rm runner python attack/http_chain.py
BROKER_MODE=passthrough docker compose up -d broker   # reproduce the baseline
```

## The control under test

The broker enforces a bounded token shape whose four properties each close one property of the
**transitive-delegation primitive** defined in the dissertation:

| Token property | Enforced value | Primitive property closed |
|----------------|----------------|---------------------------|
| `aud` | exactly one resource server | revocation boundary |
| `scope` | least privilege for the task, never the inherited scope | delegated scope |
| `exp` | 300 seconds, no refresh | trust-compounding step |
| `act` / `may_act` | delegation recorded and pre-authorised | principal |

All four live in [`policy/broker-policy.yaml`](policy/broker-policy.yaml), which is the single
source of truth read by both the in-process and the HTTP paths.

## Layout

| Path | Role |
|------|------|
| `lab/jwtutil.py` | RS256 keypair, token minting, the `act` and `may_act` claims |
| `lab/policy.py` | loads and applies the broker policy |
| `lab/services.py` | the five components: IdP, broker, resource, log sink, agent |
| `lab/chain.py` | the five-stage kill chain, parameterised by mode |
| `lab/serve.py` | HTTP entrypoints for the container topology, with JWKS |
| `lab/http_common.py` | a small JSON-over-HTTP layer on the standard library |
| `attack/` | `baseline.py`, `treatment.py`, `compare.py`, `ablation.py`, `http_chain.py` |
| `policy/` | the declarative broker policy |
| `detection/` | Sigma rule for the delegation event |
| `tests/` | 20 tests: the headline result, the four bounded properties, the ablation, the HTTP path |
| `docs/` | runbook, architecture note, coding workbook |

## Which property carries the result

`python attack/ablation.py` disables each bounded-token property in turn, then every combination,
and reports where the chain breaks. Measured on this implementation:

| Disabled | Chain | Breaks at |
|----------|-------|-----------|
| none (treatment) | broken | `T1078.004` |
| least scope | **COMPLETES** | - |
| single pinned audience | broken | `T1552` |
| short lifetime | broken | `T1078.004` |
| `may_act` | broken | `T1078.004` |

**Least scope carries the single-hop result**: disabling it alone restores the chain.
**Audience pinning is the second line**: disabling it moves the break downstream rather than
removing it, because the pivot then succeeds but the bulk query that feeds the harvest does not.
**Short lifetime and `may_act` are not exercised by this chain**, which replays the stolen token
immediately and never needs the broker to escalate. They guard variants this chain does not
contain, and reporting them as load-bearing here would overstate the result.

## Reproducibility status

Against the USENIX artifact-evaluation vocabulary this artefact targets the **Available** and
**Functional** badges. It does **not** claim **Reproduced** in the strong sense: what is
demonstrated is the binary structural fact, not an independently verified performance measurement
or an adversarial-scale result. Latency figures quoted in the dissertation are labelled illustrative.

The result is deterministic. `test_result_is_deterministic_across_runs` asserts that five
consecutive treatment runs all break at `T1078.004`.

## Source verification log

`docs/source-verification-log.md` records how every empirical claim in the dissertation was
checked: the primary source reached, the verbatim text it carries, and whether a second,
independent pass instructed to refute the claim could break it. Where a source is paywalled,
most often an ISO/IEC standard, the log says exactly which parts were reachable rather than
glossing over it. An examiner can re-run any row.

## Coding workbook

`docs/coding-workbook.csv` holds the per-cell rationales behind the gap matrix: for each
instrument-dimension cell, the verdict, the clause identifier relied upon (or the documented
absence), and the rater's justification. This is the artefact that makes the rubric re-runnable by a
second rater.

## Scope and ethics

All adversarial code targets only this disposable local environment. Nothing here touches a live
system, a production tenant or a third-party service, and no personal data is processed. The
governance gaps analysed in the dissertation are properties of open, published standards. The
RSA keypair is generated at start-up and discarded on shutdown; there are no secrets in this
repository, and the strings that look like credentials are inert fixtures the `T1552` stage
harvests.

## Licence

MIT for the code. The dissertation text is the author's own and is not covered by this licence.
