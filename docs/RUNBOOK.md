# Runbook

Ordered procedure to reproduce the binary result reported in Section 5.5 of the dissertation.

## 0. Prerequisites

Python 3.11 or later. Three third-party packages:

```bash
pip install -r requirements.txt
```

Docker is optional and only needed for the container topology in step 7. No network access outside
the local machine is required or used at any point.

## 1. Inspect the starting condition

```bash
python scripts/seed.py
```

This prints the principals, the two audiences, the shape of the initial standing grant and the
broker policy. The grant models the field condition: broad scope, both audiences, a thirty-day
lifetime. Confirm before proceeding that the policy shows `mode: enforcing`, a single allowed
audience, `records:read:single` as the only allowed scope, and a 300-second lifetime.

## 2. Baseline run: implicit scope inheritance

```bash
python attack/baseline.py
```

The broker runs in pass-through mode, which is the dominant field pattern. The attack script
executes the five stages of the reconstructed chain.

**Expected:** chain COMPLETES, two embedded secrets harvested, query-job records deleted.
Written to `results/passthrough.json` and `results/passthrough-telemetry.json`.

## 3. Treatment run: RFC 8693 bounded delegation

```bash
python attack/treatment.py
```

Identical script, identical attacker capability. The only change is that the agent must obtain a
bounded token from the broker before each resource call.

**Expected:** chain BROKEN at `T1078.004`, the delegation step, with zero secrets harvested and one
broker refusal logged. Written to `results/enforcing.json` and `results/enforcing-telemetry.json`.

## 4. Compare

```bash
python attack/compare.py
```

Emits the before/after stage table, the telemetry counts for each run, and the detection-rule hits.
The final line reads `RESULT: as predicted` when the experiment behaves as the dissertation claims.

## 5. Run the test suite

```bash
python -m pytest tests/ -v
```

Twenty tests. Five groups:

- the headline result (baseline completes, treatment breaks at the named step);
- the honest boundary (the theft still succeeds in both runs);
- the four bounded properties, one test each for audience pinning, least scope, lifetime and the
  `act` / `may_act` claims, plus scope-escalation refusal and expiry;
- the ablation results of step 6, pinned so that a regression would fail the suite;
- the HTTP topology, which starts the five services as subprocesses and runs the chain over HTTP.

## 6. Ablation: which property carries the result?

```bash
python attack/ablation.py
```

The treatment switches on four properties at once, which answers "does the control work" but not
"which part of it does the work". This script disables each in turn, then every combination, and
reports where the chain breaks. The measured result on this implementation:

| Disabled | Chain | Breaks at | Secrets |
|----------|-------|-----------|---------|
| none (treatment) | broken | `T1078.004` | 0 |
| least scope | **COMPLETES** | - | 2 |
| single pinned audience | broken | `T1552` | 0 |
| short lifetime | broken | `T1078.004` | 0 |
| `may_act` | broken | `T1078.004` | 0 |
| all four | **COMPLETES** | - | 2 |

Three things follow, and the dissertation states them rather than claiming all four properties are
equally load-bearing.

**Least scope carries the single-hop result.** Disabling it alone restores the chain completely.

**Audience pinning is the second line.** Disabling it does not restore the chain but moves the break
downstream from `T1078.004` to `T1552`: the attacker now reaches a valid cloud account on the second
resource, yet the bulk query that feeds the harvest is still refused, so nothing is taken.

**Short lifetime and `may_act` are not exercised by this chain.** The attacker replays the stolen
token immediately, so the 300-second expiry never fires, and the chain has other paths available so
it never depends on the broker escalating. They guard variants this chain does not contain, notably
delayed replay and an attacker who must trade a token up. Reporting them as load-bearing here would
overstate the result.

`results/ablation.json` records all sixteen configurations.

## 7. Container topology (optional)

```bash
docker compose up -d
docker compose run --rm runner python attack/http_chain.py
docker compose down -v
```

Five services, one per component, each verifying tokens against the IdP's published JWKS. Set
`BROKER_MODE=passthrough` to reproduce the baseline condition in containers.

## What a replicator should check

1. The treatment run fails at the **named** step, not merely somewhere.
2. Three distinct defences are reported at that step: insufficient scope, audience mismatch, and the
   `may_act` refusal. Each corresponds to one property of the bounded token.
3. The `act` claim is present, names the agent as actor, and leaves the human as subject.
4. The bounded token's lifetime is minutes, not hours.
5. The refusal appears in the telemetry as a distinct reviewable event, which is what makes the
   previously invisible delegation step observable.
