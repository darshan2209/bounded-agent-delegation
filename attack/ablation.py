"""Ablation study: which property of the bounded token carries the result?

The treatment run switches on four properties at once. That answers "does the
control work" but not "which part of it does the work". This script disables
each property in turn, and then every combination, and reports where the chain
breaks in each configuration.

    python attack/ablation.py
"""
from __future__ import annotations

import itertools
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lab import chain, policy as policy_mod  # noqa: E402

PROPERTIES = ["audience", "scope", "ttl", "may_act"]
LABEL = {
    "audience": "single pinned audience",
    "scope": "least scope",
    "ttl": "short lifetime",
    "may_act": "may_act pre-authorisation",
}


def run_with(ablated: frozenset[str]):
    original = policy_mod.load

    def patched(path=policy_mod.POLICY_PATH, mode_override=None):
        pol = original(path, mode_override=mode_override)
        pol.ablate = ablated
        return pol

    policy_mod.load = patched
    try:
        return chain.run("enforcing")[0]
    finally:
        policy_mod.load = original


def main() -> int:
    rows = []

    # All four active: the treatment condition.
    result = run_with(frozenset())
    rows.append(("none (treatment)", result))

    # Each property disabled on its own.
    for prop in PROPERTIES:
        rows.append((f"-{prop}", run_with(frozenset({prop}))))

    # Every pair, triple and the full set.
    for size in (2, 3, 4):
        for combo in itertools.combinations(PROPERTIES, size):
            rows.append(("-" + ",".join(combo), run_with(frozenset(combo))))

    print(f"{'disabled':<34} {'chain':<12} {'breaks at':<12} secrets")
    print("-" * 72)
    for label, res in rows:
        state = "COMPLETES" if res.completed else "broken"
        print(f"{label:<34} {state:<12} {str(res.broke_at or '-'):<12} "
              f"{len(res.secrets_harvested)}")
    print("-" * 72)

    singles = [(p, run_with(frozenset({p}))) for p in PROPERTIES]
    sufficient = [p for p, r in singles if r.completed]
    print("\nInterpretation")
    print("-" * 72)
    if not sufficient:
        print("  No single property is load-bearing on its own: the chain still breaks")
        print("  when any one of the four is disabled. The control is over-determined,")
        print("  which means the four properties are mutually reinforcing rather than")
        print("  one of them doing all the work.")
    else:
        for prop in sufficient:
            print(f"  Disabling {LABEL[prop]} alone restores the chain.")

    minimal = None
    for size in range(1, 5):
        for combo in itertools.combinations(PROPERTIES, size):
            if run_with(frozenset(combo)).completed:
                minimal = combo
                break
        if minimal:
            break
    if minimal:
        print(f"\n  Smallest set of disabled properties that restores the chain: "
              f"{', '.join(LABEL[p] for p in minimal)}")
    else:
        print("\n  The chain never completes while any property remains enforced.")

    out = os.path.join(ROOT, "results", "ablation.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump([{"disabled": label, "completed": res.completed,
                    "broke_at": res.broke_at,
                    "secrets": len(res.secrets_harvested)} for label, res in rows],
                  fh, indent=2)
    print(f"\n  Written: results/ablation.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
