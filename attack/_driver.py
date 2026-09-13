"""Shared driver for the two attack runs."""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lab import chain  # noqa: E402

RESULTS = os.path.join(ROOT, "results")

BAR = "=" * 78


def execute(mode: str, label: str) -> int:
    result, log = chain.run(mode)

    print(BAR)
    print(f"  {label}   (broker mode: {mode})")
    print(BAR)
    for stage in result.stages:
        mark = "PASS" if stage.succeeded else "FAIL"
        print(f"  [{mark}] {stage.technique:<10} {stage.name}")
        print(f"         {stage.detail}")
    print("-" * 78)
    if result.completed:
        print("  CHAIN COMPLETED.")
        print(f"  Secrets harvested: {len(result.secrets_harvested)}")
        for secret in result.secrets_harvested:
            print(f"    - {secret}")
    else:
        print(f"  CHAIN BROKEN at {result.broke_at}, the delegation step.")
        print(f"  Reason: {result.broke_reason}")
        print(f"  Secrets harvested: {len(result.secrets_harvested)}")
    refusals = log.of_type("refuse")
    if refusals:
        print(f"  Broker refusals logged: {len(refusals)}")
        for event in refusals:
            print(f"    - {event['reason']}")
    print(BAR)

    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, f"{mode}.json"), "w", encoding="utf-8") as fh:
        json.dump(result.as_dict(), fh, indent=2)
    log.dump(os.path.join(RESULTS, f"{mode}-telemetry.json"))
    print(f"  Written: results/{mode}.json and results/{mode}-telemetry.json\n")

    # Exit code 0 means "the run behaved as the experiment predicts".
    expected_completion = (mode == "passthrough")
    return 0 if result.completed == expected_completion else 1
