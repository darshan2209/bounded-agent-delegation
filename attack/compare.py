"""Emit the before/after comparison table reported in Section 5.5."""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lab import chain  # noqa: E402


def main() -> int:
    base, base_log = chain.run("passthrough")
    treat, treat_log = chain.run("enforcing")

    rows = []
    for stage_b, stage_t in zip(base.stages, treat.stages + [None] * 5):
        rows.append((
            stage_b.technique,
            "reached" if stage_b.succeeded else "blocked",
            ("reached" if stage_t.succeeded else "blocked") if stage_t else "not reached",
        ))

    print(f"{'Technique':<12} {'Baseline':<14} {'Treatment':<14}")
    print("-" * 42)
    for tech, b, t in rows:
        print(f"{tech:<12} {b:<14} {t:<14}")
    print("-" * 42)
    print(f"{'chain':<12} {'COMPLETES':<14} "
          f"{('COMPLETES' if treat.completed else 'BROKEN at ' + str(treat.broke_at)):<14}")
    print(f"{'secrets':<12} {len(base.secrets_harvested):<14} {len(treat.secrets_harvested):<14}")
    print()

    print("Telemetry")
    print("-" * 42)
    for label, log in (("baseline", base_log), ("treatment", treat_log)):
        counts = {}
        for event in log.events:
            counts[event["event_type"]] = counts.get(event["event_type"], 0) + 1
        print(f"  {label:<10} " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print()
    print("Detection-rule hits (delegation-anomaly.yml)")
    print("-" * 42)
    hits = [e for e in treat_log.of_type("refuse") if e.get("may_act_matched") is False]
    print(f"  may_act unmatched exchange attempts: {len(hits)}")
    for hit in hits:
        print(f"    actor={hit.get('actor')} subject={hit.get('subject')}")

    ok = base.completed and not treat.completed and treat.broke_at == "T1078.004"
    print()
    print("RESULT:", "as predicted" if ok else "UNEXPECTED, investigate")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
