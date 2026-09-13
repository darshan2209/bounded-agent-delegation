"""Treatment run: RFC 8693 bounded delegation enforced by the broker.

Exactly one variable changes from the baseline: the agent must obtain a bounded
token before each resource call. Expected outcome: the chain FAILS at the
delegation step, between T1550.001 and T1078.004.
"""
import sys

from _driver import execute

if __name__ == "__main__":
    sys.exit(execute("enforcing", "TREATMENT: RFC 8693 bounded delegation"))
