"""Baseline run: implicit scope inheritance, the broker in pass-through.

Expected outcome: the chain COMPLETES. This is the field condition, and it
confirms operationally what the gap matrix asserts analytically.
"""
import sys

from _driver import execute

if __name__ == "__main__":
    sys.exit(execute("passthrough", "BASELINE: implicit scope inheritance"))
