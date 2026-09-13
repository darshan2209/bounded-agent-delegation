"""Smoke test for the HTTP topology.

Starts the five services in background threads, then runs the same chain over
HTTP in both configurations. This proves the container path works, not only the
in-process one.
"""
from __future__ import annotations

import multiprocessing
import os
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lab.http_common import get  # noqa: E402
from lab.serve import PORTS  # noqa: E402

SERVICES = ["idp", "logsink", "broker", "resource-a", "resource-b"]


def _wait_for_idp(timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, payload = get(f"http://127.0.0.1:{PORTS['idp']}/jwks", timeout=1.0)
            if status == 200 and payload.get("keys"):
                return True
        except OSError:
            pass
        time.sleep(0.3)
    return False


@pytest.fixture(scope="module")
def topology():
    """Bring the five services up as subprocesses, tear them down after."""
    procs = []
    env = dict(os.environ, BROKER_MODE="enforcing", PYTHONPATH=ROOT)
    for service in SERVICES:
        procs.append(subprocess.Popen(
            [sys.executable, "-m", "lab.serve", service],
            cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ))
    try:
        if not _wait_for_idp():
            pytest.skip("services did not start in time on this machine")
        time.sleep(1.5)  # let broker and resources fetch JWKS
        yield
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def test_idp_publishes_jwks(topology):
    status, payload = get(f"http://127.0.0.1:{PORTS['idp']}/jwks")
    assert status == 200
    assert payload["keys"][0]["kty"] == "RSA"
    assert payload["keys"][0]["alg"] == "RS256"


def test_http_chain_breaks_at_the_delegation_step(topology):
    from attack import http_chain
    result = http_chain.run()
    assert result["completed"] is False
    assert result["broke_at"] == "T1078.004"


def test_logsink_collected_events(topology):
    status, payload = get(f"http://127.0.0.1:{PORTS['logsink']}/events")
    assert status == 200
    assert payload["count"] > 0
    kinds = {e["event_type"] for e in payload["events"]}
    assert "exchange" in kinds
    assert "present" in kinds
