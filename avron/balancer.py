"""Upstream pool: selection strategy, in-flight tracking and health.

A route no longer points at one URL. It owns a pool of upstreams and a strategy
for choosing between them. Whatever the strategy picks, a failed attempt falls
through to the next healthy candidate, so every strategy is also a failover
chain — the strategy only decides the order to try them in.

Health state lives in memory, not the database: it is per-process and worthless
after a restart, and writing a row on every request would be the slowest part of
the hot path.
"""

import itertools
import logging
import random
import threading
import time
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

STRATEGIES = {
    "failover": "Active / passive. Always the highest priority that is healthy.",
    "round_robin": "Rotate through every healthy upstream in turn.",
    "least_busy": "Whichever has the fewest requests in flight right now.",
    "weighted": "Random, biased by weight.",
}

# Failures compound: 10s, 20s, 40s ... capped. A flapping provider gets
# sidelined for longer each time instead of being retried on every request.
BASE_COOLDOWN = 10
MAX_COOLDOWN = 300


class _State:
    __slots__ = ("inflight", "failures", "cooldown_until", "ok", "fail", "last_error",
                 "last_used", "total_latency")

    def __init__(self) -> None:
        self.inflight = 0
        self.failures = 0
        self.cooldown_until = 0.0
        self.ok = 0
        self.fail = 0
        self.last_error = ""
        self.last_used = 0.0
        self.total_latency = 0.0


class Pool:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._state: Dict[int, _State] = {}
        self._rr: Dict[int, itertools.count] = {}

    def state(self, upstream_id: int) -> _State:
        with self._lock:
            return self._state.setdefault(upstream_id, _State())

    # ------------------------------------------------------------ health
    def healthy(self, upstream_id: int) -> bool:
        return self.state(upstream_id).cooldown_until <= time.time()

    def cooldown_left(self, upstream_id: int) -> int:
        return max(0, int(self.state(upstream_id).cooldown_until - time.time()))

    def record_success(self, upstream_id: int, latency: float) -> None:
        s = self.state(upstream_id)
        with self._lock:
            s.failures = 0
            s.cooldown_until = 0.0
            s.ok += 1
            s.last_error = ""
            s.total_latency += latency

    def record_failure(self, upstream_id: int, error: str) -> None:
        s = self.state(upstream_id)
        with self._lock:
            s.failures += 1
            s.fail += 1
            s.last_error = error[:200]
            delay = min(BASE_COOLDOWN * (2 ** (s.failures - 1)), MAX_COOLDOWN)
            s.cooldown_until = time.time() + delay
        logger.warning(
            "Upstream %s failed (%s). Sidelined for %ds.", upstream_id, error[:80], delay
        )

    def enter(self, upstream_id: int) -> None:
        s = self.state(upstream_id)
        with self._lock:
            s.inflight += 1
            s.last_used = time.time()

    def leave(self, upstream_id: int) -> None:
        s = self.state(upstream_id)
        with self._lock:
            s.inflight = max(0, s.inflight - 1)

    # ----------------------------------------------------------- ordering
    def order(self, upstreams: List[dict], strategy: str) -> List[dict]:
        """Return every enabled upstream, best candidate first.

        Unhealthy ones are not dropped, only pushed to the back: if every
        upstream is in cooldown we still try rather than fail the request.
        """
        live = [u for u in upstreams if u["enabled"]]
        if not live:
            return []

        healthy = [u for u in live if self.healthy(u["id"])]
        cooling = sorted(
            (u for u in live if not self.healthy(u["id"])),
            key=lambda u: self.state(u["id"]).cooldown_until,
        )

        if strategy == "round_robin":
            if healthy:
                key = id(upstreams)
                counter = self._rr.setdefault(key, itertools.count())
                offset = next(counter) % len(healthy)
                healthy = healthy[offset:] + healthy[:offset]
        elif strategy == "least_busy":
            healthy.sort(
                key=lambda u: (self.state(u["id"]).inflight, self.state(u["id"]).last_used)
            )
        elif strategy == "weighted":
            healthy = _weighted_shuffle(healthy)
        else:  # failover
            healthy.sort(key=lambda u: (u["priority"], u["id"]))

        return healthy + cooling

    # -------------------------------------------------------------- report
    def report(self, upstreams: List[dict]) -> List[dict]:
        out = []
        for u in upstreams:
            s = self.state(u["id"])
            out.append({
                "id": u["id"],
                "name": u["name"],
                "url": u["url"],
                "enabled": bool(u["enabled"]),
                "priority": u["priority"],
                "weight": u["weight"],
                "inflight": s.inflight,
                "ok": s.ok,
                "fail": s.fail,
                "cooldown": self.cooldown_left(u["id"]),
                "last_error": s.last_error,
                "avg_ms": int(1000 * s.total_latency / s.ok) if s.ok else 0,
            })
        return out


def _weighted_shuffle(items: List[dict]) -> List[dict]:
    """Order by weighted random draw without replacement."""
    pool = list(items)
    out = []
    while pool:
        total = sum(max(1, u["weight"]) for u in pool)
        pick = random.uniform(0, total)
        running = 0.0
        for i, u in enumerate(pool):
            running += max(1, u["weight"])
            if pick <= running:
                out.append(pool.pop(i))
                break
        else:
            out.append(pool.pop())
    return out


pool = Pool()
