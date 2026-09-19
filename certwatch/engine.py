"""Glue: certificate -> detector -> dedup -> (enrich) -> outputs."""
from __future__ import annotations

import logging
import queue
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .detector import BrandDetector
from .enrich import resolve_ips
from .models import Finding, severity_rank
from .outputs import Output

log = logging.getLogger("certwatch.engine")


@dataclass
class Stats:
    started: float = field(default_factory=time.time)
    certs: int = 0
    domains: int = 0
    matches: int = 0
    reported: int = 0
    dropped: int = 0

    def summary(self) -> str:
        elapsed = max(1.0, time.time() - self.started)
        return (
            f"certs={self.certs} ({self.certs / elapsed:.0f}/s) domains={self.domains} "
            f"matches={self.matches} reported={self.reported} dropped={self.dropped}"
        )


def _iso(ts: Any) -> Optional[str]:
    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")
        except (OverflowError, OSError, ValueError):
            return None
    return None


class Engine:
    def __init__(
        self,
        detector: BrandDetector,
        outputs: Sequence[Output],
        resolve: bool = False,
        min_severity: str = "LOW",
        workers: int = 4,
        queue_size: int = 2000,
        dedup_ttl: int = 3600,
        dedup_max: int = 50_000,
        drop_when_full: bool = True,
    ):
        self.detector = detector
        self.outputs = list(outputs)
        self.resolve = resolve
        self.min_rank = severity_rank(min_severity)
        self.stats = Stats()
        self._drop_when_full = drop_when_full
        self._dedup: "OrderedDict[Tuple[str, str], float]" = OrderedDict()
        self._dedup_ttl, self._dedup_max = dedup_ttl, dedup_max
        self._queue: "queue.Queue[Optional[Finding]]" = queue.Queue(maxsize=queue_size)
        self._threads: List[threading.Thread] = [
            threading.Thread(target=self._worker, name=f"certwatch-worker-{i}", daemon=True)
            for i in range(max(1, workers))
        ]
        for t in self._threads:
            t.start()

    # -- ingest ------------------------------------------------------------ #
    def handle_certificate(self, data: Dict[str, Any]) -> None:
        leaf = data.get("leaf_cert") or {}
        domains = leaf.get("all_domains") or []
        self.stats.certs += 1

        # One alert per (registered domain, brand) per certificate: "evil.xyz" and
        # "www.evil.xyz" in the same cert are one incident. All SANs are kept in the record.
        best: Dict[Tuple[str, str], Finding] = {}
        for name in domains:
            self.stats.domains += 1
            finding = self.detector.analyze(name)
            if finding is None:
                continue
            key = (finding.registered_domain, finding.target)
            if key not in best or finding.score > best[key].score:
                best[key] = finding

        meta = None
        for finding in best.values():
            if self._seen(finding):
                continue
            if meta is None:
                meta = self._cert_meta(data, leaf, domains)
            for key, value in meta.items():
                setattr(finding, key, value)
            self.stats.matches += 1
            try:
                if self._drop_when_full:
                    self._queue.put_nowait(finding)
                else:
                    self._queue.put(finding)
            except queue.Full:
                self.stats.dropped += 1

    def drain(self, timeout: float = 15.0) -> None:
        """Wait for queued findings to be processed (bounded), then stop the workers."""
        deadline = time.time() + timeout
        while self._queue.unfinished_tasks and time.time() < deadline:
            time.sleep(0.05)
        for _ in self._threads:
            try:
                self._queue.put(None, timeout=1)
            except queue.Full:
                break
        for t in self._threads:
            t.join(timeout=max(0.1, deadline - time.time()))
        for out in self.outputs:
            try:
                out.close()
            except Exception:  # noqa: BLE001
                pass

    # -- internals --------------------------------------------------------- #
    def _seen(self, f: Finding) -> bool:
        key, now = (f.domain, f.target), time.monotonic()
        ts = self._dedup.get(key)
        if ts is not None and now - ts < self._dedup_ttl:
            return True
        self._dedup[key] = now
        self._dedup.move_to_end(key)
        while len(self._dedup) > self._dedup_max:
            self._dedup.popitem(last=False)
        return False

    @staticmethod
    def _cert_meta(data: Dict[str, Any], leaf: Dict[str, Any], domains: List[str]) -> Dict[str, Any]:
        issuer = leaf.get("issuer") or {}
        return {
            "issuer": issuer.get("O") or issuer.get("CN") or issuer.get("aggregated"),
            "cert_fingerprint": leaf.get("fingerprint"),
            "not_before": _iso(leaf.get("not_before")),
            "not_after": _iso(leaf.get("not_after")),
            "log_source": (data.get("source") or {}).get("name"),
            "san_count": len(domains),
            "sans": list(domains[:20]),
        }

    def _worker(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                self._process(item)
            except Exception:  # noqa: BLE001
                log.exception("Failed to process finding")
            finally:
                self._queue.task_done()

    def _process(self, f: Finding) -> None:
        if self.resolve:
            f.ips = resolve_ips(f.domain)
            f.resolved = bool(f.ips)
            if f.resolved:
                f.bump(5, "Domain already resolves in DNS")
        rank = severity_rank(f.severity)
        if rank < self.min_rank:
            return
        self.stats.reported += 1
        for out in self.outputs:
            if rank < out.min_rank:
                continue
            try:
                out.emit(f)
            except Exception as exc:  # noqa: BLE001
                log.warning("Output '%s' failed: %s", out.name, exc)
