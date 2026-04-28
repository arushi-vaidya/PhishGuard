"""
DNS Sinkhole — in-memory local DNS resolver for phishing blocking.

Better than /etc/hosts because:
- No disk writes (all state in memory)
- Entries can expire automatically via TTL
- Clean start/stop without leaving system files modified
- Intercepts all DNS query types, not just A-record lookups

Usage:
    sinkhole = DNSSinkhole(port=5053)
    sinkhole.start()
    sinkhole.block_domain("evil-phish.com", ttl_seconds=3600)
    # configure system resolver to 127.0.0.1:5053 (or use port 53 with sudo)
    sinkhole.stop()
"""

import threading
import logging
import pickle
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

try:
    from dnslib import DNSRecord, RCODE
    from dnslib.server import DNSServer, BaseResolver
    HAS_DNSLIB = True
except ImportError:
    HAS_DNSLIB = False
    logger.warning("dnslib not installed — DNS sinkhole unavailable. Run: pip install dnslib")


class _BlockEntry:
    __slots__ = ('domain', 'blocked_at', 'expires_at')

    def __init__(self, domain: str, expires_at: Optional[datetime]):
        self.domain = domain
        self.blocked_at = datetime.now()
        self.expires_at = expires_at

    def is_expired(self) -> bool:
        return self.expires_at is not None and datetime.now() > self.expires_at


if HAS_DNSLIB:
    class _SinkholeResolver(BaseResolver):
        """dnslib resolver: NXDOMAIN for blocked domains, proxy for everything else."""

        def __init__(self, upstream_dns: str = "8.8.8.8", upstream_port: int = 53):
            self._entries: Dict[str, _BlockEntry] = {}
            self._lock = threading.Lock()
            self._upstream = upstream_dns
            self._upstream_port = upstream_port

        def block(self, domain: str, ttl_seconds: Optional[int] = None):
            key = domain.lower().rstrip('.')
            expires_at = (datetime.now() + timedelta(seconds=ttl_seconds)) if ttl_seconds else None
            with self._lock:
                self._entries[key] = _BlockEntry(key, expires_at)

        def unblock(self, domain: str):
            with self._lock:
                self._entries.pop(domain.lower().rstrip('.'), None)

        def is_blocked(self, domain: str) -> bool:
            key = domain.lower().rstrip('.')
            with self._lock:
                entry = self._entries.get(key)
                if entry is None:
                    return False
                if entry.is_expired():
                    del self._entries[key]
                    return False
                return True

        def get_blocklist(self) -> list:
            with self._lock:
                expired = [d for d, e in self._entries.items() if e.is_expired()]
                for d in expired:
                    del self._entries[d]
                return list(self._entries.keys())

        def resolve(self, request, handler):
            qname = str(request.q.qname).rstrip('.')
            if self.is_blocked(qname):
                reply = request.reply()
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
                return reply
            # Forward to upstream
            try:
                raw = request.send(self._upstream, self._upstream_port, timeout=5)
                return DNSRecord.parse(raw)
            except Exception as e:
                logger.debug(f"Upstream DNS error for {qname}: {e}")
                reply = request.reply()
                reply.header.rcode = getattr(RCODE, 'SERVFAIL')
                return reply


class DNSSinkhole:
    """
    Local DNS sinkhole server.

    Listens on 127.0.0.1:5053 by default (no root needed).
    For system-wide interception, run with sudo and use port=53, then point
    your system DNS to 127.0.0.1.

    Blocked domains get NXDOMAIN. All other queries are forwarded to upstream.
    """

    def __init__(self, port: int = 5053, upstream_dns: str = "8.8.8.8"):
        if not HAS_DNSLIB:
            raise ImportError("dnslib is required. Install with: pip install dnslib>=0.9.1")
        self._port = port
        self._resolver = _SinkholeResolver(upstream_dns)
        self._server: Optional["DNSServer"] = None
        self._running = False

    def start(self):
        self._server = DNSServer(self._resolver, port=self._port, address="127.0.0.1")
        self._server.start_thread()
        self._running = True
        logger.info(f"DNS sinkhole listening on 127.0.0.1:{self._port} (upstream: {self._resolver._upstream})")
        logger.info("Configure system DNS to 127.0.0.1 (or use dig @127.0.0.1 -p %d) to intercept queries" % self._port)

    def stop(self):
        if self._server:
            self._server.stop()
        self._running = False
        logger.info("DNS sinkhole stopped — no system files were modified")

    def block_domain(self, domain: str, ttl_seconds: Optional[int] = None):
        self._resolver.block(domain, ttl_seconds)
        expiry = f" (expires in {ttl_seconds}s)" if ttl_seconds else " (permanent until stop)"
        logger.info(f"Sinkhole blocked: {domain}{expiry}")

    def unblock_domain(self, domain: str):
        self._resolver.unblock(domain)
        logger.info(f"Sinkhole unblocked: {domain}")

    def is_running(self) -> bool:
        return self._running

    def is_blocked(self, domain: str) -> bool:
        return self._resolver.is_blocked(domain)

    def get_blocklist(self) -> list:
        return self._resolver.get_blocklist()

    @property
    def port(self) -> int:
        return self._port


# Module-level singleton so decision_engine and blocking_system share the same instance
_instance: Optional[DNSSinkhole] = None


def get_sinkhole(port: int = 5053) -> Optional[DNSSinkhole]:
    """Return the shared DNSSinkhole, creating it if needed. Returns None if dnslib missing."""
    global _instance
    if not HAS_DNSLIB:
        return None
    if _instance is None:
        _instance = DNSSinkhole(port=port)
    return _instance
