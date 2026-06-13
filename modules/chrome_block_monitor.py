""
Chrome & Laptop Block Monitor

Detects dom

"""
Chrome & Laptop Block Monitor

Detects domains that are blocked by the user's local environment — even when
PhishGuard's own engine never had a chance to see them. Specifically:

  • Browser-level blocks      (Chrome / Edge interrupted downloads, malware,
                               policy, parental controls — read from the
                               browser History SQLite database)
  • OS hosts-file blocks      (entries in C:\\Windows\\System32\\drivers\\etc\\hosts
                               or /etc/hosts pointing to 0.0.0.0 / 127.0.0.1)
  • Network-level blocks      (SSL/TLS errors, DNS NXDOMAIN, connection
                               refused/reset, timeouts — discovered by an
                               active HTTPS probe of recently-seen domains)

Every detected block is funnelled into :class:`SystemBlockDetector` so it
shows up in the dashboard's unified "blocked" feed.

Cross-platform: works on Windows, macOS, Linux. No admin required.

Author: Research Team
Date: 2026
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import socket
import sqlite3
import ssl
import tempfile
import threading
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    import requests
except ImportError:  # pragma: no cover - requests is in requirements.txt
    requests = None  # type: ignore

from .system_block_detector import SystemBlockDetector, SystemBlockType

logger = logging.getLogger(__name__)


# ── Chrome / Edge download interrupt reasons ────────────────────────────────
# https://source.chromium.org/chromium/chromium/src/+/main:components/download/public/common/download_interrupt_reasons.h
# We only surface reasons that mean "the browser refused to keep this file".
_CHROME_BLOCK_INTERRUPT_REASONS: Dict[int, str] = {
    20: "FILE_BLOCKED (policy)",
    21: "FILE_SECURITY_CHECK_FAILED",
    32: "NETWORK_INVALID_REQUEST",
    33: "NETWORK_SERVER_DOWN",
    36: "NETWORK_SSL_PROTOCOL_ERROR",
    37: "NETWORK_SERVER_CERT_PROBLEM",
    38: "NETWORK_SERVER_UNAUTHORIZED",
    39: "NETWORK_SERVER_FORBIDDEN",
    40: "NETWORK_SERVER_UNREACHABLE",
    50: "SERVER_BAD_CONTENT",
    51: "SERVER_UNAUTHORIZED",
    52: "SERVER_CERT_PROBLEM",
    53: "SERVER_FORBIDDEN",
    54: "SERVER_UNREACHABLE",
    # 4 is "Blocked dangerous" in newer Chrome
    4: "DANGEROUS_FILE_BLOCKED",
}

# Chrome download.state codes: 0=in progress, 1=complete, 2=cancelled,
# 3=interrupted (legacy), 4=interrupted (current).  Anything != 1 with
# an interrupt_reason is treated as a block candidate.
_CHROME_BLOCKED_STATES = {2, 3, 4}

# Chrome `download.danger_type` values that mean the browser actually
# refused / withheld the file (as opposed to merely warning the user).
# See: chrome/browser/download/download_danger_prompt.* and
# components/safe_browsing/content/common/proto/csd.proto
_CHROME_DANGER_TYPE_BLOCKS: Dict[int, str] = {
    7:  "DANGEROUS_HOST (Safe Browsing)",
    8:  "POTENTIALLY_UNWANTED",
    11: "BLOCKED_PASSWORD_PROTECTED",
    12: "BLOCKED_TOO_LARGE",
    13: "BLOCKED_SENSITIVE_CONTENT_WARNING",
    14: "BLOCKED_SENSITIVE_CONTENT_BLOCK",
    15: "DEEP_SCANNED_SAFE_BUT_BLOCKED",
    16: "BLOCKED_UNSUPPORTED_FILETYPE",
    17: "DANGEROUS_ACCOUNT_COMPROMISE",
    18: "DEEP_SCANNED_FAILED",
    19: "PROMPT_FOR_LOCAL_PASSWORD_SCANNING",
    20: "BLOCKED_SCAN_FAILED",
}


@dataclass
class LaptopBlockEvent:
    """A single block detected on the user's machine."""
    domain: str
    source: str            # 'chrome', 'edge', 'hosts_file', 'network_probe'
    block_type: str        # firewall / ssl_error / dns_failure / ...
    error_message: str
    destination_ip: str = ""
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())

    def to_dict(self) -> Dict:
        return asdict(self)


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.\-]+$")

# Hosts we never want to probe / scan / log. These are local-development
# artefacts and IPv6 loopback variants, not real outbound traffic, so they
# would otherwise flood the dashboard with bogus "firewall block" events
# whenever the dashboard's own dev server isn't listening on :443.
_LOCAL_HOSTS: set[str] = {
    "localhost", "localhost.localdomain",
    "127.0.0.1", "0.0.0.0", "::", "::1", "[::1]",
    "ip6-localhost", "ip6-loopback",
    "broadcasthost",
}


def _is_local_or_private(host: str) -> bool:
    """True for loopback, link-local, .local mDNS, and RFC1918 ranges."""
    if not host:
        return True
    h = host.lower().strip().strip("[]")
    if h in _LOCAL_HOSTS:
        return True
    if h.endswith(".local") or h.endswith(".localhost") or h.endswith(".lan"):
        return True
    # RFC1918 / loopback / link-local IP literals
    if h.startswith("127.") or h.startswith("10.") or h.startswith("192.168."):
        return True
    if h.startswith("169.254."):  # link-local
        return True
    if h.startswith("172."):
        try:
            second = int(h.split(".", 2)[1])
            if 16 <= second <= 31:
                return True
        except (ValueError, IndexError):
            pass
    return False


def _extract_domain(url_or_host: str) -> str:
    """
    Pull a hostname out of a URL or raw host string.

    Returns "" for empty input, loopback addresses (localhost, 127.0.0.1,
    ::1, …), .local mDNS names, and RFC1918 private ranges — those are
    local-dev traffic, not phishing indicators.
    """
    if not url_or_host:
        return ""
    s = url_or_host.strip().lower()
    if "://" in s:
        try:
            s = urlparse(s).hostname or ""
        except Exception:
            return ""
    # strip port
    s = s.split(":", 1)[0].strip(".")
    if _is_local_or_private(s):
        return ""
    return s if _DOMAIN_RE.match(s) else ""


def _copy_locked_db(src: Path) -> Optional[Path]:
    """Copy a SQLite file (e.g. Chrome's locked History DB) to a temp path."""
    if not src.exists():
        return None
    try:
        fd, tmp = tempfile.mkstemp(prefix="phishguard_", suffix=".sqlite")
        os.close(fd)
        shutil.copy2(src, tmp)
        return Path(tmp)
    except (PermissionError, OSError) as e:
        logger.debug(f"Could not copy {src}: {e}")
        return None


# ────────────────────────────────────────────────────────────────────────────
# Browser History scanner
# ────────────────────────────────────────────────────────────────────────────

class _BrowserHistoryScanner:
    """Scans Chrome / Edge / Brave history databases for blocked events."""

    def __init__(self) -> None:
        self.seen_download_ids: Set[Tuple[str, int]] = set()
        self.seen_visit_ids: Set[Tuple[str, int]] = set()

    def history_paths(self) -> List[Tuple[str, Path]]:
        """Return [(browser_label, path_to_History_db), ...] for installed browsers."""
        home = Path.home()
        candidates: List[Tuple[str, Path]] = []
        system = platform.system().lower()

        if system == "windows":
            local = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
            candidates += [
                ("chrome", local / "Google/Chrome/User Data/Default/History"),
                ("edge",   local / "Microsoft/Edge/User Data/Default/History"),
                ("brave",  local / "BraveSoftware/Brave-Browser/User Data/Default/History"),
            ]
        elif system == "darwin":
            base = home / "Library/Application Support"
            candidates += [
                ("chrome", base / "Google/Chrome/Default/History"),
                ("edge",   base / "Microsoft Edge/Default/History"),
                ("brave",  base / "BraveSoftware/Brave-Browser/Default/History"),
            ]
        else:  # linux
            cfg = home / ".config"
            candidates += [
                ("chrome", cfg / "google-chrome/Default/History"),
                ("edge",   cfg / "microsoft-edge/Default/History"),
                ("brave",  cfg / "BraveSoftware/Brave-Browser/Default/History"),
            ]
        return [(name, p) for name, p in candidates if p.exists()]

    def scan(self) -> List[LaptopBlockEvent]:
        """Scan every installed browser; return only newly-seen block events."""
        events: List[LaptopBlockEvent] = []
        for browser, path in self.history_paths():
            tmp = _copy_locked_db(path)
            if not tmp:
                continue
            try:
                events.extend(self._scan_one(browser, tmp))
            except sqlite3.Error as e:
                logger.debug(f"sqlite error reading {browser} history: {e}")
            finally:
                try:
                    tmp.unlink()
                except OSError:
                    pass
        return events

    def _scan_one(self, browser: str, db: Path) -> List[LaptopBlockEvent]:
        events: List[LaptopBlockEvent] = []
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
        try:
            cur = conn.cursor()

            # ── Blocked / interrupted downloads ────────────────────────────
            # A download is only a *block* when the browser actually withheld
            # the file from the user.  That means either:
            #   * state != 1 (1 = COMPLETE), OR
            #   * an explicit interrupt_reason from the security stack.
            # A non-zero danger_type on a completed download is only a
            # warning the user clicked through, NOT a block, so we ignore it.
            try:
                cur.execute(
                    "SELECT id, tab_url, target_path, state, interrupt_reason, "
                    "       danger_type, start_time "
                    "FROM downloads "
                    "WHERE state != 1 OR interrupt_reason != 0"
                )
                for row in cur.fetchall():
                    dl_id, url, target, state, reason, danger, _start = row
                    key = (browser, int(dl_id))
                    if key in self.seen_download_ids:
                        continue
                    self.seen_download_ids.add(key)

                    domain = _extract_domain(url or "")
                    if not domain:
                        continue

                    reason = int(reason or 0)
                    danger = int(danger or 0)
                    state = int(state or 0)

                    if reason in _CHROME_BLOCK_INTERRUPT_REASONS:
                        label = _CHROME_BLOCK_INTERRUPT_REASONS[reason]
                    elif reason:
                        label = f"INTERRUPT_REASON_{reason}"
                    elif danger in _CHROME_DANGER_TYPE_BLOCKS:
                        label = _CHROME_DANGER_TYPE_BLOCKS[danger]
                    elif state in _CHROME_BLOCKED_STATES:
                        label = "CANCELLED_OR_INTERRUPTED"
                    else:
                        # Not actually blocked, skip
                        continue

                    events.append(LaptopBlockEvent(
                        domain=domain,
                        source=browser,
                        block_type="browser_download_block",
                        error_message=f"{browser.title()} blocked download: {label}",
                    ))
            except sqlite3.Error as e:
                logger.debug(f"{browser} downloads table not available: {e}")

            # ── Visits that ended in a chrome-error://* page ───────────────
            # Chrome rewrites the URL of failed navigations (cert errors,
            # Safe-Browsing interstitials, DNS failures) to
            # "chrome-error://chromewebdata/" with the original URL kept in
            # the visit's redirect chain.  We pick those up via the urls
            # table.
            try:
                cur.execute(
                    "SELECT id, url, last_visit_time "
                    "FROM urls "
                    "WHERE url LIKE 'chrome-error://%' "
                    "   OR url LIKE 'edge-error://%' "
                    "ORDER BY last_visit_time DESC LIMIT 200"
                )
                # We can't always recover the original domain from a
                # chrome-error URL, but Chrome usually appends it as a
                # query/fragment.  Pull anything that looks like a host.
                for row in cur.fetchall():
                    url_id, url, lvt = row
                    key = (browser, int(url_id))
                    if key in self.seen_visit_ids:
                        continue
                    self.seen_visit_ids.add(key)
                    m = re.search(r"https?://([A-Za-z0-9.\-]+)", url or "")
                    domain = _extract_domain(m.group(1)) if m else ""
                    if not domain:
                        continue
                    events.append(LaptopBlockEvent(
                        domain=domain,
                        source=browser,
                        block_type="browser_navigation_block",
                        error_message=f"{browser.title()} showed an error page for {domain}",
                    ))
            except sqlite3.Error:
                pass

        finally:
            conn.close()
        return events

    def recent_domains(self, limit: int = 200, since_hours: int = 24) -> List[str]:
        """Return unique hostnames the user recently visited (for probing)."""
        out: List[str] = []
        seen: Set[str] = set()
        # Chrome stores last_visit_time as microseconds since 1601-01-01.
        epoch_offset_us = 11644473600 * 1_000_000
        cutoff_us = int(time.time() * 1_000_000) - since_hours * 3600 * 1_000_000
        cutoff_chrome = cutoff_us + epoch_offset_us

        for browser, path in self.history_paths():
            tmp = _copy_locked_db(path)
            if not tmp:
                continue
            try:
                conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True, timeout=2)
                try:
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT url FROM urls WHERE last_visit_time > ? "
                        "ORDER BY last_visit_time DESC LIMIT ?",
                        (cutoff_chrome, limit),
                    )
                    for (url,) in cur.fetchall():
                        d = _extract_domain(url)
                        if d and d not in seen:
                            seen.add(d)
                            out.append(d)
                finally:
                    conn.close()
            except sqlite3.Error:
                pass
            finally:
                try:
                    tmp.unlink()
                except OSError:
                    pass
            if len(out) >= limit:
                break
        return out[:limit]


# ────────────────────────────────────────────────────────────────────────────
# Hosts-file scanner
# ────────────────────────────────────────────────────────────────────────────

class _HostsFileScanner:
    """Reads the OS hosts file and reports entries that null-route a domain."""

    BLOCK_TARGETS = {"0.0.0.0", "127.0.0.1", "::", "::1"}

    def __init__(self) -> None:
        self.seen: Set[str] = set()

    def hosts_path(self) -> Path:
        if platform.system().lower() == "windows":
            return Path(os.environ.get("SystemRoot", r"C:\Windows")) / r"System32\drivers\etc\hosts"
        return Path("/etc/hosts")

    def scan(self) -> List[LaptopBlockEvent]:
        path = self.hosts_path()
        if not path.exists():
            return []
        events: List[LaptopBlockEvent] = []
        try:
            for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip, hosts = parts[0], parts[1:]
                if ip not in self.BLOCK_TARGETS:
                    continue
                for host in hosts:
                    domain = _extract_domain(host)
                    if not domain or domain in self.seen:
                        continue
                    self.seen.add(domain)
                    events.append(LaptopBlockEvent(
                        domain=domain,
                        source="hosts_file",
                        block_type="firewall",
                        destination_ip=ip,
                        error_message=f"Hosts file null-routes {domain} → {ip}",
                    ))
        except (OSError, UnicodeDecodeError) as e:
            logger.debug(f"hosts file unreadable: {e}")
        return events


# ────────────────────────────────────────────────────────────────────────────
# Active network probe
# ────────────────────────────────────────────────────────────────────────────

class _NetworkProbe:
    """Best-effort HTTPS probe to discover network/SSL/DNS blocks."""

    # A real browser UA so security-conscious sites (e.g. paypay.com,
    # Cloudflare-fronted endpoints) don't drop us as a headless bot — those
    # drops would otherwise be recorded as bogus "connection_timeout" blocks.
    _BROWSER_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.5 Safari/605.1.15"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    def __init__(self, timeout: float = 4.0) -> None:
        self.timeout = timeout
        # Avoid re-probing the same domain more than once per session.
        self.probed: Set[str] = set()

    def probe(self, domain: str) -> Optional[LaptopBlockEvent]:
        domain = _extract_domain(domain)
        if not domain or domain in self.probed:
            return None
        self.probed.add(domain)

        # ── DNS ────────────────────────────────────────────────────────────
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror as e:
            return LaptopBlockEvent(
                domain=domain, source="network_probe",
                block_type=SystemBlockType.DNS_FAILURE.value,
                error_message=f"DNS resolution failed: {e}",
            )

        # ── HTTPS handshake + status ──────────────────────────────────────
        if requests is None:
            return None
        try:
            r = requests.head(
                f"https://{domain}/",
                timeout=self.timeout, allow_redirects=False,
                headers=self._BROWSER_HEADERS,
            )
            # 451 / some 403 responses indicate legal / policy blocks.
            if r.status_code == 451:
                return LaptopBlockEvent(
                    domain=domain, destination_ip=ip, source="network_probe",
                    block_type="policy_block",
                    error_message=f"HTTP 451 Unavailable For Legal Reasons",
                )
            return None
        except requests.exceptions.SSLError as e:
            return LaptopBlockEvent(
                domain=domain, destination_ip=ip, source="network_probe",
                block_type=SystemBlockType.SSL_ERROR.value,
                error_message=f"SSL/TLS error: {e}",
            )
        except requests.exceptions.ConnectTimeout as e:
            return LaptopBlockEvent(
                domain=domain, destination_ip=ip, source="network_probe",
                block_type=SystemBlockType.CONNECTION_TIMEOUT.value,
                error_message=f"Connection timeout: {e}",
            )
        except requests.exceptions.ConnectionError as e:
            msg = str(e).lower()
            if "refused" in msg:
                bt = SystemBlockType.FIREWALL.value
            elif "reset" in msg:
                bt = SystemBlockType.RESET.value
            else:
                bt = SystemBlockType.UNKNOWN.value
            return LaptopBlockEvent(
                domain=domain, destination_ip=ip, source="network_probe",
                block_type=bt, error_message=f"Connection error: {e}",
            )
        except requests.exceptions.RequestException as e:
            return LaptopBlockEvent(
                domain=domain, destination_ip=ip, source="network_probe",
                block_type=SystemBlockType.UNKNOWN.value,
                error_message=f"Request error: {e}",
            )


# ────────────────────────────────────────────────────────────────────────────
# Public façade
# ────────────────────────────────────────────────────────────────────────────

class ChromeBlockMonitor:
    """
    Aggregates browser-history, hosts-file and active-probe block detection.

    Typical use from the dashboard::

        monitor = ChromeBlockMonitor()
        monitor.start_background(interval=15)        # async
        recent = monitor.recent_blocks(limit=50)
    """

    def __init__(
        self,
        log_dir: str = "logs",
        probe_recent_history: bool = True,
        probe_timeout: float = 4.0,
    ) -> None:
        self.detector = SystemBlockDetector(log_dir=log_dir)
        self.browser = _BrowserHistoryScanner()
        self.hosts = _HostsFileScanner()
        self.probe = _NetworkProbe(timeout=probe_timeout)
        self.probe_recent_history = probe_recent_history

        self._recent: List[LaptopBlockEvent] = []
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ── single-shot scan ──────────────────────────────────────────────────
    def scan_once(self) -> List[LaptopBlockEvent]:
        """Run all detectors once and return any newly-discovered blocks."""
        new_events: List[LaptopBlockEvent] = []

        # 1. Browser history (downloads + chrome-error:// pages)
        try:
            new_events.extend(self.browser.scan())
        except Exception as e:
            logger.debug(f"browser scan failed: {e}")

        # 2. Hosts file
        try:
            new_events.extend(self.hosts.scan())
        except Exception as e:
            logger.debug(f"hosts scan failed: {e}")

        # 3. Probe recently-visited domains so we also catch silent blocks
        if self.probe_recent_history:
            try:
                for d in self.browser.recent_domains(limit=80, since_hours=48):
                    ev = self.probe.probe(d)
                    if ev:
                        new_events.append(ev)
            except Exception as e:
                logger.debug(f"network probe failed: {e}")

        # Forward each event to SystemBlockDetector + remember locally
        for ev in new_events:
            try:
                self.detector.detect_and_log(
                    domain=ev.domain,
                    destination_ip=ev.destination_ip,
                    error_type=ev.block_type,
                    error_message=ev.error_message,
                    timestamp=ev.timestamp,
                )
            except Exception as e:
                logger.debug(f"failed to log event: {e}")
        with self._lock:
            self._recent.extend(new_events)
            # cap memory
            if len(self._recent) > 500:
                self._recent = self._recent[-500:]
        return new_events

    def probe_domain(self, domain: str) -> Optional[LaptopBlockEvent]:
        """Force-probe a single domain (used by the dashboard's test endpoint)."""
        ev = self.probe.probe(domain)
        if ev:
            self.detector.detect_and_log(
                domain=ev.domain,
                destination_ip=ev.destination_ip,
                error_type=ev.block_type,
                error_message=ev.error_message,
                timestamp=ev.timestamp,
            )
            with self._lock:
                self._recent.append(ev)
        return ev

    def recent_blocks(self, limit: int = 50) -> List[Dict]:
        with self._lock:
            return [e.to_dict() for e in self._recent[-limit:]][::-1]

    def stats(self) -> Dict:
        with self._lock:
            events = list(self._recent)
        by_source: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        for e in events:
            by_source[e.source] = by_source.get(e.source, 0) + 1
            by_type[e.block_type] = by_type.get(e.block_type, 0) + 1
        return {
            "total": len(events),
            "by_source": by_source,
            "by_type": by_type,
        }

    # ── background loop ───────────────────────────────────────────────────
    def start_background(self, interval: float = 15.0) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def _loop() -> None:
            logger.info(f"ChromeBlockMonitor background loop started (every {interval}s)")
            while not self._stop.is_set():
                try:
                    found = self.scan_once()
                    if found:
                        logger.info(f"ChromeBlockMonitor: {len(found)} new block(s) detected")
                except Exception as e:
                    logger.warning(f"ChromeBlockMonitor loop error: {e}")
                self._stop.wait(interval)

        self._thread = threading.Thread(target=_loop, daemon=True,
                                        name="ChromeBlockMonitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


# ────────────────────────────────────────────────────────────────────────────
# CLI helper:  python -m modules.chrome_block_monitor
# ────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    m = ChromeBlockMonitor()
    print("Scanning for laptop / Chrome blocks...")
    events = m.scan_once()
    if not events:
        print("  (nothing blocked yet — try visiting a known-bad site in Chrome)")
    for ev in events:
        print(f"  [{ev.source:14s}] {ev.block_type:24s} {ev.domain}")
        print(f"                  {ev.error_message}")
    print("\nStats:", m.stats())


ains that are blocked by the user's local environment — even when
PhishGuard's own engine never had a chance to see them. Specifically:

  • Browser-level blocks      (Chrome / Edge interrupted downloads, malware,
                               policy, parental controls — read from the
                               browser History SQLite database)
  • OS hosts-file blocks      (entries in C:\\Windows\\System32\\drivers\\etc\\hosts
                               or /etc/hosts pointing to 0.0.0.0 / 127.0.0.1)
  • Network-level blocks      (SSL/TLS errors, DNS NXDOMAIN, connection
                               refused/reset, timeouts — discovered by an
                               active HTTPS probe of recently-seen domains)

Every detected block is funnelled into :class:`SystemBlockDetector` so it
shows up in the dashboard's unified "blocked" feed.

Cross-platform: works on Windows, macOS, Linux. No admin required.

Author: Research Team
Date: 2026
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import socket
import sqlite3
import ssl
import tempfile
import threading
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    import requests
except ImportError:  # pragma: no cover - requests is in requirements.txt
    requests = None  # type: ignore

from .system_block_detector import SystemBlockDetector, SystemBlockType

logger = logging.getLogger(__name__)


# ── Chrome / Edge download interrupt reasons ────────────────────────────────
# https://source.chromium.org/chromium/chromium/src/+/main:components/download/public/common/download_interrupt_reasons.h
# We only surface reasons that mean "the browser refused to keep this file".
_CHROME_BLOCK_INTERRUPT_REASONS: Dict[int, str] = {
    20: "FILE_BLOCKED (policy)",
    21: "FILE_SECURITY_CHECK_FAILED",
    32: "NETWORK_INVALID_REQUEST",
    33: "NETWORK_SERVER_DOWN",
    36: "NETWORK_SSL_PROTOCOL_ERROR",
    37: "NETWORK_SERVER_CERT_PROBLEM",
    38: "NETWORK_SERVER_UNAUTHORIZED",
    39: "NETWORK_SERVER_FORBIDDEN",
    40: "NETWORK_SERVER_UNREACHABLE",
    50: "SERVER_BAD_CONTENT",
    51: "SERVER_UNAUTHORIZED",
    52: "SERVER_CERT_PROBLEM",
    53: "SERVER_FORBIDDEN",
    54: "SERVER_UNREACHABLE",
    # 4 is "Blocked dangerous" in newer Chrome
    4: "DANGEROUS_FILE_BLOCKED",
}

# Chrome download.state codes: 0=in progress, 1=complete, 2=cancelled,
# 3=interrupted (legacy), 4=interrupted (current).  Anything != 1 with
# an interrupt_reason is treated as a block candidate.
_CHROME_BLOCKED_STATES = {2, 3, 4}

# Chrome `download.danger_type` values that mean the browser actually
# refused / withheld the file (as opposed to merely warning the user).
# See: chrome/browser/download/download_danger_prompt.* and
# components/safe_browsing/content/common/proto/csd.proto
_CHROME_DANGER_TYPE_BLOCKS: Dict[int, str] = {
    7:  "DANGEROUS_HOST (Safe Browsing)",
    8:  "POTENTIALLY_UNWANTED",
    11: "BLOCKED_PASSWORD_PROTECTED",
    12: "BLOCKED_TOO_LARGE",
    13: "BLOCKED_SENSITIVE_CONTENT_WARNING",
    14: "BLOCKED_SENSITIVE_CONTENT_BLOCK",
    15: "DEEP_SCANNED_SAFE_BUT_BLOCKED",
    16: "BLOCKED_UNSUPPORTED_FILETYPE",
    17: "DANGEROUS_ACCOUNT_COMPROMISE",
    18: "DEEP_SCANNED_FAILED",
    19: "PROMPT_FOR_LOCAL_PASSWORD_SCANNING",
    20: "BLOCKED_SCAN_FAILED",
}


@dataclass
class LaptopBlockEvent:
    """A single block detected on the user's machine."""
    domain: str
    source: str            # 'chrome', 'edge', 'hosts_file', 'network_probe'
    block_type: str        # firewall / ssl_error / dns_failure / ...
    error_message: str
    destination_ip: str = ""
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())

    def to_dict(self) -> Dict:
        return asdict(self)


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.\-]+$")

# Hosts we never want to probe / scan / log. These are local-development
# artefacts and IPv6 loopback variants, not real outbound traffic, so they
# would otherwise flood the dashboard with bogus "firewall block" events
# whenever the dashboard's own dev server isn't listening on :443.
_LOCAL_HOSTS: set[str] = {
    "localhost", "localhost.localdomain",
    "127.0.0.1", "0.0.0.0", "::", "::1", "[::1]",
    "ip6-localhost", "ip6-loopback",
    "broadcasthost",
}


def _is_local_or_private(host: str) -> bool:
    """True for loopback, link-local, .local mDNS, and RFC1918 ranges."""
    if not host:
        return True
    h = host.lower().strip().strip("[]")
    if h in _LOCAL_HOSTS:
        return True
    if h.endswith(".local") or h.endswith(".localhost") or h.endswith(".lan"):
        return True
    # RFC1918 / loopback / link-local IP literals
    if h.startswith("127.") or h.startswith("10.") or h.startswith("192.168."):
        return True
    if h.startswith("169.254."):  # link-local
        return True
    if h.startswith("172."):
        try:
            second = int(h.split(".", 2)[1])
            if 16 <= second <= 31:
                return True
        except (ValueError, IndexError):
            pass
    return False


def _extract_domain(url_or_host: str) -> str:
    """
    Pull a hostname out of a URL or raw host string.

    Returns "" for empty input, loopback addresses (localhost, 127.0.0.1,
    ::1, …), .local mDNS names, and RFC1918 private ranges — those are
    local-dev traffic, not phishing indicators.
    """
    if not url_or_host:
        return ""
    s = url_or_host.strip().lower()
    if "://" in s:
        try:
            s = urlparse(s).hostname or ""
        except Exception:
            return ""
    # strip port
    s = s.split(":", 1)[0].strip(".")
    if _is_local_or_private(s):
        return ""
    return s if _DOMAIN_RE.match(s) else ""


def _copy_locked_db(src: Path) -> Optional[Path]:
    """Copy a SQLite file (e.g. Chrome's locked History DB) to a temp path."""
    if not src.exists():
        return None
    try:
        fd, tmp = tempfile.mkstemp(prefix="phishguard_", suffix=".sqlite")
        os.close(fd)
        shutil.copy2(src, tmp)
        return Path(tmp)
    except (PermissionError, OSError) as e:
        logger.debug(f"Could not copy {src}: {e}")
        return None


# ────────────────────────────────────────────────────────────────────────────
# Browser History scanner
# ────────────────────────────────────────────────────────────────────────────

class _BrowserHistoryScanner:
    """Scans Chrome / Edge / Brave history databases for blocked events."""

    def __init__(self) -> None:
        self.seen_download_ids: Set[Tuple[str, int]] = set()
        self.seen_visit_ids: Set[Tuple[str, int]] = set()

    def history_paths(self) -> List[Tuple[str, Path]]:
        """Return [(browser_label, path_to_History_db), ...] for installed browsers."""
        home = Path.home()
        candidates: List[Tuple[str, Path]] = []
        system = platform.system().lower()

        if system == "windows":
            local = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
            candidates += [
                ("chrome", local / "Google/Chrome/User Data/Default/History"),
                ("edge",   local / "Microsoft/Edge/User Data/Default/History"),
                ("brave",  local / "BraveSoftware/Brave-Browser/User Data/Default/History"),
            ]
        elif system == "darwin":
            base = home / "Library/Application Support"
            candidates += [
                ("chrome", base / "Google/Chrome/Default/History"),
                ("edge",   base / "Microsoft Edge/Default/History"),
                ("brave",  base / "BraveSoftware/Brave-Browser/Default/History"),
            ]
        else:  # linux
            cfg = home / ".config"
            candidates += [
                ("chrome", cfg / "google-chrome/Default/History"),
                ("edge",   cfg / "microsoft-edge/Default/History"),
                ("brave",  cfg / "BraveSoftware/Brave-Browser/Default/History"),
            ]
        return [(name, p) for name, p in candidates if p.exists()]

    def scan(self) -> List[LaptopBlockEvent]:
        """Scan every installed browser; return only newly-seen block events."""
        events: List[LaptopBlockEvent] = []
        for browser, path in self.history_paths():
            tmp = _copy_locked_db(path)
            if not tmp:
                continue
            try:
                events.extend(self._scan_one(browser, tmp))
            except sqlite3.Error as e:
                logger.debug(f"sqlite error reading {browser} history: {e}")
            finally:
                try:
                    tmp.unlink()
                except OSError:
                    pass
        return events

    def _scan_one(self, browser: str, db: Path) -> List[LaptopBlockEvent]:
        events: List[LaptopBlockEvent] = []
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
        try:
            cur = conn.cursor()

            # ── Blocked / interrupted downloads ────────────────────────────
            # A download is only a *block* when the browser actually withheld
            # the file from the user.  That means either:
            #   * state != 1 (1 = COMPLETE), OR
            #   * an explicit interrupt_reason from the security stack.
            # A non-zero danger_type on a completed download is only a
            # warning the user clicked through, NOT a block, so we ignore it.
            try:
                cur.execute(
                    "SELECT id, tab_url, target_path, state, interrupt_reason, "
                    "       danger_type, start_time "
                    "FROM downloads "
                    "WHERE state != 1 OR interrupt_reason != 0"
                )
                for row in cur.fetchall():
                    dl_id, url, target, state, reason, danger, _start = row
                    key = (browser, int(dl_id))
                    if key in self.seen_download_ids:
                        continue
                    self.seen_download_ids.add(key)

                    domain = _extract_domain(url or "")
                    if not domain:
                        continue

                    reason = int(reason or 0)
                    danger = int(danger or 0)
                    state = int(state or 0)

                    if reason in _CHROME_BLOCK_INTERRUPT_REASONS:
                        label = _CHROME_BLOCK_INTERRUPT_REASONS[reason]
                    elif reason:
                        label = f"INTERRUPT_REASON_{reason}"
                    elif danger in _CHROME_DANGER_TYPE_BLOCKS:
                        label = _CHROME_DANGER_TYPE_BLOCKS[danger]
                    elif state in _CHROME_BLOCKED_STATES:
                        label = "CANCELLED_OR_INTERRUPTED"
                    else:
                        # Not actually blocked, skip
                        continue

                    events.append(LaptopBlockEvent(
                        domain=domain,
                        source=browser,
                        block_type="browser_download_block",
                        error_message=f"{browser.title()} blocked download: {label}",
                    ))
            except sqlite3.Error as e:
                logger.debug(f"{browser} downloads table not available: {e}")

            # ── Visits that ended in a chrome-error://* page ───────────────
            # Chrome rewrites the URL of failed navigations (cert errors,
            # Safe-Browsing interstitials, DNS failures) to
            # "chrome-error://chromewebdata/" with the original URL kept in
            # the visit's redirect chain.  We pick those up via the urls
            # table.
            try:
                cur.execute(
                    "SELECT id, url, last_visit_time "
                    "FROM urls "
                    "WHERE url LIKE 'chrome-error://%' "
                    "   OR url LIKE 'edge-error://%' "
                    "ORDER BY last_visit_time DESC LIMIT 200"
                )
                # We can't always recover the original domain from a
                # chrome-error URL, but Chrome usually appends it as a
                # query/fragment.  Pull anything that looks like a host.
                for row in cur.fetchall():
                    url_id, url, lvt = row
                    key = (browser, int(url_id))
                    if key in self.seen_visit_ids:
                        continue
                    self.seen_visit_ids.add(key)
                    m = re.search(r"https?://([A-Za-z0-9.\-]+)", url or "")
                    domain = _extract_domain(m.group(1)) if m else ""
                    if not domain:
                        continue
                    events.append(LaptopBlockEvent(
                        domain=domain,
                        source=browser,
                        block_type="browser_navigation_block",
                        error_message=f"{browser.title()} showed an error page for {domain}",
                    ))
            except sqlite3.Error:
                pass

        finally:
            conn.close()
        return events

    def recent_domains(self, limit: int = 200, since_hours: int = 24) -> List[str]:
        """Return unique hostnames the user recently visited (for probing)."""
        out: List[str] = []
        seen: Set[str] = set()
        # Chrome stores last_visit_time as microseconds since 1601-01-01.
        epoch_offset_us = 11644473600 * 1_000_000
        cutoff_us = int(time.time() * 1_000_000) - since_hours * 3600 * 1_000_000
        cutoff_chrome = cutoff_us + epoch_offset_us

        for browser, path in self.history_paths():
            tmp = _copy_locked_db(path)
            if not tmp:
                continue
            try:
                conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True, timeout=2)
                try:
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT url FROM urls WHERE last_visit_time > ? "
                        "ORDER BY last_visit_time DESC LIMIT ?",
                        (cutoff_chrome, limit),
                    )
                    for (url,) in cur.fetchall():
                        d = _extract_domain(url)
                        if d and d not in seen:
                            seen.add(d)
                            out.append(d)
                finally:
                    conn.close()
            except sqlite3.Error:
                pass
            finally:
                try:
                    tmp.unlink()
                except OSError:
                    pass
            if len(out) >= limit:
                break
        return out[:limit]


# ────────────────────────────────────────────────────────────────────────────
# Hosts-file scanner
# ────────────────────────────────────────────────────────────────────────────

class _HostsFileScanner:
    """Reads the OS hosts file and reports entries that null-route a domain."""

    BLOCK_TARGETS = {"0.0.0.0", "127.0.0.1", "::", "::1"}

    def __init__(self) -> None:
        self.seen: Set[str] = set()

    def hosts_path(self) -> Path:
        if platform.system().lower() == "windows":
            return Path(os.environ.get("SystemRoot", r"C:\Windows")) / r"System32\drivers\etc\hosts"
        return Path("/etc/hosts")

    def scan(self) -> List[LaptopBlockEvent]:
        path = self.hosts_path()
        if not path.exists():
            return []
        events: List[LaptopBlockEvent] = []
        try:
            for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip, hosts = parts[0], parts[1:]
                if ip not in self.BLOCK_TARGETS:
                    continue
                for host in hosts:
                    domain = _extract_domain(host)
                    if not domain or domain in self.seen:
                        continue
                    self.seen.add(domain)
                    events.append(LaptopBlockEvent(
                        domain=domain,
                        source="hosts_file",
                        block_type="firewall",
                        destination_ip=ip,
                        error_message=f"Hosts file null-routes {domain} → {ip}",
                    ))
        except (OSError, UnicodeDecodeError) as e:
            logger.debug(f"hosts file unreadable: {e}")
        return events


# ────────────────────────────────────────────────────────────────────────────
# Active network probe
# ────────────────────────────────────────────────────────────────────────────

class _NetworkProbe:
    """Best-effort HTTPS probe to discover network/SSL/DNS blocks."""

    # A real browser UA so security-conscious sites (e.g. paypay.com,
    # Cloudflare-fronted endpoints) don't drop us as a headless bot — those
    # drops would otherwise be recorded as bogus "connection_timeout" blocks.
    _BROWSER_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.5 Safari/605.1.15"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    def __init__(self, timeout: float = 4.0) -> None:
        self.timeout = timeout
        # Avoid re-probing the same domain more than once per session.
        self.probed: Set[str] = set()

    def probe(self, domain: str) -> Optional[LaptopBlockEvent]:
        domain = _extract_domain(domain)
        if not domain or domain in self.probed:
            return None
        self.probed.add(domain)

        # ── DNS ────────────────────────────────────────────────────────────
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror as e:
            return LaptopBlockEvent(
                domain=domain, source="network_probe",
                block_type=SystemBlockType.DNS_FAILURE.value,
                error_message=f"DNS resolution failed: {e}",
            )

        # ── HTTPS handshake + status ──────────────────────────────────────
        if requests is None:
            return None
        try:
            r = requests.head(
                f"https://{domain}/",
                timeout=self.timeout, allow_redirects=False,
                headers=self._BROWSER_HEADERS,
            )
            # 451 / some 403 responses indicate legal / policy blocks.
            if r.status_code == 451:
                return LaptopBlockEvent(
                    domain=domain, destination_ip=ip, source="network_probe",
                    block_type="policy_block",
                    error_message=f"HTTP 451 Unavailable For Legal Reasons",
                )
            return None
        except requests.exceptions.SSLError as e:
            return LaptopBlockEvent(
                domain=domain, destination_ip=ip, source="network_probe",
                block_type=SystemBlockType.SSL_ERROR.value,
                error_message=f"SSL/TLS error: {e}",
            )
        except requests.exceptions.ConnectTimeout as e:
            return LaptopBlockEvent(
                domain=domain, destination_ip=ip, source="network_probe",
                block_type=SystemBlockType.CONNECTION_TIMEOUT.value,
                error_message=f"Connection timeout: {e}",
            )
        except requests.exceptions.ConnectionError as e:
            msg = str(e).lower()
            if "refused" in msg:
                bt = SystemBlockType.FIREWALL.value
            elif "reset" in msg:
                bt = SystemBlockType.RESET.value
            else:
                bt = SystemBlockType.UNKNOWN.value
            return LaptopBlockEvent(
                domain=domain, destination_ip=ip, source="network_probe",
                block_type=bt, error_message=f"Connection error: {e}",
            )
        except requests.exceptions.RequestException as e:
            return LaptopBlockEvent(
                domain=domain, destination_ip=ip, source="network_probe",
                block_type=SystemBlockType.UNKNOWN.value,
                error_message=f"Request error: {e}",
            )


# ────────────────────────────────────────────────────────────────────────────
# Public façade
# ────────────────────────────────────────────────────────────────────────────

class ChromeBlockMonitor:
    """
    Aggregates browser-history, hosts-file and active-probe block detection.

    Typical use from the dashboard::

        monitor = ChromeBlockMonitor()
        monitor.start_background(interval=15)        # async
        recent = monitor.recent_blocks(limit=50)
    """

    def __init__(
        self,
        log_dir: str = "logs",
        probe_recent_history: bool = True,
        probe_timeout: float = 4.0,
    ) -> None:
        self.detector = SystemBlockDetector(log_dir=log_dir)
        self.browser = _BrowserHistoryScanner()
        self.hosts = _HostsFileScanner()
        self.probe = _NetworkProbe(timeout=probe_timeout)
        self.probe_recent_history = probe_recent_history

        self._recent: List[LaptopBlockEvent] = []
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ── single-shot scan ──────────────────────────────────────────────────
    def scan_once(self) -> List[LaptopBlockEvent]:
        """Run all detectors once and return any newly-discovered blocks."""
        new_events: List[LaptopBlockEvent] = []

        # 1. Browser history (downloads + chrome-error:// pages)
        try:
            new_events.extend(self.browser.scan())
        except Exception as e:
            logger.debug(f"browser scan failed: {e}")

        # 2. Hosts file
        try:
            new_events.extend(self.hosts.scan())
        except Exception as e:
            logger.debug(f"hosts scan failed: {e}")

        # 3. Probe recently-visited domains so we also catch silent blocks
        if self.probe_recent_history:
            try:
                for d in self.browser.recent_domains(limit=80, since_hours=48):
                    ev = self.probe.probe(d)
                    if ev:
                        new_events.append(ev)
            except Exception as e:
                logger.debug(f"network probe failed: {e}")

        # Forward each event to SystemBlockDetector + remember locally
        for ev in new_events:
            try:
                self.detector.detect_and_log(
                    domain=ev.domain,
                    destination_ip=ev.destination_ip,
                    error_type=ev.block_type,
                    error_message=ev.error_message,
                    timestamp=ev.timestamp,
                )
            except Exception as e:
                logger.debug(f"failed to log event: {e}")
        with self._lock:
            self._recent.extend(new_events)
            # cap memory
            if len(self._recent) > 500:
                self._recent = self._recent[-500:]
        return new_events

    def probe_domain(self, domain: str) -> Optional[LaptopBlockEvent]:
        """Force-probe a single domain (used by the dashboard's test endpoint)."""
        ev = self.probe.probe(domain)
        if ev:
            self.detector.detect_and_log(
                domain=ev.domain,
                destination_ip=ev.destination_ip,
                error_type=ev.block_type,
                error_message=ev.error_message,
                timestamp=ev.timestamp,
            )
            with self._lock:
                self._recent.append(ev)
        return ev

    def recent_blocks(self, limit: int = 50) -> List[Dict]:
        with self._lock:
            return [e.to_dict() for e in self._recent[-limit:]][::-1]

    def stats(self) -> Dict:
        with self._lock:
            events = list(self._recent)
        by_source: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        for e in events:
            by_source[e.source] = by_source.get(e.source, 0) + 1
            by_type[e.block_type] = by_type.get(e.block_type, 0) + 1
        return {
            "total": len(events),
            "by_source": by_source,
            "by_type": by_type,
        }

    # ── background loop ───────────────────────────────────────────────────
    def start_background(self, interval: float = 15.0) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def _loop() -> None:
            logger.info(f"ChromeBlockMonitor background loop started (every {interval}s)")
            while not self._stop.is_set():
                try:
                    found = self.scan_once()
                    if found:
                        logger.info(f"ChromeBlockMonitor: {len(found)} new block(s) detected")
                except Exception as e:
                    logger.warning(f"ChromeBlockMonitor loop error: {e}")
                self._stop.wait(interval)

        self._thread = threading.Thread(target=_loop, daemon=True,
                                        name="ChromeBlockMonitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


# ────────────────────────────────────────────────────────────────────────────
# CLI helper:  python -m modules.chrome_block_monitor
# ────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    m = ChromeBlockMonitor()
    print("Scanning for laptop / Chrome blocks...")
    events = m.scan_once()
    if not events:
        print("  (nothing blocked yet — try visiting a known-bad site in Chrome)")
    for ev in events:
        print(f"  [{ev.source:14s}] {ev.block_type:24s} {ev.domain}")
        print(f"                  {ev.error_message}")
    print("\nStats:", m.stats())
