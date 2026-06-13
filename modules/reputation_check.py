"""
Reputation-based phishing detection (no ML required).

Looks up a domain / URL against well-known threat intelligence sources:

  1. Google Safe Browsing v4  (the same list that powers Chrome's warnings)
  2. PhishTank  (community-curated, refreshed every few minutes)
  3. OpenPhish  (community feed, refreshed every few minutes)

The first source to flag the domain wins. If nothing is flagged the result
is `unknown` — the caller can then fall back to heuristics / the ML model.

Setup:
  - For Safe Browsing, get a free API key
    (https://developers.google.com/safe-browsing/v4/get-started)
    and set the env var GOOGLE_SAFE_BROWSING_API_KEY before starting the
    dashboard. Without a key the lookup is silently skipped.
  - PhishTank / OpenPhish work with no key.

The feeds are downloaded once on first use and cached on disk in
`logs/threat_cache/` for 1 hour, so lookups are O(1) set membership checks
and don't hit the network on every request.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Set

import requests

logger = logging.getLogger(__name__)

# ── Config ───────────────────────────────────────────────────────────────────
CACHE_DIR = Path("logs/threat_cache")
CACHE_TTL_SECONDS = 60 * 60  # 1 hour

SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
)

# Lightweight text feeds that don't require an API key.
PHISHTANK_FEED_URL = "http://data.phishtank.com/data/online-valid.json"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"

REQUEST_TIMEOUT = 6  # seconds — fail fast so the dashboard stays responsive

# Safety net: never let a community feed flag one of the top global domains.
# PhishTank in particular sometimes contains URLs whose host is
# `google.com/?url=...` (open redirectors) which would otherwise produce a
# nasty false positive on standalone use of this module.
_TRUSTED_ANCHORS: Set[str] = {
    "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
    "linkedin.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
    "stripe.com", "cloudflare.com", "wikipedia.org", "mozilla.org",
    "reddit.com", "instagram.com", "live.com", "office.com", "icloud.com",
    "openai.com", "anthropic.com",
    # Financial / payment brands — phishing-target heavyweights.
    "paypal.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "citibank.com", "hsbc.com", "americanexpress.com", "discover.com",
    "capitalone.com", "venmo.com", "cashapp.com",
    # Communication / productivity.
    "gmail.com", "outlook.com", "yahoo.com", "zoom.us", "slack.com",
    "dropbox.com", "docusign.com", "adobe.com", "notion.so", "atlassian.com",
    # Streaming / commerce.
    "netflix.com", "spotify.com", "ebay.com", "etsy.com", "shopify.com",
    "walmart.com", "target.com", "bestbuy.com",
    # Crypto exchanges (popular phishing targets).
    "binance.com", "coinbase.com", "kraken.com",
}

# ── Brand-impersonation heuristic ────────────────────────────────────────────
# Catches the obvious "paypal-verify-account.com" style domains that aren't
# yet in any community feed. We only flag when there's a clear brand name
# AND a suspicious action token in the SAME label.
_BRAND_TOKENS: Set[str] = {
    "paypal", "apple", "icloud", "amazon", "google", "gmail", "microsoft",
    "office365", "outlook", "netflix", "instagram", "facebook", "whatsapp",
    "linkedin", "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc",
    "dropbox", "docusign", "adobe", "github", "stripe", "binance", "coinbase",
}
_SUSPICIOUS_TOKENS: Set[str] = {
    "verify", "verification", "login", "signin", "secure", "account",
    "update", "confirm", "support", "recover", "recovery", "billing",
    "alert", "wallet", "unlock", "reset", "auth", "validation",
}
# Cheap / abused TLDs commonly used by short-lived phishing kits.
_CHEAP_TLDS: Set[str] = {
    ".xyz", ".top", ".tk", ".gq", ".cf", ".ml", ".click", ".work",
    ".loan", ".country", ".date", ".kim", ".gdn", ".support", ".zip",
}
# Real brand domains — never flag these.
_LEGIT_BRAND_DOMAINS: Set[str] = (
    {b + ".com" for b in _BRAND_TOKENS}
    | {"icloud.com", "office.com", "live.com", "outlook.com", "chase.com"}
)


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    """Edit distance with early termination at `cap` (returns cap+1 if exceeded)."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    if len(a) > len(b):
        a, b = b, a
    # Iterative DP — short strings so a fresh row per call is fine.
    prev = list(range(len(a) + 1))
    for j, cb in enumerate(b, 1):
        curr = [j] + [0] * len(a)
        row_min = j
        for i, ca in enumerate(a, 1):
            cost = 0 if ca == cb else 1
            curr[i] = min(curr[i-1] + 1, prev[i] + 1, prev[i-1] + cost)
            if curr[i] < row_min:
                row_min = curr[i]
        if row_min > cap:
            return cap + 1
        prev = curr
    return prev[-1]


def _typosquat_match(label: str) -> Optional[tuple[str, int]]:
    """
    Return (brand, edit_distance) if `label` looks like a typo of a brand
    (e.g. 'facbok' vs 'facebook', 'gogle' vs 'google'). None otherwise.

    Only checks brands ≥ 6 chars long to avoid false positives on short
    words (e.g. 'apply' vs 'apple'). Distance cap scales with brand length:
    brand ≤ 6 chars → max 1 edit, brand ≥ 7 chars → max 2 edits.
    """
    if not label or len(label) < 4:
        return None
    best: Optional[tuple[str, int]] = None
    for brand in _BRAND_TOKENS:
        if len(brand) < 6 or label == brand:
            continue
        if abs(len(label) - len(brand)) > 2:
            continue
        cap = 1 if len(brand) <= 6 else 2
        d = _levenshtein(label, brand, cap=cap)
        if 1 <= d <= cap:
            if best is None or d < best[1]:
                best = (brand, d)
    return best


def _heuristic_phishing(host: str) -> Optional[ReputationResult]:
    """
    Lightweight rule-based detector for obvious brand-impersonation domains.
    Returns a phishing verdict only when the signal is strong; otherwise None.
    """
    if not host or host in _LEGIT_BRAND_DOMAINS:
        return None
    label = host.split(".", 1)[0]
    reasons: list[str] = []
    score = 0.0

    # Brand name appears anywhere in the host (and it isn't the real domain).
    brand_hit = next((b for b in _BRAND_TOKENS if b in host), None)
    if brand_hit:
        reasons.append(f"impersonates brand '{brand_hit}'")
        score += 0.55

    # Typosquatting: label is a near-miss of a known brand
    # (e.g. 'facbok' ~ 'facebook', 'gogle' ~ 'google', 'amazonn' ~ 'amazon').
    # Runs even when brand_hit is true so we catch brand+extra-char tricks.
    typo = _typosquat_match(label)
    if typo:
        brand, dist = typo
        reasons.append(f"typo of brand '{brand}' (edit distance {dist})")
        # Strong signal on its own — typosquats are almost always malicious.
        # Slightly lower bump if brand_hit already added 0.55 to avoid stacking
        # to absurd confidence on harmless substring hits.
        score += 0.45 if brand_hit else 0.8

    # Suspicious action token in the same label as the brand.
    susp_hits = [t for t in _SUSPICIOUS_TOKENS if t in host]
    if susp_hits:
        reasons.append("contains " + "/".join(susp_hits[:2]))
        score += 0.25 + 0.05 * min(len(susp_hits), 3)

    # Heavy hyphenation (verify-account-paypal style).
    if label.count("-") >= 2:
        reasons.append(f"{label.count('-')} hyphens in label")
        score += 0.1

    # Cheap / abused TLD.
    if any(host.endswith(tld) for tld in _CHEAP_TLDS):
        reasons.append("cheap/abused TLD")
        score += 0.2

    # Flag if EITHER:
    #   (a) brand impersonation + (suspicious tokens OR heavy hyphens), OR
    #   (b) typosquat of a brand (strong signal on its own).
    if (brand_hit and (susp_hits or label.count("-") >= 2) and score >= 0.7) \
            or (typo is not None and score >= 0.7):
        return ReputationResult(
            verdict="phishing",
            source="heuristic",
            confidence=min(score, 0.95),
            reason="Brand-impersonation pattern: " + "; ".join(reasons),
            threat_type="SOCIAL_ENGINEERING",
        )
    return None


# ── Result type ──────────────────────────────────────────────────────────────
@dataclass
class ReputationResult:
    verdict: str           # "phishing" | "legitimate" | "unknown"
    source: str            # e.g. "google_safe_browsing", "phishtank", "openphish", "none"
    confidence: float      # 0..1
    reason: str = ""
    threat_type: str = ""  # populated when verdict == "phishing"
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "source": self.source,
            "confidence": self.confidence,
            "reason": self.reason,
            "threat_type": self.threat_type,
            "details": self.details,
        }


# ── Internal helpers ─────────────────────────────────────────────────────────
def _normalise(domain_or_url: str) -> tuple[str, str]:
    """Return (domain, full_url) for both kinds of input."""
    raw = (domain_or_url or "").strip()
    if not raw:
        return "", ""
    if "://" in raw:
        url = raw
        host = raw.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    else:
        host = raw.split("/", 1)[0].split(":", 1)[0]
        url = f"http://{host}"
    return host.lower(), url


def _cache_path(name: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{name}.json"


def _cache_fresh(path: Path) -> bool:
    return path.exists() and (time.time() - path.stat().st_mtime) < CACHE_TTL_SECONDS


def _load_cached_set(name: str) -> Optional[Set[str]]:
    p = _cache_path(name)
    if not _cache_fresh(p):
        return None
    try:
        return set(json.loads(p.read_text(encoding="utf-8")))
    except Exception as e:
        logger.debug(f"Could not read {name} cache: {e}")
        return None


def _save_cached_set(name: str, items: Set[str]) -> None:
    try:
        _cache_path(name).write_text(json.dumps(sorted(items)), encoding="utf-8")
    except Exception as e:
        logger.debug(f"Could not write {name} cache: {e}")


def _host_in_set(host: str, blocklist: Set[str]) -> bool:
    """Exact host match OR any parent-domain match."""
    if not host:
        return False
    if host in blocklist:
        return True
    parts = host.split(".")
    for i in range(1, len(parts) - 1):
        if ".".join(parts[i:]) in blocklist:
            return True
    return False


# ── PhishTank feed ───────────────────────────────────────────────────────────
def _refresh_phishtank() -> Set[str]:
    cached = _load_cached_set("phishtank")
    if cached is not None:
        return cached
    try:
        logger.info("Refreshing PhishTank feed...")
        r = requests.get(
            PHISHTANK_FEED_URL,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "PhishGuard/1.0 (research)"},
        )
        r.raise_for_status()
        entries = r.json()
        hosts: Set[str] = set()
        for e in entries:
            url = e.get("url") or ""
            if "://" in url:
                host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
                if host:
                    hosts.add(host.lower())
        _save_cached_set("phishtank", hosts)
        logger.info(f"✓ PhishTank: {len(hosts)} hosts cached")
        return hosts
    except Exception as e:
        logger.warning(f"PhishTank refresh failed: {e}")
        return set()


# ── OpenPhish feed ───────────────────────────────────────────────────────────
def _refresh_openphish() -> Set[str]:
    cached = _load_cached_set("openphish")
    if cached is not None:
        return cached
    try:
        logger.info("Refreshing OpenPhish feed...")
        r = requests.get(
            OPENPHISH_FEED_URL,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "PhishGuard/1.0 (research)"},
        )
        r.raise_for_status()
        hosts: Set[str] = set()
        for line in r.text.splitlines():
            line = line.strip()
            if "://" in line:
                host = line.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
                if host:
                    hosts.add(host.lower())
        _save_cached_set("openphish", hosts)
        logger.info(f"✓ OpenPhish: {len(hosts)} hosts cached")
        return hosts
    except Exception as e:
        logger.warning(f"OpenPhish refresh failed: {e}")
        return set()


# ── Google Safe Browsing ─────────────────────────────────────────────────────
def _check_safe_browsing(url: str) -> Optional[ReputationResult]:
    key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not key:
        return None
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(
            SAFE_BROWSING_URL.format(key=key),
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code != 200:
            logger.debug(f"Safe Browsing HTTP {r.status_code}: {r.text[:120]}")
            return None
        matches = r.json().get("matches") or []
        if matches:
            threat = matches[0].get("threatType", "UNKNOWN")
            return ReputationResult(
                verdict="phishing",
                source="google_safe_browsing",
                confidence=1.0,
                reason=f"Google Safe Browsing flagged this URL as {threat}.",
                threat_type=threat,
                details={"matches": matches},
            )
        # 200 with no matches means "not in any GSB blocklist" — that does
        # NOT prove the URL is safe (brand-new phishing kits aren't on the
        # list yet). Return None so the caller falls through to the next
        # signal instead of incorrectly approving the domain.
        return None
    except Exception as e:
        logger.debug(f"Safe Browsing lookup failed: {e}")
        return None


# ── Public API ───────────────────────────────────────────────────────────────
class ReputationChecker:
    """
    Thread-safe wrapper that combines Google Safe Browsing + PhishTank +
    OpenPhish. Caches the feeds on disk for `CACHE_TTL_SECONDS`.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._phishtank: Set[str] = set()
        self._openphish: Set[str] = set()
        self._last_refresh: float = 0.0

    def _ensure_feeds(self) -> None:
        with self._lock:
            if time.time() - self._last_refresh < 60:  # don't hammer
                # Lazy-load from cache if we haven't loaded into memory yet
                if not self._phishtank:
                    self._phishtank = _refresh_phishtank()
                if not self._openphish:
                    self._openphish = _refresh_openphish()
                return
            self._phishtank = _refresh_phishtank()
            self._openphish = _refresh_openphish()
            self._last_refresh = time.time()

    def check(self, domain_or_url: str) -> ReputationResult:
        host, url = _normalise(domain_or_url)
        if not host:
            return ReputationResult(
                verdict="unknown",
                source="none",
                confidence=0.0,
                reason="Empty input.",
            )

        # 0. Hard allow-list for the top global domains so a noisy community
        #    feed entry can't ever flag them as phishing.
        if _host_in_set(host, _TRUSTED_ANCHORS):
            return ReputationResult(
                verdict="legitimate",
                source="trusted_anchor",
                confidence=1.0,
                reason=f"{host} is on the trusted-anchor allow-list.",
            )

        # 1. Google Safe Browsing — best signal when configured.
        gsb = _check_safe_browsing(url)
        if gsb is not None and gsb.verdict == "phishing":
            return gsb

        # 2. Community feeds.
        self._ensure_feeds()
        if _host_in_set(host, self._phishtank):
            return ReputationResult(
                verdict="phishing",
                source="phishtank",
                confidence=0.95,
                reason=f"{host} appears in the PhishTank verified phishing feed.",
                threat_type="SOCIAL_ENGINEERING",
            )
        if _host_in_set(host, self._openphish):
            return ReputationResult(
                verdict="phishing",
                source="openphish",
                confidence=0.9,
                reason=f"{host} appears in the OpenPhish community feed.",
                threat_type="SOCIAL_ENGINEERING",
            )

        # 3. Brand-impersonation heuristic — catches obvious lookalikes
        #    ("paypal-verify-account.com", "apple-login-secure.com", …)
        #    that aren't yet listed in any community feed.
        heur = _heuristic_phishing(host)
        if heur is not None:
            return heur

        # 4. Nothing flagged it — caller decides what to do.
        #    We deliberately do NOT return "legitimate" here: absence from a
        #    blocklist is not proof of safety.
        return ReputationResult(
            verdict="unknown",
            source="none",
            confidence=0.0,
            reason=(
                "Not found in Google Safe Browsing, PhishTank, OpenPhish, "
                "or brand-impersonation heuristic."
                if os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
                else "Not found in PhishTank, OpenPhish, or brand-impersonation "
                     "heuristic (Safe Browsing key not set)."
            ),
        )

    def stats(self) -> dict:
        return {
            "phishtank_hosts": len(self._phishtank),
            "openphish_hosts": len(self._openphish),
            "safe_browsing_enabled": bool(
                os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
            ),
            "last_refresh": self._last_refresh,
        }


# Module-level singleton — cheap, threadsafe, only loaded on first use.
_DEFAULT_CHECKER: Optional[ReputationChecker] = None


def get_default_checker() -> ReputationChecker:
    global _DEFAULT_CHECKER
    if _DEFAULT_CHECKER is None:
        _DEFAULT_CHECKER = ReputationChecker()
    return _DEFAULT_CHECKER


def check_domain(domain_or_url: str) -> ReputationResult:
    """One-shot convenience wrapper."""
    return get_default_checker().check(domain_or_url)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    for d in ["google.com", "paypal-verify-account.com", "github.com"]:
        r = check_domain(d)
        print(f"{d:40s} -> {r.verdict:11s} ({r.source}, conf={r.confidence:.2f})")
        print(f"    {r.reason}")