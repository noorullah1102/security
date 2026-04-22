"""Threat feed checker - queries multiple sources for URL reputation."""

import asyncio
import base64
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp
from structlog import get_logger

logger = get_logger()


@dataclass
class ThreatCheckResult:
    """Result from checking a URL against threat feeds."""
    url: str
    is_known_threat: bool = False
    sources: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    threat_type: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    target_brand: str | None = None


class ThreatFeedChecker:
    """Check URLs against multiple threat intelligence sources.

    Supported sources:
    - URLhaus (abuse.ch) - Free
    - OpenPhish - Free
    - Reddit (r/phishing, r/cybersecurity) - Requires credentials
    - PhishTank - Requires API key
    - VirusTotal - Free tier (4 requests/min)
    - Google Safe Browsing - Free API
    - urlscan.io - Free tier
    """

    URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
    URLHAUS_TEXT_URL = "https://urlhaus.abuse.ch/downloads/text_online/"
    OPENPHISH_URL = "https://openphish.com/feed.txt"
    PHISHTANK_API = "https://checkurl.phishtank.com/checkurl/"
    VIRUSTOTAL_API = "https://www.virustotal.com/api/v3/urls"
    GOOGLE_SAFEBROWSING_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    URLSCAN_API = "https://urlscan.io/api/v1/search/"

    def __init__(self):
        """Initialize threat feed checker."""
        self._session: aiohttp.ClientSession | None = None
        self._openphish_cache: set[str] | None = None
        self._openphish_cache_time: datetime | None = None
        self._openphish_cache_ttl = 3600  # 1 hour
        self._urlhaus_cache: set[str] | None = None
        self._urlhaus_cache_time: datetime | None = None
        self._urlhaus_cache_ttl = 1800  # 30 minutes
        self._phishtank_cache: set[str] | None = None
        self._phishtank_cache_time: datetime | None = None
        self._phishtank_cache_ttl = 14400  # 4 hours

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=60, connect=10)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            }
            self._session = aiohttp.ClientSession(timeout=timeout, headers=headers)
        return self._session

    async def check_urlhaus(self, url: str) -> dict[str, Any]:
        """Check if URL is in URLhaus database.

        Uses API with Auth-Key if configured, otherwise falls back to
        cached Plain-Text URL List (no auth required).

        Returns:
            Dict with 'found', 'threat_type', 'source', 'details'
        """
        urlhaus_auth_key = os.environ.get("URLHAUS_AUTH_KEY")

        # Method 1: Use API if Auth-Key is configured
        if urlhaus_auth_key:
            return await self._check_urlhaus_api(url, urlhaus_auth_key)

        # Method 2: Fallback to cached plain-text URL list
        return await self._check_urlhaus_cache(url)

    async def _check_urlhaus_api(self, url: str, auth_key: str) -> dict[str, Any]:
        """Check URL via URLhaus API (requires Auth-Key)."""
        session = await self._get_session()

        try:
            async with session.post(
                self.URLHAUS_API,
                data={"url": url},
                headers={"Auth-Key": auth_key}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()

                    if data.get("query_status") == "ok" and data.get("threat"):
                        return {
                            "found": True,
                            "threat_type": data.get("threat", "malware_download"),
                            "source": "urlhaus",
                            "details": {
                                "id": data.get("id"),
                                "status": data.get("url_status"),
                                "threat": data.get("threat"),
                                "tags": data.get("tags", []),
                                "urlhaus_link": data.get("urlhaus_reference"),
                                "date_added": data.get("date_added"),
                                "target": data.get("tld_guess"),
                            }
                        }

        except Exception as e:
            logger.debug("URLhaus API check failed", error=str(e))

        return {"found": False, "source": "urlhaus"}

    async def _check_urlhaus_cache(self, url: str) -> dict[str, Any]:
        """Check URL against cached URLhaus plain-text URL list (no auth required).

        Tries multiple matching strategies:
        1. Exact match
        2. Scheme-swapped match (http <-> https)
        3. Trailing slash normalization
        """
        now = datetime.utcnow()
        if self._urlhaus_cache is None or \
           (self._urlhaus_cache_time and (now - self._urlhaus_cache_time).seconds > self._urlhaus_cache_ttl):
            await self._refresh_urlhaus_cache()

        if not self._urlhaus_cache:
            return {"found": False, "source": "urlhaus"}

        # Normalize variants to try
        variants = self._url_variants(url)

        for variant in variants:
            if variant in self._urlhaus_cache:
                return {
                    "found": True,
                    "source": "urlhaus",
                    "threat_type": "malware_download",
                    "details": {
                        "message": "URL found in URLhaus database (cached feed)",
                        "matched_variant": variant if variant != url else None,
                    }
                }

        return {"found": False, "source": "urlhaus"}

    def _url_variants(self, url: str) -> list[str]:
        """Generate URL variants for matching (scheme swap, trailing slash)."""
        variants = [url]

        # Scheme swap
        if url.startswith("https://"):
            variants.append("http://" + url[8:])
        elif url.startswith("http://"):
            variants.append("https://" + url[7:])

        # Trailing slash normalization
        for v in list(variants):
            if v.endswith("/"):
                variants.append(v.rstrip("/"))
            else:
                variants.append(v + "/")

        return variants

    async def _refresh_urlhaus_cache(self) -> None:
        """Refresh URLhaus plain-text URL list cache.

        Downloads the online malware URL list from urlhaus.abuse.ch
        which does NOT require authentication.
        """
        session = await self._get_session()

        try:
            async with session.get(self.URLHAUS_TEXT_URL) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    self._urlhaus_cache = set(
                        line.strip() for line in text.strip().split("\n")
                        if line.strip() and not line.startswith("#")
                    )
                    self._urlhaus_cache_time = datetime.utcnow()
                    logger.debug("URLhaus cache refreshed", count=len(self._urlhaus_cache))
        except Exception as e:
            logger.warning("Failed to refresh URLhaus cache", error=str(e))

    async def check_openphish(self, url: str) -> dict[str, Any]:
        """Check if URL is in OpenPhish feed.

        Returns:
            Dict with 'found', 'source', 'details'
        """
        # Refresh cache if needed
        now = datetime.utcnow()
        if self._openphish_cache is None or \
           (self._openphish_cache_time and (now - self._openphish_cache_time).seconds > self._openphish_cache_ttl):
            await self._refresh_openphish_cache()

        if self._openphish_cache:
            for variant in self._url_variants(url):
                if variant in self._openphish_cache:
                    return {
                        "found": True,
                        "source": "openphish",
                        "threat_type": "phishing",
                        "details": {
                            "message": "URL found in OpenPhish feed",
                            "matched_variant": variant if variant != url else None,
                        }
                    }

        return {"found": False, "source": "openphish"}

    async def _refresh_openphish_cache(self) -> None:
        """Refresh OpenPhish feed cache."""
        session = await self._get_session()

        try:
            async with session.get(self.OPENPHISH_URL) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    self._openphish_cache = set(
                        line.strip() for line in text.strip().split("\n")
                        if line.strip()
                    )
                    self._openphish_cache_time = datetime.utcnow()
                    logger.debug("OpenPhish cache refreshed", count=len(self._openphish_cache))
        except Exception as e:
            logger.warning("Failed to refresh OpenPhish cache", error=str(e))

    async def check_reddit(self, url: str) -> dict[str, Any]:
        """Check if URL has been reported on Reddit.

        Returns:
            Dict with 'found', 'source', 'details'
        """
        client_id = os.environ.get("REDDIT_CLIENT_ID")
        client_secret = os.environ.get("REDDIT_CLIENT_SECRET")

        if not client_id or not client_secret:
            return {"found": False, "source": "reddit", "error": "Not configured"}

        try:
            import praw

            reddit = praw.Reddit(
                client_id=client_id,
                client_secret=client_secret,
                user_agent="PhishRadar/1.0",
            )

            # Search for the URL in relevant subreddits
            subreddits = ["phishing", "cybersecurity", "scams"]
            mentions = []

            domain = self._extract_domain(url)

            for sub_name in subreddits:
                try:
                    subreddit = reddit.subreddit(sub_name)

                    # Search for the domain or URL
                    search_query = f'"{domain}"'

                    for post in subreddit.search(search_query, limit=5, time_filter="year"):
                        if post.score >= 3:  # Only count posts with some engagement
                            mentions.append({
                                "subreddit": sub_name,
                                "title": post.title[:100],  # Truncate long titles
                                "score": post.score,
                                "url": f"https://reddit.com{post.permalink}",
                                "created": datetime.fromtimestamp(post.created_utc).isoformat(),
                            })
                except Exception:
                    continue

            if mentions:
                # Be very conservative - Reddit posts often discuss legitimate brands
                # in the context of phishing (e.g., "New Google phishing scam")
                # Only flag if the domain itself is being reported as malicious,
                # not just mentioned in phishing discussions

                phishing_keywords = ["phishing", "scam", "malware", "malicious", "fraud", "spoof"]
                safe_keywords = ["impersonating", "fake", "beware", "warning", "alert"]

                high_confidence_mentions = []
                for m in mentions:
                    title_lower = m["title"].lower()
                    has_phishing_kw = any(kw in title_lower for kw in phishing_keywords)

                    # Check if the domain is specifically called out as malicious
                    # vs just being mentioned as an impersonation target
                    is_brand_impersonation = any(kw in title_lower for kw in safe_keywords)

                    # Only count if:
                    # 1. Very high score (100+) AND phishing keywords
                    # 2. OR score >= 50 AND phishing keywords AND NOT about impersonation
                    if m["score"] >= 100 and has_phishing_kw and not is_brand_impersonation:
                        high_confidence_mentions.append(m)
                    elif m["score"] >= 50 and has_phishing_kw and not is_brand_impersonation:
                        high_confidence_mentions.append(m)

                # Only flag as threat if we have multiple high-confidence mentions
                if len(high_confidence_mentions) >= 2:
                    return {
                        "found": True,
                        "source": "reddit",
                        "threat_type": "reported",
                        "details": {
                            "mentions": high_confidence_mentions[:3],
                            "total_mentions": len(high_confidence_mentions),
                        }
                    }

        except Exception as e:
            logger.debug("Reddit check failed", error=str(e))

        return {"found": False, "source": "reddit"}

    async def check_phishtank(self, url: str) -> dict[str, Any]:
        """Check if URL is in PhishTank database.

        Uses disk-cached database download (online-valid.json).
        Works without API key. Cache refreshes every 4 hours.

        Returns:
            Dict with 'found', 'source', 'details'
        """
        return await self._check_phishtank_cache(url)

    async def _check_phishtank_cache(self, url: str) -> dict[str, Any]:
        """Check URL against cached PhishTank database (works without API key)."""
        now = datetime.utcnow()
        if self._phishtank_cache is None or \
           (self._phishtank_cache_time and (now - self._phishtank_cache_time).seconds > self._phishtank_cache_ttl):
            await self._refresh_phishtank_cache()

        if self._phishtank_cache:
            for variant in self._url_variants(url):
                if variant in self._phishtank_cache:
                    return {
                        "found": True,
                        "source": "phishtank",
                        "threat_type": "phishing",
                        "details": {
                            "message": "URL found in PhishTank database",
                            "matched_variant": variant if variant != url else None,
                        }
                    }

        return {"found": False, "source": "phishtank"}

    async def _refresh_phishtank_cache(self) -> None:
        """Refresh PhishTank database cache.

        Uses a 3-tier approach:
        1. Load from disk cache if fresh (< 4 hours old)
        2. Download from PhishTank API if disk cache is stale
        3. Fall back to stale disk cache if download fails (rate limited)
        """
        cache_dir = Path("data")
        cache_file = cache_dir / "phishtank_cache.json"
        meta_file = cache_dir / "phishtank_cache_meta.json"

        # Tier 1: Try loading from disk cache
        if cache_file.exists() and meta_file.exists():
            try:
                with open(meta_file) as f:
                    meta = json.load(f)
                cached_time = datetime.fromisoformat(meta.get("timestamp", ""))
                age_seconds = (datetime.utcnow() - cached_time).seconds
                if age_seconds < self._phishtank_cache_ttl:
                    with open(cache_file) as f:
                        data = json.load(f)
                    self._phishtank_cache = set(data) if isinstance(data, list) else set()
                    self._phishtank_cache_time = datetime.utcnow()
                    logger.debug("PhishTank cache loaded from disk", count=len(self._phishtank_cache))
                    return
            except Exception as e:
                logger.debug("Failed to load PhishTank disk cache", error=str(e))

        # Tier 2: Download from PhishTank (CSV format — not rate-limited like JSON)
        import csv
        import io

        # Try multiple PhishTank feed URLs (order matters)
        phish_feed_urls = [
            "https://data.phishtank.com/data/online-valid.csv",
            "http://data.phishtank.com/data/online-valid.csv",
            "https://phishtank.org/online-valid.csv",
        ]

        session = await self._get_session()

        for feed_url in phish_feed_urls:
            try:
                async with session.get(feed_url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        reader = csv.DictReader(io.StringIO(text))
                        url_set = set(
                            row["url"]
                            for row in reader
                            if row.get("url")
                        )
                        self._phishtank_cache = url_set
                        self._phishtank_cache_time = datetime.utcnow()

                        # Save to disk
                        cache_dir.mkdir(parents=True, exist_ok=True)
                        with open(cache_file, "w") as f:
                            json.dump(list(url_set), f)
                        with open(meta_file, "w") as f:
                            json.dump({"timestamp": datetime.utcnow().isoformat()}, f)

                        logger.info("PhishTank cache refreshed from CSV feed", count=len(url_set), url=feed_url)
                        return
                    else:
                        logger.debug("PhishTank feed URL returned non-200", url=feed_url, status=resp.status)
            except Exception as e:
                logger.debug("PhishTank feed URL failed", url=feed_url, error=str(e))

        logger.warning("All PhishTank feed URLs failed")

        # Tier 3: Fall back to stale disk cache
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                self._phishtank_cache = set(data) if isinstance(data, list) else set()
                self._phishtank_cache_time = datetime.utcnow()
                logger.info("PhishTank using stale disk cache", count=len(self._phishtank_cache))
            except Exception as e:
                logger.warning("Failed to load stale PhishTank cache", error=str(e))

    async def check_virustotal(self, url: str) -> dict[str, Any]:
        """Check URL reputation via VirusTotal API.

        Free tier: 4 requests/minute, 500 requests/day.
        Get API key from: https://www.virustotal.com/gui/my-apikey

        Returns:
            Dict with 'found', 'source', 'threat_type', 'details'
        """
        vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY")

        if not vt_api_key:
            return {"found": False, "source": "virustotal", "error": "API key not configured"}

        session = await self._get_session()

        try:
            # VirusTotal requires URL to be base64 encoded (without padding)
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            async with session.get(
                f"{self.VIRUSTOTAL_API}/{url_id}",
                headers={"x-apikey": vt_api_key}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()

                    attributes = data.get("data", {}).get("attributes", {})
                    last_analysis = attributes.get("last_analysis_stats", {})

                    malicious = last_analysis.get("malicious", 0)
                    suspicious = last_analysis.get("suspicious", 0)
                    total = sum(last_analysis.values())

                    # Consider it a threat if any engine flagged it as malicious
                    if malicious > 0 or suspicious > 0:
                        # Get specific threats from engines
                        results = attributes.get("last_analysis_results", {})
                        threats = [
                            {"engine": k, "result": v.get("result")}
                            for k, v in results.items()
                            if v.get("category") in ["malicious", "suspicious"]
                        ][:5]  # Top 5

                        return {
                            "found": True,
                            "source": "virustotal",
                            "threat_type": "malware" if malicious > suspicious else "suspicious",
                            "details": {
                                "malicious_count": malicious,
                                "suspicious_count": suspicious,
                                "total_engines": total,
                                "reputation": attributes.get("reputation", 0),
                                "threats": threats,
                                "first_submitted": attributes.get("first_submission_date"),
                                "last_analysis": attributes.get("last_analysis_date"),
                            }
                        }

                elif resp.status == 429:
                    logger.warning("VirusTotal rate limit exceeded")
                    return {"found": False, "source": "virustotal", "error": "Rate limited"}

        except Exception as e:
            logger.debug("VirusTotal check failed", error=str(e))

        return {"found": False, "source": "virustotal"}

    async def check_google_safebrowsing(self, url: str) -> dict[str, Any]:
        """Check URL via Google Safe Browsing API.

        Free tier: 10,000 requests/day.
        Get API key from: https://console.cloud.google.com/apis/credentials

        Returns:
            Dict with 'found', 'source', 'threat_type', 'details'
        """
        gsb_api_key = os.environ.get("GOOGLE_SAFEBROWSING_API_KEY")

        if not gsb_api_key:
            return {"found": False, "source": "google_safebrowsing", "error": "API key not configured"}

        session = await self._get_session()

        try:
            # Parse URL to get threats
            parsed = urlparse(url)
            threat_entries = [{"url": url}]

            payload = {
                "client": {
                    "clientId": "phishradar",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": threat_entries
                }
            }

            async with session.post(
                f"{self.GOOGLE_SAFEBROWSING_API}?key={gsb_api_key}",
                json=payload
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()

                    if data.get("matches"):
                        matches = data["matches"]
                        threat_types = list(set(m.get("threatType") for m in matches))

                        return {
                            "found": True,
                            "source": "google_safebrowsing",
                            "threat_type": "phishing" if "SOCIAL_ENGINEERING" in threat_types else "malware",
                            "details": {
                                "threat_types": threat_types,
                                "platforms": list(set(m.get("platformType") for m in matches)),
                                "cache_duration": matches[0].get("cacheDuration") if matches else None,
                            }
                        }

        except Exception as e:
            logger.debug("Google Safe Browsing check failed", error=str(e))

        return {"found": False, "source": "google_safebrowsing"}

    async def check_urlscan(self, url: str) -> dict[str, Any]:
        """Check if URL has been scanned on urlscan.io.

        Free tier: 1000 searches/day.
        Get API key from: https://urlscan.io/user-apikey/

        Returns:
            Dict with 'found', 'source', 'threat_type', 'details'
        """
        urlscan_api_key = os.environ.get("URLSCAN_API_KEY")

        session = await self._get_session()

        try:
            # Search for the domain
            domain = self._extract_domain(url)
            headers = {}
            if urlscan_api_key:
                headers["API-Key"] = urlscan_api_key

            async with session.get(
                f"{self.URLSCAN_API}?q=domain:{domain}",
                headers=headers
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()

                    results = data.get("results", [])
                    if results:
                        # Check if any results are marked as malicious
                        # Only flag if the page has been flagged as malicious by urlscan
                        malicious_scans = []
                        for r in results[:10]:
                            task = r.get("task", {})
                            verdicts = r.get("verdicts", {})
                            # Check if urlscan flagged it as malicious
                            if verdicts.get("overall", {}).get("malicious"):
                                malicious_scans.append(r)
                            # Or if it's an automatic scan with high malicious score
                            elif task.get("method") == "automatic":
                                stats = r.get("stats", {})
                                # Check for phishing indicators
                                if stats.get("phishing", 0) > 0:
                                    malicious_scans.append(r)

                        if malicious_scans:
                            return {
                                "found": True,
                                "source": "urlscan",
                                "threat_type": "phishing",
                                "details": {
                                    "total_scans": data.get("total", 0),
                                    "malicious_count": len(malicious_scans),
                                    "scan_urls": [
                                        f"https://urlscan.io/result/{r.get('_id')}"
                                        for r in malicious_scans[:3]
                                    ],
                                    "first_seen": malicious_scans[0].get("task", {}).get("time"),
                                }
                            }

        except Exception as e:
            logger.debug("urlscan.io check failed", error=str(e))

        return {"found": False, "source": "urlscan"}

    async def check_all_sources(self, url: str) -> ThreatCheckResult:
        """Check URL against all threat intelligence sources.

        Checks in order of speed (fastest/most reliable first):
        1. URLhaus (free, fast)
        2. OpenPhish (free, cached)
        3. VirusTotal (free tier)
        4. Google Safe Browsing (free)
        5. urlscan.io (free tier)
        6. Reddit (requires credentials)
        7. PhishTank (free, rate limited without key)

        Args:
            url: URL to check

        Returns:
            ThreatCheckResult with combined findings
        """
        logger.info("Checking threat feeds", url=url)

        # Run all checks in parallel
        tasks = [
            self.check_urlhaus(url),
            self.check_openphish(url),
            self.check_virustotal(url),
            self.check_google_safebrowsing(url),
            self.check_urlscan(url),
            self.check_reddit(url),
            self.check_phishtank(url),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate results
        sources_found = []
        all_details = {}
        threat_type = None
        target_brand = None

        for result in results:
            # Handle exceptions from individual feed checks
            if isinstance(result, Exception):
                logger.warning("Feed check raised exception", error=str(result))
                continue

            source = result.get("source", "unknown")
            all_details[source] = result

            if result.get("found"):
                sources_found.append(source)

                if not threat_type and result.get("threat_type"):
                    threat_type = result["threat_type"]

                # Extract target brand from details
                details = result.get("details", {})
                if details.get("target"):
                    target_brand = details["target"]

        is_threat = len(sources_found) > 0

        if is_threat:
            logger.info(
                "URL found in threat feeds",
                url=url,
                sources=sources_found
            )

        return ThreatCheckResult(
            url=url,
            is_known_threat=is_threat,
            sources=sources_found,
            details=all_details,
            threat_type=threat_type,
            target_brand=target_brand,
        )

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc.replace("www.", "")
        except Exception:
            return url

    async def close(self) -> None:
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
