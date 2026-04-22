"""URL feature extraction module."""

import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import tldextract
from structlog import get_logger

from src.analyzer.models import URLFeatures

logger = get_logger()

# Suspicious TLDs commonly used for phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs
    ".xyz", ".top", ".club", ".online", ".site",  # Cheap TLDs
    ".work", ".click", ".link", ".info", ".biz",  # Often abused
    ".cc", ".ru", ".cn",  # High abuse rates
}

# Suspicious keywords often found in phishing URLs
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "account", "update", "confirm", "confirmation",
    "password", "passwd", "pwd", "credential", "auth", "authenticate",
    "banking", "alert", "warning", "suspended", "locked", "unlock",
    "verify-account", "secure-login", "account-update", "action-required",
    "webscr", "cmd", "dispatch", "session", "token", "access",
}

# Brand names often impersonated (used for smarter detection)
BRAND_NAMES = {
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "chase", "bankofamerica",
    "wellsfargo", "citi", "ebay", "walmart", "target",
}


class FeatureExtractor:
    """Extract features from URLs for phishing detection."""

    def __init__(
        self,
        redirect_timeout: float = 5.0,
        ssl_timeout: float = 5.0,
        whois_timeout: float = 10.0,
    ):
        """Initialize the feature extractor.

        Args:
            redirect_timeout: Timeout for following redirects (seconds)
            ssl_timeout: Timeout for SSL certificate checks (seconds)
            whois_timeout: Timeout for WHOIS lookups (seconds)
        """
        self.redirect_timeout = redirect_timeout
        self.ssl_timeout = ssl_timeout
        self.whois_timeout = whois_timeout

    def extract(self, url: str) -> URLFeatures:
        """Extract all features from a URL.

        Args:
            url: The URL to analyze

        Returns:
            URLFeatures dataclass with all extracted features
        """
        logger.debug("Extracting features", url=url)

        # Parse URL
        parsed = urlparse(url)

        # Detect IP address early — determines how we process the URL
        netloc = parsed.netloc
        # Strip brackets from IPv6 and port
        host = netloc.split(":")[0]
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        has_ip_address = self._has_ip_address(netloc)

        if has_ip_address:
            return self._extract_ip_url(url, parsed, host)

        # Normal domain-based URL
        extracted = tldextract.extract(url)

        # Extract domain info (needed for smart keyword detection)
        domain = extracted.registered_domain or parsed.netloc

        # Extract lexical features
        url_length = len(url)
        path_depth = self._get_path_depth(parsed.path)
        has_https = parsed.scheme == "https"
        subdomain_count = self._count_subdomains(extracted.subdomain)
        suspicious_tld = self._is_suspicious_tld(extracted.suffix)
        has_suspicious_keywords = self._has_suspicious_keywords(url.lower(), domain)

        # Check SSL certificate
        ssl_valid, ssl_issuer = self._check_ssl(netloc, has_https)

        # Get domain age (with caching)
        domain_age_days = self._get_domain_age(domain)

        # Follow redirects
        redirect_count, redirect_chain = self._follow_redirects(url)

        # Typosquatting detection
        typosquat_target, typosquat_distance = self._check_typosquat(extracted.domain)

        return URLFeatures(
            domain_age_days=domain_age_days,
            ssl_valid=ssl_valid,
            ssl_issuer=ssl_issuer,
            redirect_count=redirect_count,
            redirect_chain=redirect_chain,
            typosquat_target=typosquat_target,
            typosquat_distance=typosquat_distance,
            has_ip_address=False,
            url_length=url_length,
            path_depth=path_depth,
            has_suspicious_keywords=has_suspicious_keywords,
            subdomain_count=subdomain_count,
            has_https=has_https,
            suspicious_tld=suspicious_tld,
        )

    def _extract_ip_url(self, url: str, parsed, host: str) -> URLFeatures:
        """Extract features for IP-address-based URLs.

        IP URLs skip WHOIS, typosquatting, and subdomain analysis
        (these don't apply to raw IPs).
        """
        url_length = len(url)
        path_depth = self._get_path_depth(parsed.path)
        has_https = parsed.scheme == "https"
        has_suspicious_keywords = self._has_suspicious_keywords(url.lower(), host)

        # SSL check on IP
        ssl_valid, ssl_issuer = self._check_ssl(parsed.netloc, has_https)

        # Follow redirects
        redirect_count, redirect_chain = self._follow_redirects(url)

        return URLFeatures(
            domain_age_days=0,
            ssl_valid=ssl_valid,
            ssl_issuer=ssl_issuer,
            redirect_count=redirect_count,
            redirect_chain=redirect_chain,
            typosquat_target=None,
            typosquat_distance=0,
            has_ip_address=True,
            url_length=url_length,
            path_depth=path_depth,
            has_suspicious_keywords=has_suspicious_keywords,
            subdomain_count=0,
            has_https=has_https,
            suspicious_tld=False,
        )

    def _get_path_depth(self, path: str) -> int:
        """Calculate the depth of the URL path."""
        if not path or path == "/":
            return 0
        return len([p for p in path.strip("/").split("/") if p])

    def _count_subdomains(self, subdomain: str) -> int:
        """Count the number of subdomains."""
        if not subdomain:
            return 0
        return len(subdomain.split("."))

    def _has_ip_address(self, netloc: str) -> bool:
        """Check if the netloc contains an IP address."""
        # Remove port if present
        host = netloc.split(":")[0]

        # Check for IPv4
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass

        # Check for IPv6
        if host.startswith("[") and host.endswith("]"):
            try:
                ipaddress.ip_address(host[1:-1])
                return True
            except ValueError:
                pass

        return False

    def _is_suspicious_tld(self, tld: str) -> bool:
        """Check if the TLD is commonly used for phishing."""
        if not tld:
            return False
        return f".{tld.lower()}" in SUSPICIOUS_TLDS

    # Well-known legitimate domains — skip keyword checks
    TRUSTED_DOMAINS = {
        "google.com", "www.google.com", "gmail.com",
        "microsoft.com", "live.com", "outlook.com", "office.com",
        "apple.com", "icloud.com",
        "amazon.com", "aws.amazon.com",
        "facebook.com", "fb.com", "meta.com",
        "paypal.com",
        "netflix.com",
        "twitter.com", "x.com",
        "instagram.com",
        "linkedin.com",
        "github.com", "www.github.com",
        "youtube.com", "www.youtube.com",
        "reddit.com", "www.reddit.com",
        "wikipedia.org", "www.wikipedia.org",
        "stackoverflow.com",
        "yahoo.com",
        "dropbox.com",
        "adobe.com",
        "steampowered.com",
        "cloudflare.com",
        "openai.com",
        "anthropic.com",
        "chase.com",
        "bankofamerica.com",
        "wellsfargo.com",
        "citibank.com", "citi.com",
    }

    def _has_suspicious_keywords(self, url: str, domain: str = "") -> bool:
        """Check if URL contains suspicious keywords.

        Smart detection: Brand names are only suspicious if the domain
        isn't the official brand domain. Trusted domains skip keyword checks.
        """
        url_lower = url.lower()
        domain_lower = (domain or "").lower()

        # Skip keyword checks for trusted domains
        if domain_lower in self.TRUSTED_DOMAINS:
            return False

        # Check for action-based suspicious keywords
        if any(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS):
            return True

        # Check for brand impersonation
        for brand in BRAND_NAMES:
            if brand in url_lower:
                # If domain is exactly the brand domain, it's legitimate
                if domain_lower == f"{brand}.com" or domain_lower == brand:
                    continue
                # If brand appears in path or subdomain of non-brand domain, suspicious
                return True

        return False

    def _check_ssl(self, netloc: str, is_https: bool) -> tuple[bool, str | None]:
        """Check SSL certificate validity."""
        if not is_https:
            return False, None

        host = netloc.split(":")[0]
        port = 443

        if ":" in netloc:
            parts = netloc.split(":")
            try:
                port = int(parts[1])
            except (ValueError, IndexError):
                port = 443

        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.ssl_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    issuer_name = issuer.get("organizationName", issuer.get("commonName"))
                    return True, issuer_name
        except Exception as e:
            logger.debug("SSL check failed", host=host, error=str(e))
            return False, None

    def _get_domain_age(self, domain: str) -> int:
        """Get domain age in days using WHOIS."""
        if not domain or self._has_ip_address(domain):
            return 0

        try:
            import whois

            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age = datetime.now(timezone.utc) - creation_date
                return max(0, age.days)

        except Exception as e:
            logger.debug("WHOIS lookup failed", domain=domain, error=str(e))

        return 0

    def _follow_redirects(self, url: str) -> tuple[int, list[str]]:
        """Follow HTTP redirects and return chain."""
        redirect_chain = [url]

        try:
            import requests

            response = requests.get(
                url,
                allow_redirects=True,
                timeout=self.redirect_timeout,
                headers={"User-Agent": "PhishRadar/1.0"},
            )

            if response.history:
                for resp in response.history:
                    redirect_chain.append(str(resp.url))
                redirect_chain.append(str(response.url))
                return len(response.history), redirect_chain
        except Exception as e:
            logger.debug("Redirect check failed", url=url, error=str(e))

        return 0, redirect_chain

    def _check_typosquat(self, domain: str) -> tuple[str | None, int]:
        """Check if domain is a typosquat of popular domains."""
        popular_domains = [
            "google", "facebook", "amazon", "apple", "microsoft",
            "paypal", "netflix", "twitter", "instagram", "linkedin",
            "bankofamerica", "chase", "wellsfargo", "citi", "yahoo",
            "outlook", "hotmail", "gmail", "office", "onedrive",
        ]

        domain_lower = domain.lower()

        # Check for exact match first
        if domain_lower in popular_domains:
            return None, 0

        # Simple Levenshtein distance check
        min_distance = float("inf")
        closest_match = None

        for popular in popular_domains:
            distance = self._levenshtein_distance(domain_lower, popular)
            if distance < min_distance and distance <= 2:
                min_distance = distance
                closest_match = popular

        if closest_match and min_distance <= 2:
            return f"{closest_match}.com", int(min_distance)

        return None, 0

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def to_feature_vector(self, features: URLFeatures) -> list[float]:
        """Convert URLFeatures to ML model input vector."""
        return [
            float(min(features.domain_age_days, 3650)),
            float(features.ssl_valid),
            float(features.redirect_count),
            float(features.typosquat_distance),
            float(features.has_ip_address),
            float(min(features.url_length, 500)),
            float(features.path_depth),
            float(features.has_suspicious_keywords),
            float(features.subdomain_count),
            float(features.has_https),
            float(features.suspicious_tld),
        ]
