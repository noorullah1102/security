"""Collect real phishing and legitimate URLs for training.

Sources:
- Phishing: URLhaus, OpenPhish, Reddit
- Legitimate: Tranco top domains, Cisco Umbrella
"""

import asyncio
import json
import os
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import aiohttp
from structlog import get_logger

logger = get_logger()


@dataclass
class URLSample:
    """A single URL sample for training."""
    url: str
    label: Literal["phishing", "legitimate"]
    source: str


class PhishingDataCollector:
    """Collect phishing URLs from multiple sources."""

    URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    URLHAUS_ONLINE_URL = "https://urlhaus.abuse.ch/downloads/text/"
    OPENPHISH_URL = "https://openphish.com/feed.txt"

    def __init__(self, max_per_source: int = 500):
        """Initialize collector.

        Args:
            max_per_source: Maximum URLs to collect per source
        """
        self.max_per_source = max_per_source
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def fetch_urlhaus(self) -> list[str]:
        """Fetch phishing URLs from URLhaus."""
        session = await self._get_session()
        urls = []

        try:
            # Try the recent URLs API first
            logger.info("Fetching from URLhaus API...")
            async with session.get(self.URLHAUS_RECENT_URL, params={"limit": self.max_per_source}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get("urls", [])[:self.max_per_source]:
                        url = item.get("url")
                        if url and self._is_valid_url(url):
                            urls.append(url)
                    logger.info("URLhaus API fetched", count=len(urls))
                    return urls
        except Exception as e:
            logger.warning("URLhaus API failed, trying text dump", error=str(e))

        # Fallback to text dump
        try:
            async with session.get(self.URLHAUS_ONLINE_URL) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.strip().split("\n")[:self.max_per_source]:
                        url = line.strip()
                        if url and not url.startswith("#") and self._is_valid_url(url):
                            urls.append(url)
                    logger.info("URLhaus text dump fetched", count=len(urls))
        except Exception as e:
            logger.warning("URLhaus text dump failed", error=str(e))

        return urls

    async def fetch_openphish(self) -> list[str]:
        """Fetch phishing URLs from OpenPhish."""
        session = await self._get_session()
        urls = []

        try:
            logger.info("Fetching from OpenPhish...")
            async with session.get(self.OPENPHISH_URL) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.strip().split("\n")[:self.max_per_source]:
                        url = line.strip()
                        if url and self._is_valid_url(url):
                            urls.append(url)
                    logger.info("OpenPhish fetched", count=len(urls))
        except Exception as e:
            logger.warning("OpenPhish fetch failed", error=str(e))

        return urls

    async def fetch_reddit(self) -> list[str]:
        """Fetch phishing URLs from Reddit r/cybersecurity and r/phishing.

        Requires Reddit API credentials:
        - REDDIT_CLIENT_ID
        - REDDIT_CLIENT_SECRET
        """
        urls = []

        # Check for Reddit credentials
        client_id = os.environ.get("REDDIT_CLIENT_ID")
        client_secret = os.environ.get("REDDIT_CLIENT_SECRET")

        if not client_id or not client_secret:
            logger.warning("Reddit API credentials not set. Skipping Reddit source.")
            logger.info("To use Reddit, set: REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET")
            return urls

        try:
            import praw

            logger.info("Fetching from Reddit...")

            reddit = praw.Reddit(
                client_id=client_id,
                client_secret=client_secret,
                user_agent="PhishRadar/1.0",
            )

            # Subreddits to monitor
            subreddits = ["phishing", "cybersecurity", "scams"]
            keywords = ["phishing", "scam", "malicious", "fraud", "credential"]

            for sub_name in subreddits:
                try:
                    subreddit = reddit.subreddit(sub_name)

                    # Get hot posts
                    for post in subreddit.hot(limit=50):
                        # Skip low-score posts
                        if post.score < 5:
                            continue

                        # Extract URLs from post
                        post_urls = []

                        # Link post
                        if post.url and not post.is_self:
                            if self._is_valid_url(post.url):
                                post_urls.append(post.url)

                        # Text post - extract URLs
                        if post.selftext:
                            import re
                            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
                            found = re.findall(url_pattern, post.selftext)
                            for url in found:
                                if self._is_valid_url(url):
                                    post_urls.append(url)

                        # Filter out Reddit internal links
                        post_urls = [
                            url for url in post_urls
                            if "reddit.com" not in url and "redd.it" not in url
                        ]

                        urls.extend(post_urls)

                        if len(urls) >= self.max_per_source:
                            break

                except Exception as e:
                    logger.warning(f"Reddit subreddit {sub_name} failed", error=str(e))
                    continue

            logger.info("Reddit fetched", count=len(urls))

        except ImportError:
            logger.warning("PRAW not installed. Run: pip install praw")
        except Exception as e:
            logger.warning("Reddit fetch failed", error=str(e))

        return urls[:self.max_per_source]

    async def collect_all(self, include_reddit: bool = True) -> list[str]:
        """Collect phishing URLs from all sources.

        Args:
            include_reddit: Whether to include Reddit as a source
        """
        tasks = [
            self.fetch_urlhaus(),
            self.fetch_openphish(),
        ]

        if include_reddit:
            tasks.append(self.fetch_reddit())

        results = await asyncio.gather(*tasks)

        # Combine and dedupe
        all_urls = set()
        for url_list in results:
            all_urls.update(url_list)

        logger.info("Total phishing URLs collected", count=len(all_urls))
        return list(all_urls)

    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid for training."""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False

    async def close(self):
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()


class LegitimateDataCollector:
    """Collect legitimate URLs from trusted sources."""

    TRANCO_URL = "https://tranco-list.eu/download/X5Q6L/1000"
    CISCO_UMBRELLA_URL = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
    DOMCOP_URL = "https://www.domcop.com/files/top/domains/top-10k-domains-.json"

    # Common paths to append to legitimate domains
    COMMON_PATHS = [
        "/", "/about", "/contact", "/products", "/services",
        "/blog", "/news", "/help", "/faq", "/login", "/search",
        "/api", "/docs", "/pricing", "/features", "/team",
    ]

    def __init__(self, max_domains: int = 500):
        """Initialize collector.

        Args:
            max_domains: Maximum domains to collect
        """
        self.max_domains = max_domains
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=60)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def fetch_tranco(self) -> list[str]:
        """Fetch top domains from Tranco list."""
        session = await self._get_session()
        domains = []

        # Try multiple Tranco list IDs
        tranco_ids = ["X5Q6L", "LJ7Q2", "K5Q6L"]  # Different time periods

        for list_id in tranco_ids:
            try:
                url = f"https://tranco-list.eu/download/{list_id}/1000"
                logger.info(f"Fetching from Tranco (list {list_id})...")
                async with session.get(url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.strip().split("\n")[:self.max_domains]:
                            parts = line.strip().split(",")
                            if len(parts) >= 2:
                                domain = parts[1].strip()
                                if domain:
                                    domains.append(domain)
                        if domains:
                            logger.info("Tranco fetched", count=len(domains))
                            return domains
            except Exception as e:
                logger.warning(f"Tranco list {list_id} failed", error=str(e))

        # Fallback to hardcoded top domains
        logger.info("Using fallback top domains...")
        return self._get_fallback_domains()

    def _get_fallback_domains(self) -> list[str]:
        """Get fallback list of top legitimate domains."""
        # Comprehensive list of legitimate, well-known domains
        return [
            # Tech giants
            "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
            "linkedin.com", "wikipedia.org", "reddit.com", "amazon.com", "netflix.com",
            "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "medium.com",
            # Cloud & Dev
            "cloudflare.com", "stripe.com", "twilio.com", "heroku.com", "vercel.com",
            "netlify.com", "digitalocean.com", "aws.amazon.com", "azure.microsoft.com",
            "cloud.google.com", "docker.com", "kubernetes.io", "npmjs.com", "pypi.org",
            # SaaS
            "notion.so", "slack.com", "zoom.us", "dropbox.com", "figma.com",
            "canva.com", "trello.com", "asana.com", "airtable.com", "webflow.com",
            "atlassian.com", "salesforce.com", "hubspot.com", "mailchimp.com", "zendesk.com",
            # E-commerce
            "paypal.com", "ebay.com", "walmart.com", "target.com", "bestbuy.com",
            "etsy.com", "shopify.com", "craigslist.org", "costco.com", "ikea.com",
            # Media & News
            "cnn.com", "bbc.com", "nytimes.com", "washingtonpost.com", "theguardian.com",
            "forbes.com", "bloomberg.com", "wsj.com", "techcrunch.com", "theverge.com",
            "engadget.com", "wired.com", "arstechnica.com", "gizmodo.com", "mashable.com",
            # Streaming & Entertainment
            "spotify.com", "twitch.tv", "pinterest.com", "tumblr.com", "tiktok.com",
            "disney.com", "hulu.com", "hbomax.com", "paramount.com", "peacocktv.com",
            # Email & Communication
            "gmail.com", "outlook.com", "office.com", "live.com", "yahoo.com",
            "protonmail.com", "icloud.com", "aol.com", "mail.com", "zoho.com",
            # Finance
            "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com",
            "capitalone.com", "usbank.com", "pnc.com", "td.com", "fidelity.com",
            "vanguard.com", "schwab.com", "robinhood.com", "coinbase.com",
            # Education
            "mit.edu", "stanford.edu", "harvard.edu", "berkeley.edu", "cmu.edu",
            "caltech.edu", "princeton.edu", "yale.edu", "columbia.edu", "nyu.edu",
            "coursera.org", "udemy.com", "edx.org", "khanacademy.org", "duolingo.com",
            # Government
            "usa.gov", "whitehouse.gov", "nasa.gov", "cdc.gov", "fbi.gov",
            "irs.gov", "ssa.gov", "va.gov", "medicare.gov", "studentaid.gov",
            # Healthcare
            "mayoclinic.org", "webmd.com", "healthline.com", "nih.gov", "who.int",
            "clevelandclinic.org", "hopkinsmedicine.org", "ucsf.edu",
            # Travel
            "expedia.com", "booking.com", "airbnb.com", "tripadvisor.com", "kayak.com",
            "hotels.com", "priceline.com", "southwest.com", "delta.com", "united.com",
            # Food & Dining
            "doordash.com", "ubereats.com", "grubhub.com", "instacart.com",
            "starbucks.com", "mcdonalds.com", "dominos.com", "chipotle.com",
            # Automotive
            "tesla.com", "ford.com", "chevrolet.com", "toyota.com", "honda.com",
            "bmw.com", "mercedes-benz.com", "volkswagen.com", "audi.com",
            # Non-profit
            "wikipedia.org", "mozilla.org", "wikimedia.org", "archive.org",
            "eff.org", "opensource.org", "linuxfoundation.org", "apache.org",
            # More tech
            "openai.com", "anthropic.com", "deepmind.com", "nvidia.com", "intel.com",
            "amd.com", "cisco.com", "oracle.com", "ibm.com", "sap.com",
            "adobe.com", "autodesk.com", "intuit.com", "vmware.com",
        ]

    async def collect_all(self) -> list[str]:
        """Collect legitimate URLs."""
        domains = await self.fetch_tranco()

        # Convert domains to URLs with varied paths
        urls = []
        for domain in domains[:self.max_domains]:
            # Add root URL
            urls.append(f"https://{domain}/")

            # Add some with random paths for variety
            if random.random() < 0.3:
                path = random.choice(self.COMMON_PATHS)
                urls.append(f"https://{domain}{path}")

        logger.info("Total legitimate URLs generated", count=len(urls))
        return urls

    async def close(self):
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()


async def collect_training_data(
    output_dir: str = "data/training",
    max_phishing: int = 500,
    max_legitimate: int = 500,
    include_reddit: bool = True,
) -> tuple[list[URLSample], dict]:
    """Collect training data from all sources.

    Args:
        output_dir: Directory to save collected data
        max_phishing: Maximum phishing URLs to collect
        max_legitimate: Maximum legitimate URLs to collect
        include_reddit: Whether to include Reddit as a source

    Returns:
        Tuple of (samples, stats)
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    stats = {
        "phishing_collected": 0,
        "legitimate_collected": 0,
        "total_collected": 0,
        "sources": {},
    }

    samples = []

    # Collect phishing URLs
    phishing_collector = PhishingDataCollector(max_per_source=max_phishing // 3)
    try:
        phishing_urls = await phishing_collector.collect_all(include_reddit=include_reddit)

        # Determine source label
        source_label = "urlhaus+openphish"
        if include_reddit and os.environ.get("REDDIT_CLIENT_ID"):
            source_label = "urlhaus+openphish+reddit"

        for url in phishing_urls[:max_phishing]:
            samples.append(URLSample(
                url=url,
                label="phishing",
                source=source_label
            ))
        stats["phishing_collected"] = min(len(phishing_urls), max_phishing)
        stats["sources"][source_label] = len(phishing_urls)
    finally:
        await phishing_collector.close()

    # Collect legitimate URLs
    legit_collector = LegitimateDataCollector(max_domains=max_legitimate)
    try:
        legit_urls = await legit_collector.collect_all()
        for url in legit_urls[:max_legitimate]:
            samples.append(URLSample(
                url=url,
                label="legitimate",
                source="tranco"
            ))
        stats["legitimate_collected"] = min(len(legit_urls), max_legitimate)
        stats["sources"]["tranco"] = len(legit_urls)
    finally:
        await legit_collector.close()

    # Shuffle samples
    random.shuffle(samples)
    stats["total_collected"] = len(samples)

    # Save to JSON
    data = [
        {"url": s.url, "label": s.label, "source": s.source}
        for s in samples
    ]

    output_file = output_path / "real_dataset.json"
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)

    logger.info("Dataset saved", path=str(output_file), total=len(samples))

    # Save stats
    with open(output_path / "collection_stats.json", "w") as f:
        json.dump(stats, f, indent=2)

    return samples, stats


async def main():
    """Main entry point for data collection."""
    print("=" * 60)
    print("PhishRadar - Real Data Collection")
    print("=" * 60)

    # Check for Reddit credentials
    has_reddit = bool(os.environ.get("REDDIT_CLIENT_ID") and os.environ.get("REDDIT_CLIENT_SECRET"))

    print("\nSources:")
    print("  [1] URLhaus      - Malicious URL database")
    print("  [2] OpenPhish    - Phishing feed")
    if has_reddit:
        print("  [3] Reddit       - r/phishing, r/cybersecurity (configured)")
    else:
        print("  [3] Reddit       - Not configured (set REDDIT_CLIENT_ID/SECRET)")

    print("\nTo enable Reddit:")
    print("  1. Go to https://www.reddit.com/prefs/apps")
    print("  2. Create a 'script' app")
    print("  3. Export credentials:")
    print("     export REDDIT_CLIENT_ID=your_client_id")
    print("     export REDDIT_CLIENT_SECRET=your_client_secret")

    print("\n[1/2] Collecting phishing URLs...")
    print("[2/2] Collecting legitimate URLs...\n")

    samples, stats = await collect_training_data(
        output_dir="data/training",
        max_phishing=500,
        max_legitimate=500,
        include_reddit=has_reddit,
    )

    print("\n" + "=" * 60)
    print("Collection Complete!")
    print("=" * 60)
    print(f"\nPhishing URLs:    {stats['phishing_collected']}")
    print(f"Legitimate URLs:  {stats['legitimate_collected']}")
    print(f"Total Samples:    {stats['total_collected']}")
    print(f"\nSaved to: data/training/real_dataset.json")

    # Show source breakdown
    print("\nSources:")
    for source, count in stats["sources"].items():
        print(f"  - {source}: {count} URLs")


if __name__ == "__main__":
    asyncio.run(main())
