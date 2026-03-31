"""Reddit monitor for trending threat discussions.

Uses PRAW to monitor r/cybersecurity subreddit for URLs and threat keywords.
"""

import asyncio
import re
from datetime import datetime, timedelta
from typing import Any

from urllib.parse import urlparse

import praw
from structlog import get_logger

from src.config import get_settings
from src.feeds.normalizer import FeedNormalizer, ThreatIndicatorData

logger = get_logger()


class RedditError(Exception):
    """Exception raised for Reddit API errors."""

    def __init__(self, message: str):
        """Initialize error.

        Args:
            message: Error message
        """
        super().__init__(message)


class RedditMonitor:
    """Monitor Reddit for trending phishing threats.

    Uses PRAW (Python Reddit API Wrapper) for Reddit API access.
    Rate limits:
    - 60 requests per minute (standard Reddit limits)
    """

    SUBREDDIT = "cybersecurity"
    TARGET_POSTS_PER_RUN = 30
    MIN_SCORE = 10  # Minimum score for trending

    LOOKBACK_HOURS = 3

    # Keyword patterns for threat detection
    SUSPICIOUS_KEYWORDS = [
        "phishing",
        "phish",
        "scam",
        "malware",
        "ransomware",
        "credential",
        "stealer",
        "fraud",
    ]

    # URL extraction regex
    URL_PATTERN = re.compile(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .-]*/?\??[^ \n]+',
        re.IGNORECASE,
    )

    def __init__(self):
        """Initialize Reddit monitor."""
        settings = get_settings()
        self.normalizer = FeedNormalizer()
        self._reddit: praw.Reddit | None = None
        self._last_request_time: datetime | None = None

        # Store credentials
        self.client_id = settings.reddit_client_id
        self.client_secret = settings.reddit_client_secret
        self.user_agent = settings.reddit_user_agent

    def _get_reddit(self) -> praw.Reddit:
        """Get or create Reddit client."""
        if self._reddit is None:
            if not self.client_id or not self.client_secret:
                raise RedditError("Reddit API credentials not configured")

            self._reddit = praw.Reddit(
                client_id=self.client_id,
                client_secret=self.client_secret,
                user_agent=self.user_agent,
            )
        return self._reddit

    async def fetch_feed(self, limit: int = 30) -> list[ThreatIndicatorData]:
        """Fetch trending threat-related posts from Reddit.

        Args:
            limit: Maximum number of posts to fetch

        Returns:
            List of normalized threat indicators

        Raises:
            RedditError: If API request fails
        """
        try:
            reddit = self._get_reddit()
            subreddit = reddit.subreddit(self.SUBREDDIT)

            # Get hot posts
            posts = list(subreddit.hot(limit=limit or self.TARGET_POSTS_PER_RUN))
            self._last_request_time = datetime.utcnow()

            indicators = []

            for post in posts:
                try:
                    # Skip low-engagement posts
                    if post.score < self.MIN_SCORE:
                        continue

                    # Extract URLs from post
                    urls = self._extract_urls(post)

                    for url in urls:
                        # Skip Reddit internal links
                        if "reddit.com" in url or "redd.it" in url:
                            continue

                        # Normalize the data
                        raw_data = {
                            "post_id": post.id,
                            "url": url,
                            "title": post.title,
                            "subreddit": str(post.subreddit),
                            "author": str(post.author) if post.author else "[deleted]",
                            "created_utc": post.created_utc,
                            "score": post.score,
                            "num_comments": post.num_comments,
                            "permalink": post.permalink,
                        }

                        indicator = self.normalizer.normalize_reddit(raw_data)
                        if indicator:
                            indicators.append(indicator)

                except Exception as e:
                    logger.debug("Failed to process Reddit post", error=str(e))
                    continue

            logger.info(
                "Reddit fetch complete",
                posts_fetched=len(posts),
                indicators_found=len(indicators),
            )

            return indicators

        except praw.exceptions.PRAWException as e:
            logger.error("Reddit API error", error=str(e))
            raise RedditError(f"Reddit API error: {e}") from e
        except Exception as e:
            logger.exception("Reddit fetch error", error=str(e))
            raise RedditError(f"Failed to fetch Reddit feed: {e}") from e

    def _extract_urls(self, post) -> list[str]:
        """Extract URLs from a Reddit post.

        Args:
            post: PRAW Submission object

        Returns:
            List of URLs found in the post
        """
        urls = []

        # Check post URL (if it's a link post)
        if post.url and not post.is_self:
            urls.append(post.url)

        # Check post body (if it's a text post)
        if post.selftext:
            found_urls = self.URL_PATTERN.findall(post.selftext)
            urls.extend(found_urls)

        return list(set(urls))  # Remove duplicates

    async def search_by_keywords(
        self, keywords: list[str], limit: int = 50
    ) -> list[ThreatIndicatorData]:
        """Search Reddit for posts containing specific keywords.

        Args:
            keywords: List of keywords to search for
            limit: Maximum number of posts to fetch

        Returns:
            List of normalized threat indicators
        """
        try:
            reddit = self._get_reddit()
            subreddit = reddit.subreddit(self.SUBREDDIT)

            indicators = []

            for keyword in keywords:
                try:
                    search_results = subreddit.search(
                        keyword,
                        sort="relevance",
                        time_filter="week",
                        limit=limit,
                    )

                    for post in search_results:
                        if post.score < self.MIN_SCORE:
                            continue

                        urls = self._extract_urls(post)

                        for url in urls:
                            if "reddit.com" in url or "redd.it" in url:
                                continue

                            raw_data = {
                                "post_id": post.id,
                                "url": url,
                                "title": post.title,
                                "subreddit": str(post.subreddit),
                                "author": str(post.author) if post.author else "[deleted]",
                                "created_utc": post.created_utc,
                                "score": post.score,
                                "num_comments": post.num_comments,
                                "permalink": post.permalink,
                            }

                            indicator = self.normalizer.normalize_reddit(raw_data)
                            if indicator:
                                indicators.append(indicator)

                except Exception:
                    continue

            # Remove duplicates by URL
            seen_urls = set()
            unique_indicators = []
            for indicator in indicators:
                if indicator.url not in seen_urls:
                    seen_urls.add(indicator.url)
                    unique_indicators.append(indicator)

            logger.info(
                "Reddit keyword search complete",
                keywords=keywords,
                indicators_found=len(unique_indicators),
            )

            return unique_indicators

        except praw.exceptions.PRAWException as e:
            logger.error("Reddit search error", error=str(e))
            return []
        except Exception as e:
            logger.exception("Reddit keyword search error", error=str(e))
            return []

    def get_feed_stats(self) -> dict[str, Any]:
        """Get statistics about the feed.

        Returns:
            Dictionary with feed statistics
        """
        return {
            "source": "reddit",
            "status": "operational" if self._reddit else "not_initialized",
            "subreddit": self.SUBREDDIT,
            "last_check": self._last_request_time.isoformat() if self._last_request_time else None,
        }

    async def close(self) -> None:
        """Close Reddit client."""
        self._reddit = None
