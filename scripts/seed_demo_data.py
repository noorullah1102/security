"""Seed database with demo data for dashboard visualization."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import random
from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from src.db.models import ScanRecord


def random_url(verdict: str) -> tuple[str, str | None]:
    """Generate a random URL based on verdict type."""
    brands = ["paypal", "apple", "microsoft", "amazon", "google", "netflix", "facebook", "instagram"]

    if verdict == "phishing":
        brand = random.choice(brands)
        patterns = [
            f"https://{brand}-verify.secure-login{random.randint(1,999)}.com/account",
            f"https://{brand}1.com/secure/verify",
            f"https://login-{brand}.xyz/confirm",
            f"https://{brand}-support.ru/reset",
            f"https://secure-{brand}.tk/auth",
        ]
        return random.choice(patterns), brand

    elif verdict == "suspicious":
        return f"https://unknown-site{random.randint(1,999)}.net/page/{random.randint(1,100)}", None

    else:  # safe
        safe_domains = ["google.com", "github.com", "stackoverflow.com", "python.org", "fastapi.com"]
        return f"https://{random.choice(safe_domains)}/path/{random.randint(1,100)}", None


def generate_features(verdict: str) -> dict:
    """Generate realistic features based on verdict."""
    if verdict == "phishing":
        return {
            "url_length": random.randint(60, 120),
            "domain_age_days": random.randint(1, 30),
            "ssl_valid": random.choice([True, False]),
            "redirect_count": random.randint(2, 5),
            "has_suspicious_keywords": True,
            "typosquat_target": random.choice(["paypal", "apple", "microsoft"]),
            "subdomain_count": random.randint(2, 4),
            "has_ip_address": random.choice([True, False]),
            "path_depth": random.randint(2, 5),
            "uses_https": random.choice([True, False]),
        }
    elif verdict == "suspicious":
        return {
            "url_length": random.randint(40, 80),
            "domain_age_days": random.randint(30, 180),
            "ssl_valid": True,
            "redirect_count": random.randint(1, 2),
            "has_suspicious_keywords": random.choice([True, False]),
            "typosquat_target": None,
            "subdomain_count": random.randint(1, 2),
            "has_ip_address": False,
            "path_depth": random.randint(1, 3),
            "uses_https": True,
        }
    else:  # safe
        return {
            "url_length": random.randint(20, 50),
            "domain_age_days": random.randint(365, 3000),
            "ssl_valid": True,
            "redirect_count": 0,
            "has_suspicious_keywords": False,
            "typosquat_target": None,
            "subdomain_count": random.randint(0, 1),
            "has_ip_address": False,
            "path_depth": random.randint(1, 2),
            "uses_https": True,
        }


def generate_ai_explanation(verdict: str, url: str) -> dict:
    """Generate AI explanation based on verdict."""
    if verdict == "phishing":
        return {
            "summary": f"This URL appears to be a phishing attempt.",
            "explanation": f"The URL {url} shows multiple indicators of phishing including suspicious domain and misleading path structure.",
            "risk_factors": ["Newly registered domain", "Suspicious URL structure", "Typosquatting detected"],
            "severity": random.choice(["high", "critical"]),
            "recommended_action": "Block this URL and report to IT security team.",
        }
    elif verdict == "suspicious":
        return {
            "summary": "This URL requires further investigation.",
            "explanation": "Some characteristics of this URL are unusual and warrant caution.",
            "risk_factors": ["Unusual domain", "Limited reputation data"],
            "severity": "medium",
            "recommended_action": "Review manually before proceeding.",
        }
    else:
        return {
            "summary": "This URL appears to be safe.",
            "explanation": "No suspicious indicators detected.",
            "risk_factors": [],
            "severity": "low",
            "recommended_action": "No action required.",
        }


def seed_scans(session: Session, count: int = 100):
    """Seed scan history with realistic data."""
    print(f"Seeding {count} scan records...")

    verdicts = ["phishing"] * 35 + ["suspicious"] * 25 + ["safe"] * 40

    for i in range(count):
        verdict = random.choice(verdicts)
        url, brand = random_url(verdict)

        # Spread over last 7 days
        days_ago = random.randint(0, 6)
        hours_ago = random.randint(0, 23)
        created_at = datetime.utcnow() - timedelta(days=days_ago, hours=hours_ago)

        scan = ScanRecord(
            id=str(uuid4()),
            url=url,
            verdict=verdict,
            confidence=round(random.uniform(0.75, 0.99), 2),
            severity=generate_ai_explanation(verdict, url)["severity"],
            features=generate_features(verdict),
            ai_explanation=generate_ai_explanation(verdict, url),
            target_brand=brand,
            created_at=created_at,
        )
        session.add(scan)

    session.commit()
    print(f"✓ Created {count} scan records")


def seed_threat_indicators(session: Session, count: int = 50):
    """Seed threat indicators from feeds."""
    print(f"Seeding {count} threat indicators...")

    sources = ["phishtank", "urlhaus", "reddit"]
    threat_types = ["phishing", "malware", "credential_theft"]

    brands = ["paypal", "apple", "microsoft", "amazon", "google", "netflix", "facebook", "instagram"]

    for i in range(count):
        brand = random.choice(brands)
        source = random.choice(sources)
        threat_type = random.choice(threat_types)

        patterns = [
            f"https://{brand}-verify.xyz/login",
            f"https://secure-{brand}.tk/auth",
            f"https://{brand}1.com/confirm",
            f"https://login-{brand}.ru/account",
        ]

        indicator = ThreatIndicator(
            id=str(uuid4()),
            url=random.choice(patterns),
            source=source,
            threat_type=threat_type,
            target_brand=brand,
            first_seen=datetime.utcnow() - timedelta(days=random.randint(1, 30)),
            last_seen=datetime.utcnow() - timedelta(hours=random.randint(1, 48)),
            confidence=round(random.uniform(0.7, 0.99), 2),
            source_id=f"{source}_{random.randint(1000, 9999)}",
            extra_data={"tags": [threat_type]},
        )
        session.add(indicator)

    session.commit()
    print(f"✓ Created {count} threat indicators")


def seed_feed_status(session: Session):
    """Seed feed status records."""
    print("Seeding feed status records...")

    feeds = [
        {"source": "phishtank", "status": "healthy", "count": 1500},
        {"source": "urlhaus", "status": "healthy", "count": 2300},
        {"source": "reddit", "status": "healthy", "count": 45},
    ]

    for feed in feeds:
        status = FeedStatus(
            source=feed["source"],
            status=feed["status"],
            last_update=datetime.utcnow() - timedelta(minutes=random.randint(5, 60)),
            last_attempt=datetime.utcnow() - timedelta(minutes=random.randint(1, 30)),
            indicator_count=feed["count"],
            error_count=0,
        )
        session.add(status)

    session.commit()
    print("✓ Created feed status records")


def main():
    """Run all seed functions."""
    print("=== Seeding PhishRadar Demo Data ===\n")

    engine = create_engine("sqlite:///phishradar.db")
    with Session(engine) as session:
        # Clear existing data
        session.query(ScanRecord).delete()
        session.commit()

        # Seed new data
        seed_scans(session, count=100)

    print("\n=== Seeding Complete ===")
    print("Run 'uvicorn src.main:app --reload' and open http://localhost:8000")


if __name__ == "__main__":
    main()
