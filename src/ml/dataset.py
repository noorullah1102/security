"""Dataset preparation for ML training."""

import json
import random
import string
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal
from dataclasses import dataclass
from urllib.parse import urlparse
import tldextract


@dataclass
class URLSample:
    """A single URL sample for training."""
    url: str
    label: Literal["phishing", "legitimate"]
    source: str


class DatasetGenerator:
    """Generate synthetic training dataset."""

    # Common phishing keywords
    PHISHING_KEYWORDS = [
        "login", "verify", "account", "secure", "update", "confirm",
        "password", "signin", "authenticate", "credential", "banking",
        "alert", "warning", "suspended", "locked", "unlock",
        "verify-account", "secure-login", "account-update", "action-required",
        "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    ]

    # Suspicious TLDs
    SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".online", ".site"]

    # Legitimate domains for typosquatting
    POPULAR_DOMAINS = [
        "google", "facebook", "amazon", "apple", "microsoft",
        "paypal", "netflix", "twitter", "instagram", "linkedin",
        "bankofamerica", "chase", "wellsfargo", "citi", "yahoo",
        "outlook", "hotmail", "gmail", "office", "onedrive",
    ]

    def __init__(self, seed: int = 42):
        """Initialize generator with random seed."""
        random.seed(seed)

    def generate_phishing_url(self) -> str:
        """Generate a phishing URL sample."""
        patterns = [
            self._generate_typosquat_url,
            self._generate_suspicious_tld_url,
            self._generate_keyword_url,
            self._generate_ip_url,
            self._generate_long_url,
            self._generate_subdomain_url,
        ]

        generator = random.choice(patterns)
        return generator()

    def _generate_typosquat_url(self) -> str:
        """Generate typosquatting URL."""
        brand = random.choice(self.POPULAR_DOMAINS)
        typos = self._introduce_typos(brand)
        tld = random.choice([".com", ".net", ".org"])
        paths = ["/login", "/verify", "/account", "/secure", "/signin"]
        return f"https://{typos}{tld}{random.choice(paths)}"

    def _introduce_typos(self, word: str) -> str:
        """Introduce typos into a word."""
        if len(word) < 3:
            return word

        result = list(word)
        num_typos = random.randint(1, 2)

        for _ in range(num_typos):
            pos = random.randint(0, len(result) - 1)
            typo_type = random.choice(["substitute", "omit", "add"])

            if typo_type == "substitute":
                # Substitute with similar looking character
                substitutions = {
                    'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'],
                    'o': ['0'], 'l': ['1'], 's': ['5', '$'],
                    'g': ['q'], 'q': ['g'], 'b': ['d'], 'd': ['b'],
                }
                if result[pos].lower() in substitutions:
                    result[pos] = random.choice(substitutions[result[pos].lower()])
            elif typo_type == "omit":
                result.pop(pos)
            elif typo_type == "add":
                result.insert(pos, random.choice(string.ascii_lowercase))

        return ''.join(result)

    def _generate_suspicious_tld_url(self) -> str:
        """Generate URL with suspicious TLD."""
        words = ["secure", "login", "verify", "account", "bank", "paypal", "amazon"]
        word = random.choice(words)
        tld = random.choice(self.SUSPICIOUS_TLDS)
        return f"https://{word}-secure{tld}/login"

    def _generate_keyword_url(self) -> str:
        """Generate URL with suspicious keywords."""
        domains = ["secure", "verify", "account", "login", "bank", "safe"]
        domain = random.choice(domains)
        keyword = random.choice(self.PHISHING_KEYWORDS[:10])
        tld = random.choice([".com", ".net", ".org"])
        return f"https://{domain}-{keyword}{tld}/verify"

    def _generate_ip_url(self) -> str:
        """Generate URL with IP address."""
        ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        paths = ["/login", "/verify", "/secure", "/admin", "/signin"]
        return f"http://{ip}{random.choice(paths)}"

    def _generate_long_url(self) -> str:
        """Generate suspiciously long URL."""
        domain = random.choice(self.POPULAR_DOMAINS)
        path_segments = random.randint(5, 10)
        path = "/".join(random.choices(string.ascii_lowercase, k=path_segments))
        return f"https://{domain}-secure.com/{path}/login"

    def _generate_subdomain_url(self) -> str:
        """Generate URL with many subdomains."""
        brand = random.choice(self.POPULAR_DOMAINS)
        subdomains = ".".join(random.choices(["secure", "verify", "login", "account"], k=random.randint(3, 5)))
        return f"https://{subdomains}.{brand}-verify.com/login"

    def generate_legitimate_url(self) -> str:
        """Generate a legitimate URL sample."""
        patterns = [
            self._generate_normal_domain_url,
            self._generate_normal_path_url,
            self._generate_known_brand_url,
        ]

        generator = random.choice(patterns)
        return generator()

    def _generate_normal_domain_url(self) -> str:
        """Generate normal domain URL."""
        words = ["example", "website", "company", "store", "shop", "blog", "news", "info"]
        domain = random.choice(words) + str(random.randint(1, 999))
        tld = random.choice([".com", ".net", ".org", ".io", ".co"])
        paths = ["/", "/about", "/contact", "/products", "/services", "/blog"]
        return f"https://{domain}{tld}{random.choice(paths)}"

    def _generate_normal_path_url(self) -> str:
        """Generate URL with normal path structure."""
        domains = ["mywebsite", "oursite", "thecompany", "beststore", "coolblog"]
        domain = random.choice(domains) + str(random.randint(100, 9999))
        path_depth = random.randint(1, 3)
        path = "/".join(random.choices(string.ascii_lowercase, k=path_depth))
        return f"https://{domain}.com/{path}"

    def _generate_known_brand_url(self) -> str:
        """Generate legitimate brand URL (exact match)."""
        brand = random.choice(self.POPULAR_DOMAINS)
        tld = ".com"
        paths = ["/", "/products", "/about", "/contact", "/help", "/blog"]
        return f"https://{brand}{tld}{random.choice(paths)}"

    def generate_dataset(
        self,
        num_phishing: int = 5000,
        num_legitimate: int = 5000,
        output_dir: str = "data"
    ) -> list[URLSample]:
        """Generate balanced dataset.

        Args:
            num_phishing: Number of phishing samples
            num_legitimate: Number of legitimate samples
            output_dir: Directory to save dataset

        Returns:
            List of URLSample objects
        """
        samples = []

        # Generate phishing samples
        for _ in range(num_phishing):
            url = self.generate_phishing_url()
            samples.append(URLSample(
                url=url,
                label="phishing",
                source="synthetic"
            ))

        # Generate legitimate samples
        for _ in range(num_legitimate):
            url = self.generate_legitimate_url()
            samples.append(URLSample(
                url=url,
                label="legitimate",
                source="synthetic"
            ))

        # Shuffle
        random.shuffle(samples)

        # Save to file
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        data = [
            {"url": s.url, "label": s.label, "source": s.source}
            for s in samples
        ]

        with open(output_path / "dataset.json", "w") as f:
            json.dump(data, f, indent=2)

        return samples


if __name__ == "__main__":
    generator = DatasetGenerator(seed=42)
    samples = generator.generate_dataset(num_phishing=5000, num_legitimate=5000)
    print(f"Generated {len(samples)} samples")
    print(f"Phishing: {sum(1 for s in samples if s.label == 'phishing')}")
    print(f"Legitimate: {sum(1 for s in samples if s.label == 'legitimate')}")
