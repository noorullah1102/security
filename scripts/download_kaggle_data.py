#!/usr/bin/env python3
"""Download phishing datasets from Kaggle.

Usage:
    python scripts/download_kaggle_data.py

Requires Kaggle API credentials:
    1. Go to https://www.kaggle.com/settings
    2. Scroll to API section and click "Create New API Token"
    3. Save kaggle.json to ~/.kaggle/kaggle.json
"""

import os
import subprocess
import sys
from pathlib import Path

# Kaggle datasets for phishing detection
DATASETS = [
    {
        "name": "taruntiwarihp/phishing-site-urls",
        "file": "phishing_site_urls.csv",
        "description": "~135K URLs labeled as good/bad",
    },
    {
        "name": "sid321axn/malicious-urls-dataset",
        "file": "malicious_urls.csv",
        "description": "~651K URLs with multiple categories",
    },
    {
        "name": "shashwatwork/phishing-detection-dataset",
        "file": "phishing_detection.csv",
        "description": "~100K URLs for phishing detection",
    },
]

DATA_DIR = Path(__file__).parent.parent / "data" / "external"


def check_kaggle_credentials() -> bool:
    """Check if Kaggle credentials are configured."""
    kaggle_json = Path.home() / ".kaggle" / "kaggle.json"
    return kaggle_json.exists()


def setup_instructions():
    """Print setup instructions."""
    print("\n" + "=" * 60)
    print("KAGGLE API SETUP REQUIRED")
    print("=" * 60)
    print("""
To download datasets, you need Kaggle API credentials:

1. Go to https://www.kaggle.com/settings
2. Scroll down to the 'API' section
3. Click 'Create New API Token'
4. This will download 'kaggle.json'
5. Move it to ~/.kaggle/kaggle.json:

   mkdir -p ~/.kaggle
   mv ~/Downloads/kaggle.json ~/.kaggle/
   chmod 600 ~/.kaggle/kaggle.json

6. Run this script again:
   python scripts/download_kaggle_data.py
""")
    print("=" * 60)


def download_dataset(dataset: dict) -> bool:
    """Download a single dataset from Kaggle."""
    print(f"\nDownloading: {dataset['name']}")
    print(f"  Description: {dataset['description']}")

    try:
        # Use kaggle CLI to download
        cmd = [
            "kaggle", "datasets", "download",
            "-d", dataset["name"],
            "-p", str(DATA_DIR),
            "--unzip",
            "--quiet"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print(f"  ✓ Downloaded successfully")
            return True
        else:
            print(f"  ✗ Failed: {result.stderr}")
            return False

    except FileNotFoundError:
        print("  ✗ Kaggle CLI not found. Install with: pip install kaggle")
        return False


def list_downloaded_files():
    """List all downloaded files."""
    print("\n" + "=" * 60)
    print("DOWNLOADED FILES")
    print("=" * 60)

    if not DATA_DIR.exists():
        print("No files downloaded yet.")
        return

    files = list(DATA_DIR.glob("*.csv"))
    if not files:
        files = list(DATA_DIR.glob("*"))

    if files:
        for f in sorted(files):
            size = f.stat().st_size / (1024 * 1024)  # MB
            print(f"  {f.name}: {size:.2f} MB")
    else:
        print("No CSV files found.")


def main():
    """Main entry point."""
    print("=" * 60)
    print("KAGGLE PHISHING DATASET DOWNLOADER")
    print("=" * 60)

    # Check credentials
    if not check_kaggle_credentials():
        setup_instructions()
        sys.exit(1)

    # Create data directory
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    print(f"\nData directory: {DATA_DIR}")
    print(f"\nDatasets to download: {len(DATASETS)}")

    # Download each dataset
    success_count = 0
    for dataset in DATASETS:
        if download_dataset(dataset):
            success_count += 1

    # Summary
    print("\n" + "=" * 60)
    print(f"DOWNLOADED {success_count}/{len(DATASETS)} DATASETS")
    print("=" * 60)

    # List files
    list_downloaded_files()

    print("\nNext step: Run training with the new data")
    print("  python -m src.ml.train_with_kaggle")


if __name__ == "__main__":
    main()
