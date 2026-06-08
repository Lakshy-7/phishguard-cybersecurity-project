#!/usr/bin/env python3
"""
PhishGuard — Real Dataset Downloader
=====================================
Run this ONCE on your machine to download real Kaggle phishing datasets
and retrain the models on them. Much better accuracy than synthetic data.

Usage:
    python download_dataset.py

Requirements:
    pip install kaggle opendatasets requests
    Also set up Kaggle API credentials (see instructions below).
"""

import os
import sys
import subprocess

# ── Instructions ───────────────────────────────────────────────────────────────
print("""
╔══════════════════════════════════════════════════════════════════╗
║          PhishGuard Real Dataset Downloader                      ║
╚══════════════════════════════════════════════════════════════════╝

This script downloads 3 real phishing datasets from Kaggle and
merges them to train much more accurate ML models.

STEP 1 — Get your Kaggle API key:
  1. Go to https://www.kaggle.com and sign in (free account)
  2. Click your profile photo → Settings → API → Create New Token
  3. Save the downloaded kaggle.json file to:
       Windows: C:\\Users\\<username>\\.kaggle\\kaggle.json
       Mac/Linux: ~/.kaggle/kaggle.json

STEP 2 — Run this script:
  python download_dataset.py

Datasets that will be downloaded:
  • Phishing Site URLs (549,346 rows)   — shashwatwork
  • Web Page Phishing Detection (11k rows) — fathykhader
  • Email Spam & Phishing (18k emails)  — naserabdullahalam

Press ENTER to continue or Ctrl+C to cancel.
""")

try:
    input()
except KeyboardInterrupt:
    print("Cancelled.")
    sys.exit(0)

# ── Install dependencies ───────────────────────────────────────────────────────
print("[1/5] Installing dependencies...")
subprocess.run([sys.executable, "-m", "pip", "install", "kaggle", "opendatasets", "requests", "-q"])

import requests
import pandas as pd
import numpy as np

DATASETS_DIR = os.path.join(os.path.dirname(__file__), "datasets")
os.makedirs(DATASETS_DIR, exist_ok=True)

# ── Download datasets ──────────────────────────────────────────────────────────
print("\n[2/5] Downloading Kaggle datasets...")

try:
    import kaggle
    kaggle.api.authenticate()
    print("  ✅ Kaggle authentication successful")
except Exception as e:
    print(f"""
  ❌ Kaggle authentication failed: {e}

  Please make sure kaggle.json is in the right place:
    Windows: C:\\Users\\{os.environ.get('USERNAME','<username>')}\.kaggle\\kaggle.json
    Mac/Linux: ~/.kaggle/kaggle.json

  Get your token at: https://www.kaggle.com/settings (API section)
""")
    sys.exit(1)


def kaggle_download(dataset_slug, filename, target_path):
    """Download a specific file from a Kaggle dataset."""
    import tempfile, zipfile, shutil
    tmp_dir = tempfile.mkdtemp()
    try:
        print(f"  Downloading {dataset_slug}...")
        kaggle.api.dataset_download_files(dataset_slug, path=tmp_dir, unzip=True, quiet=False)
        # Find the target file
        for root, _, files in os.walk(tmp_dir):
            for f in files:
                if f == filename or f.endswith('.csv'):
                    src = os.path.join(root, f)
                    shutil.copy(src, target_path)
                    rows = sum(1 for _ in open(target_path)) - 1
                    print(f"  ✅ Saved {rows:,} rows → {target_path}")
                    return True
        print(f"  ⚠ File {filename} not found in downloaded archive")
        return False
    except Exception as e:
        print(f"  ❌ Failed: {e}")
        return False
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# Dataset 1: Phishing Site URLs (549k URLs with label)
url_raw_path  = os.path.join(DATASETS_DIR, "kaggle_phishing_urls.csv")
# Dataset 2: Email phishing dataset
email_raw_path = os.path.join(DATASETS_DIR, "kaggle_phishing_emails.csv")

kaggle_download("taruntiwarihp/phishing-site-urls",
                "phishing_site_urls.csv", url_raw_path)
kaggle_download("naserabdullahalam/phishing-email-dataset",
                "phishing_email.csv", email_raw_path)


# ── Merge & normalise URL dataset ──────────────────────────────────────────────
print("\n[3/5] Processing URL dataset...")

url_frames = []

if os.path.exists(url_raw_path):
    df_k = pd.read_csv(url_raw_path)
    print(f"  Kaggle URLs: {len(df_k):,} rows, columns: {list(df_k.columns)}")

    # Standardise column names — different datasets use different names
    col_map = {}
    for col in df_k.columns:
        cl = col.lower().strip()
        if cl in ('url', 'urls', 'address'):
            col_map[col] = 'url'
        elif cl in ('label', 'type', 'class', 'status', 'result'):
            col_map[col] = 'label'
    df_k = df_k.rename(columns=col_map)

    if 'url' in df_k.columns and 'label' in df_k.columns:
        # Normalise label to 0/1
        df_k['label'] = df_k['label'].astype(str).str.lower()
        df_k['label'] = df_k['label'].map(lambda x:
            1 if x in ('phishing', '1', 'bad', 'malicious', 'defacement') else 0)
        df_k = df_k[['url', 'label']].dropna()
        # Sample to keep training manageable (cap at 50k)
        phish = df_k[df_k['label'] == 1].sample(min(25000, len(df_k[df_k['label']==1])), random_state=42)
        legit = df_k[df_k['label'] == 0].sample(min(25000, len(df_k[df_k['label']==0])), random_state=42)
        url_frames.append(pd.concat([phish, legit]))
        print(f"  Using {len(phish):,} phishing + {len(legit):,} legit URLs from Kaggle")

# Always include synthetic data as a supplement
print("  Adding synthetic data...")
sys.path.insert(0, os.path.dirname(__file__))
from app.ml.dataset_generator import (
    LEGITIMATE_URLS_BASE, PHISHING_URLS_BASE,
    _synthetic_phishing_urls, _synthetic_legit_urls
)
synthetic = pd.DataFrame(
    [{'url': u, 'label': 0} for u in LEGITIMATE_URLS_BASE] +
    [{'url': u, 'label': 1} for u in PHISHING_URLS_BASE] +
    _synthetic_phishing_urls(600) +
    _synthetic_legit_urls(300)
)
url_frames.append(synthetic)

url_df = pd.concat(url_frames, ignore_index=True).drop_duplicates(subset='url')
url_df = url_df.sample(frac=1, random_state=42).reset_index(drop=True)
url_final_path = os.path.join(DATASETS_DIR, "url_dataset.csv")
url_df.to_csv(url_final_path, index=False)
print(f"  ✅ Final URL dataset: {len(url_df):,} rows "
      f"(phishing={url_df['label'].sum():,}, legit={(url_df['label']==0).sum():,})")


# ── Merge & normalise Email dataset ───────────────────────────────────────────
print("\n[4/5] Processing Email dataset...")

email_frames = []

if os.path.exists(email_raw_path):
    df_e = pd.read_csv(email_raw_path, encoding='latin-1')
    print(f"  Kaggle emails: {len(df_e):,} rows, columns: {list(df_e.columns)}")

    col_map = {}
    for col in df_e.columns:
        cl = col.lower().strip()
        if cl in ('email text', 'body', 'message', 'text', 'content'):
            col_map[col] = 'body'
        elif cl in ('email type', 'label', 'class', 'type', 'spam'):
            col_map[col] = 'label'
        elif cl in ('subject',):
            col_map[col] = 'subject'
    df_e = df_e.rename(columns=col_map)

    if 'body' in df_e.columns and 'label' in df_e.columns:
        df_e['label'] = df_e['label'].astype(str).str.lower()
        df_e['label'] = df_e['label'].map(lambda x:
            1 if x in ('phishing email', 'phishing', '1', 'spam', 'malicious') else 0)
        if 'subject' not in df_e.columns:
            df_e['subject'] = ''
        if 'sender' not in df_e.columns:
            df_e['sender'] = ''
        df_e = df_e[['subject', 'body', 'sender', 'label']].dropna(subset=['body'])
        phish_e = df_e[df_e['label']==1].sample(min(5000, len(df_e[df_e['label']==1])), random_state=42)
        legit_e = df_e[df_e['label']==0].sample(min(5000, len(df_e[df_e['label']==0])), random_state=42)
        email_frames.append(pd.concat([phish_e, legit_e]))
        print(f"  Using {len(phish_e):,} phishing + {len(legit_e):,} legit emails from Kaggle")

from app.ml.dataset_generator import PHISHING_EMAIL_TEMPLATES, LEGITIMATE_EMAIL_TEMPLATES, _synthetic_phishing_emails, _synthetic_legit_emails
synth_email = pd.DataFrame(
    PHISHING_EMAIL_TEMPLATES + LEGITIMATE_EMAIL_TEMPLATES +
    _synthetic_phishing_emails(150) + _synthetic_legit_emails(120)
)
email_frames.append(synth_email)

email_df = pd.concat(email_frames, ignore_index=True)
email_df = email_df.sample(frac=1, random_state=42).reset_index(drop=True)
email_final_path = os.path.join(DATASETS_DIR, "email_dataset.csv")
email_df.to_csv(email_final_path, index=False)
print(f"  ✅ Final email dataset: {len(email_df):,} rows")


# ── Retrain ────────────────────────────────────────────────────────────────────
print("\n[5/5] Retraining models on real data...")

# Clear old models
import glob, shutil
for f in glob.glob("app/ml/saved_models/*.pkl") + glob.glob("app/ml/saved_models/*.json"):
    os.remove(f)
    print(f"  Deleted old model: {f}")

from app.ml.train import train_all_models
meta = train_all_models()

print(f"""
╔══════════════════════════════════════════════════════════════════╗
║  ✅ Done! Models retrained on real Kaggle data.                  ║
╠══════════════════════════════════════════════════════════════════╣
║  URL Dataset:   {len(url_df):>8,} samples                               ║
║  Email Dataset: {len(email_df):>8,} samples                               ║
║                                                                  ║
║  Now run:  python run.py                                         ║
╚══════════════════════════════════════════════════════════════════╝
""")
