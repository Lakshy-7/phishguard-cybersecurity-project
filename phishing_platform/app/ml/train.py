"""
PhishGuard ML Training — v3.0  (Kaggle Real Data Edition)
==========================================================

URL Detection
  Source  : datasets/kaggle/dataset_phishing.csv  (11,430 rows, 87 pre-extracted features)
  Fallback: synthetic generator (used if Kaggle file missing)
  Models  : Random Forest  |  Gradient Boosting  |  Logistic Regression

Email Detection
  Sources : datasets/kaggle/Enron.csv      (720k rows — ham/spam)
            datasets/kaggle/Nazario.csv    (2.7k  rows — phishing only)
            datasets/kaggle/CEAS_08.csv    (1.3M  rows — spam/phishing)
            datasets/kaggle/Ling.csv       (5.4k  rows — phishing/ham)
            datasets/kaggle/phishing_email.csv (82k rows)
  Fallback: synthetic generator
  Model   : TF-IDF (trigrams, 10 000 features) + Logistic Regression pipeline
"""

import os, sys, json, warnings
warnings.filterwarnings('ignore')

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble          import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model      import LogisticRegression
from sklearn.pipeline          import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection   import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics           import (accuracy_score, precision_score,
                                       recall_score, f1_score, classification_report)
from sklearn.preprocessing     import StandardScaler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

BASE_DIR    = os.path.join(os.path.dirname(__file__), '..', '..')
KAGGLE_DIR  = os.path.join(BASE_DIR, 'datasets', 'kaggle')
DATASET_DIR = os.path.join(BASE_DIR, 'datasets')
MODELS_DIR  = os.path.join(os.path.dirname(__file__), 'saved_models')
os.makedirs(MODELS_DIR,  exist_ok=True)
os.makedirs(DATASET_DIR, exist_ok=True)

# ══════════════════════════════════════════════════════════════════════════════
# URL MODEL  — uses Kaggle 87-feature dataset
# ══════════════════════════════════════════════════════════════════════════════

# The Kaggle dataset already has 87 hand-crafted features per URL.
# We use ALL of them for the Kaggle-trained models, giving much higher accuracy
# than our 29-feature extractor on raw URL strings.
# We ALSO keep the raw-URL models for the URL scanner (which takes a new URL
# the user types in — we can't run page-level features on it live).

KAGGLE_URL_FEATURES = [
    'length_url','length_hostname','ip','nb_dots','nb_hyphens','nb_at','nb_qm',
    'nb_and','nb_or','nb_eq','nb_underscore','nb_tilde','nb_percent','nb_slash',
    'nb_star','nb_colon','nb_comma','nb_semicolumn','nb_dollar','nb_space',
    'nb_www','nb_com','nb_dslash','http_in_path','https_token','ratio_digits_url',
    'ratio_digits_host','punycode','port','tld_in_path','tld_in_subdomain',
    'abnormal_subdomain','nb_subdomains','prefix_suffix','random_domain',
    'shortening_service','path_extension','nb_redirection','nb_external_redirection',
    'length_words_raw','char_repeat','shortest_words_raw','shortest_word_host',
    'shortest_word_path','longest_words_raw','longest_word_host','longest_word_path',
    'avg_words_raw','avg_word_host','avg_word_path','phish_hints','domain_in_brand',
    'brand_in_subdomain','brand_in_path','suspecious_tld','statistical_report',
    'nb_hyperlinks','ratio_intHyperlinks','ratio_extHyperlinks','ratio_nullHyperlinks',
    'nb_extCSS','ratio_intRedirection','ratio_extRedirection','ratio_intErrors',
    'ratio_extErrors','login_form','external_favicon','links_in_tags','submit_email',
    'ratio_intMedia','ratio_extMedia','sfh','iframe','popup_window','safe_anchor',
    'onmouseover','right_clic','empty_title','domain_in_title','domain_with_copyright',
    'whois_registered_domain','domain_registration_length','domain_age',
    'web_traffic','dns_record','google_index','page_rank',
]


def _load_kaggle_url_dataset():
    path = os.path.join(KAGGLE_DIR, 'dataset_phishing.csv')
    if not os.path.exists(path):
        return None, None
    print(f"    Loading: {path}")
    df = pd.read_csv(path)
    df['label'] = (df['status'] == 'phishing').astype(int)
    # Use only columns that exist
    feat_cols = [c for c in KAGGLE_URL_FEATURES if c in df.columns]
    X = df[feat_cols].fillna(0).values
    y = df['label'].values
    print(f"    Kaggle URL dataset: {len(df):,} rows | {len(feat_cols)} features")
    print(f"    Phishing={y.sum():,}  Legitimate={(y==0).sum():,}")
    return X, y, feat_cols


def _load_synthetic_url_dataset():
    """Fallback: generate synthetic URL data + extract our 29 features."""
    from app.ml.dataset_generator import generate_url_dataset
    from app.ml.url_features import extract_url_features, features_to_vector
    csv_path = os.path.join(DATASET_DIR, 'url_dataset.csv')
    if not os.path.exists(csv_path):
        generate_url_dataset(csv_path)
    df = pd.read_csv(csv_path)
    X_raw, y = [], []
    for _, row in df.iterrows():
        try:
            feats = extract_url_features(str(row['url']))
            X_raw.append(features_to_vector(feats))
            y.append(int(row['label']))
        except Exception:
            continue
    return np.array(X_raw), np.array(y)


def train_url_model():
    print("\n" + "─"*55)
    print("  Training URL Phishing Detection Models (Kaggle data)")
    print("─"*55)

    result = _load_kaggle_url_dataset()

    if result[0] is not None:
        X, y, feat_cols = result
        dataset_source = 'Kaggle (dataset_phishing.csv — 87 features)'
        dataset_size   = len(y)
    else:
        print("    ⚠ Kaggle dataset not found — using synthetic data")
        from app.ml.url_features import FEATURE_NAMES
        feat_cols = FEATURE_NAMES
        X, y = _load_synthetic_url_dataset()
        dataset_source = 'Synthetic (generated)'
        dataset_size   = len(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # ── Random Forest ──────────────────────────────────────────────
    print("\n    [1/3] Training Random Forest (200 trees)...")
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=None, min_samples_split=2,
        min_samples_leaf=1, n_jobs=-1, random_state=42
    )
    rf.fit(X_train, y_train)
    rf_pred  = rf.predict(X_test)
    rf_acc   = accuracy_score(y_test, rf_pred)
    rf_f1    = f1_score(y_test, rf_pred)
    rf_prec  = precision_score(y_test, rf_pred)
    rf_rec   = recall_score(y_test, rf_pred)
    print(f"    Accuracy={rf_acc:.4f}  Precision={rf_prec:.4f}  Recall={rf_rec:.4f}  F1={rf_f1:.4f}")

    # ── Gradient Boosting ──────────────────────────────────────────
    print("\n    [2/3] Training Gradient Boosting (150 estimators)...")
    gb = GradientBoostingClassifier(
        n_estimators=150, max_depth=5, learning_rate=0.1,
        subsample=0.8, random_state=42
    )
    gb.fit(X_train, y_train)
    gb_pred  = gb.predict(X_test)
    gb_acc   = accuracy_score(y_test, gb_pred)
    gb_f1    = f1_score(y_test, gb_pred)
    gb_prec  = precision_score(y_test, gb_pred)
    gb_rec   = recall_score(y_test, gb_pred)
    print(f"    Accuracy={gb_acc:.4f}  Precision={gb_prec:.4f}  Recall={gb_rec:.4f}  F1={gb_f1:.4f}")

    # ── Logistic Regression ────────────────────────────────────────
    print("\n    [3/3] Training Logistic Regression...")
    scaler   = StandardScaler()
    lr       = LogisticRegression(max_iter=1000, C=1.0, random_state=42, n_jobs=-1)
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)
    lr.fit(X_train_s, y_train)
    lr_pred  = lr.predict(X_test_s)
    lr_acc   = accuracy_score(y_test, lr_pred)
    lr_f1    = f1_score(y_test, lr_pred)
    lr_prec  = precision_score(y_test, lr_pred)
    lr_rec   = recall_score(y_test, lr_pred)
    print(f"    Accuracy={lr_acc:.4f}  Precision={lr_prec:.4f}  Recall={lr_rec:.4f}  F1={lr_f1:.4f}")

    # ── Classification report (RF) ─────────────────────────────────
    print("\n    Classification Report (Random Forest — best model):")
    print(classification_report(y_test, rf_pred,
                                target_names=['Legitimate', 'Phishing'],
                                digits=4))

    # ── Top feature importances ────────────────────────────────────
    importances = dict(zip(feat_cols, rf.feature_importances_))
    top10 = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:10]
    print("    Top 10 predictive features (Random Forest):")
    for feat, imp in top10:
        bar = '█' * int(imp * 200)
        print(f"      {feat:<32} {imp:.4f}  {bar}")

    # ── Save ───────────────────────────────────────────────────────
    joblib.dump(rf,     os.path.join(MODELS_DIR, 'url_model.pkl'))
    joblib.dump(gb,     os.path.join(MODELS_DIR, 'url_gb_model.pkl'))
    joblib.dump(scaler, os.path.join(MODELS_DIR, 'url_scaler.pkl'))
    joblib.dump(lr,     os.path.join(MODELS_DIR, 'url_lr_model.pkl'))
    # Save feature column names so predictor uses the right features
    joblib.dump(feat_cols, os.path.join(MODELS_DIR, 'url_feature_cols.pkl'))

    meta = {
        'dataset_source':   dataset_source,
        'dataset_size':     dataset_size,
        'n_features':       len(feat_cols),
        'feature_names':    feat_cols,
        'training_samples': len(X_train),
        'test_samples':     len(X_test),
        'model_type':       'RandomForest + GradientBoosting + LogisticRegression',
        # Per-model stats
        'rf_accuracy':  round(rf_acc,  4), 'rf_f1':  round(rf_f1,  4),
        'rf_precision': round(rf_prec, 4), 'rf_recall': round(rf_rec, 4),
        'gb_accuracy':  round(gb_acc,  4), 'gb_f1':  round(gb_f1,  4),
        'gb_precision': round(gb_prec, 4), 'gb_recall': round(gb_rec, 4),
        'lr_accuracy':  round(lr_acc,  4), 'lr_f1':  round(lr_f1,  4),
        'lr_precision': round(lr_prec, 4), 'lr_recall': round(lr_rec, 4),
        # Legacy keys kept for dashboard compatibility
        'accuracy':     round(rf_acc,  4),
        'f1_score':     round(rf_f1,   4),
        'lr_f1_score':  round(lr_f1,   4),
    }
    with open(os.path.join(MODELS_DIR, 'url_model_meta.json'), 'w') as f:
        json.dump(meta, f, indent=2)

    print(f"\n    ✅ URL models saved → {MODELS_DIR}")
    return meta


# ══════════════════════════════════════════════════════════════════════════════
# EMAIL MODEL  — uses Kaggle multi-source dataset
# ══════════════════════════════════════════════════════════════════════════════

def _load_kaggle_email_datasets():
    """
    Load and merge multiple Kaggle email datasets into a single DataFrame.
    Returns DataFrame with columns: subject, body, sender, label (0/1)
    """
    frames = []

    def _try_load(path, label_col, text_col, subject_col=None, sender_col=None,
                  label_map=None, sample=None):
        if not os.path.exists(path):
            return
        name = os.path.basename(path)
        print(f"    Loading {name}...")
        try:
            df = pd.read_csv(path, encoding='latin-1', on_bad_lines='skip',
                             low_memory=False)
            # Rename columns
            df = df.rename(columns={
                label_col:   'label',
                text_col:    'body',
            })
            if subject_col and subject_col in df.columns:
                df = df.rename(columns={subject_col: 'subject'})
            else:
                df['subject'] = ''
            if sender_col and sender_col in df.columns:
                df = df.rename(columns={sender_col: 'sender'})
            else:
                df['sender'] = ''
            # Map labels to 0/1
            if label_map:
                df['label'] = df['label'].map(label_map)
            else:
                df['label'] = pd.to_numeric(df['label'], errors='coerce')
            df = df.dropna(subset=['label', 'body'])
            df['label'] = df['label'].astype(int)
            df = df[['subject', 'body', 'sender', 'label']]
            if sample:
                phish = df[df['label']==1]
                legit = df[df['label']==0]
                ph_n  = min(len(phish), sample//2)
                le_n  = min(len(legit), sample//2)
                df    = pd.concat([
                    phish.sample(ph_n, random_state=42),
                    legit.sample(le_n, random_state=42)
                ])
            phish_n = (df['label']==1).sum()
            legit_n = (df['label']==0).sum()
            print(f"      → {len(df):,} rows  (phishing={phish_n:,}, legit={legit_n:,})")
            frames.append(df)
        except Exception as e:
            print(f"      ⚠ Could not load {name}: {e}")

    # Enron — label 1=spam/phishing, 0=ham
    _try_load(os.path.join(KAGGLE_DIR, 'Enron.csv'),
              label_col='label', text_col='body', subject_col='subject',
              sample=20000)

    # Nazario — all phishing (label=1)
    _try_load(os.path.join(KAGGLE_DIR, 'Nazario.csv'),
              label_col='label', text_col='body', subject_col='subject',
              sender_col='sender', sample=2000)

    # CEAS_08 — label 1=spam, 0=ham
    _try_load(os.path.join(KAGGLE_DIR, 'CEAS_08.csv'),
              label_col='label', text_col='body', subject_col='subject',
              sender_col='sender', sample=20000)

    # Ling — label 1=phishing, 0=legit
    _try_load(os.path.join(KAGGLE_DIR, 'Ling.csv'),
              label_col='label', text_col='body', subject_col='subject',
              sample=5000)

    # phishing_email.csv — text_combined + label
    path = os.path.join(KAGGLE_DIR, 'phishing_email.csv')
    if os.path.exists(path):
        print(f"    Loading phishing_email.csv...")
        df = pd.read_csv(path, encoding='latin-1', on_bad_lines='skip')
        df = df.rename(columns={'text_combined': 'body'})
        df['subject'] = ''
        df['sender']  = ''
        df = df.dropna(subset=['label','body'])
        df['label'] = pd.to_numeric(df['label'], errors='coerce').dropna().astype(int)
        df = df[['subject','body','sender','label']]
        phish = df[df['label']==1].sample(min(10000, (df['label']==1).sum()), random_state=42)
        legit = df[df['label']==0].sample(min(10000, (df['label']==0).sum()), random_state=42)
        df = pd.concat([phish, legit])
        print(f"      → {len(df):,} rows  (phishing={(df['label']==1).sum():,}, legit={(df['label']==0).sum():,})")
        frames.append(df)

    if not frames:
        return None
    combined = pd.concat(frames, ignore_index=True)
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    return combined


def train_email_model():
    print("\n" + "─"*55)
    print("  Training Email Phishing Detection Model (Kaggle data)")
    print("─"*55)

    # Try Kaggle first
    df = _load_kaggle_email_datasets()
    dataset_source = 'Kaggle (Enron + Nazario + CEAS_08 + Ling + phishing_email)'

    if df is None or len(df) < 100:
        print("    ⚠ Kaggle email data not found — using synthetic data")
        from app.ml.dataset_generator import generate_email_dataset
        csv_path = os.path.join(DATASET_DIR, 'email_dataset.csv')
        if not os.path.exists(csv_path):
            generate_email_dataset(csv_path)
        df = pd.read_csv(csv_path)
        dataset_source = 'Synthetic (generated)'

    # Always append hand-crafted templates for diversity
    from app.ml.dataset_generator import (PHISHING_EMAIL_TEMPLATES,
                                          LEGITIMATE_EMAIL_TEMPLATES,
                                          _synthetic_phishing_emails,
                                          _synthetic_legit_emails)
    synth = pd.DataFrame(
        PHISHING_EMAIL_TEMPLATES + LEGITIMATE_EMAIL_TEMPLATES +
        _synthetic_phishing_emails(200) + _synthetic_legit_emails(150)
    )
    df = pd.concat([df, synth], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\n    Total email dataset: {len(df):,} rows")
    print(f"    Phishing={(df['label']==1).sum():,}  Legitimate={(df['label']==0).sum():,}")

    # Build text feature: subject + sender + body
    df['text'] = (
        df['subject'].fillna('').astype(str) + ' ' +
        df['sender'].fillna('').astype(str)  + ' ' +
        df['body'].fillna('').astype(str)
    )

    X = df['text'].values
    y = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # NLTK stopwords
    try:
        import nltk
        nltk.download('stopwords', quiet=True)
        from nltk.corpus import stopwords
        stop_words = list(stopwords.words('english'))
    except Exception:
        stop_words = 'english'

    print("\n    Training TF-IDF (trigrams, 10k features) + Logistic Regression...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            max_features=10000,
            ngram_range=(1, 3),
            stop_words=stop_words,
            sublinear_tf=True,
            min_df=2,
            analyzer='word',
        )),
        ('clf', LogisticRegression(
            max_iter=1000, C=2.0, solver='lbfgs',
            random_state=42, n_jobs=-1
        ))
    ])

    pipeline.fit(X_train, y_train)
    pred   = pipeline.predict(X_test)
    acc    = accuracy_score(y_test, pred)
    f1     = f1_score(y_test, pred)
    prec   = precision_score(y_test, pred)
    rec    = recall_score(y_test, pred)

    # 5-fold cross-validation
    print("    Running 5-fold cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipeline, X, y, cv=cv, scoring='f1', n_jobs=-1)

    print(f"\n    Accuracy ={acc:.4f}  Precision={prec:.4f}  Recall={rec:.4f}  F1={f1:.4f}")
    print(f"    CV F1    ={cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print("\n    Classification Report:")
    print(classification_report(y_test, pred,
                                target_names=['Legitimate', 'Phishing'], digits=4))

    joblib.dump(pipeline, os.path.join(MODELS_DIR, 'email_model.pkl'))

    meta = {
        'dataset_source':   dataset_source,
        'dataset_size':     len(df),
        'model_type':       'TF-IDF (trigram, 10k) + LogisticRegression',
        'accuracy':         round(acc,  4),
        'precision':        round(prec, 4),
        'recall':           round(rec,  4),
        'f1_score':         round(f1,   4),
        'cv_f1_mean':       round(float(cv_scores.mean()), 4),
        'cv_f1_std':        round(float(cv_scores.std()),  4),
        'training_samples': len(X_train),
        'test_samples':     len(X_test),
    }
    with open(os.path.join(MODELS_DIR, 'email_model_meta.json'), 'w') as f:
        json.dump(meta, f, indent=2)

    print(f"    ✅ Email model saved → {MODELS_DIR}")
    return meta


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def train_all_models():
    print("\n" + "═"*55)
    print("  PhishGuard — ML Training v3.0  (Kaggle Real Data)")
    print("═"*55)
    url_meta   = train_url_model()
    email_meta = train_email_model()
    print("\n" + "═"*55)
    print("  ✅ All models trained and saved successfully!")
    print("═"*55)
    return {'url': url_meta, 'email': email_meta}


if __name__ == '__main__':
    train_all_models()
