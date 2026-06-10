🛡️ PhishGuard — AI-Powered Phishing Detection & Awareness Platform
PhishGuard is a full-stack, locally-runnable cybersecurity platform that uses real Kaggle datasets and machine learning to detect phishing URLs and emails. It includes a phishing simulation trainer, a domain analyzer, bulk scanning, REST API, and a settings/API key management system.

📸 What It Does
Feature	Description
URL Scanner	Paste any URL and get an instant phishing risk score using an ensemble of 3 ML models trained on 11,430 real Kaggle URLs
Email Scanner	Analyse suspicious emails using an NLP model trained on 33,000+ real emails from Enron, Nazario, CEAS-08, Ling, and phishing_email datasets
Bulk URL Scanner	Scan up to 50 URLs at once, filter results, export to CSV
Domain Analyzer	Deep heuristic analysis of any domain — TLD risk, entropy, brand impersonation, subdomain depth, keyword density
Phishing Simulation	Create safe, educational phishing awareness campaigns. Clicking tracks the user and shows an education page — no credentials are ever collected
REST API	Full JSON API with X-API-Key header authentication — call from scripts, tools, or CI pipelines
Reports & Charts	Chart.js analytics: detection trends, model breakdown, scan history
Settings	Change password, edit profile, create/revoke API keys
🤖 Machine Learning Models
URL Detection — Ensemble of 3 Models
Trained on the Kaggle Web Page Phishing Detection dataset (11,430 URLs, 87 pre-extracted features per URL), plus a supplementary raw-URL lexical model trained on 12,785 URLs:

Model	Accuracy	F1 Score	Training Data
Random Forest (200 trees)	96.0%	96.0%	Kaggle 87-feat (11,430 URLs)
Gradient Boosting (150 est.)	96.2%	96.3%	Kaggle 87-feat (11,430 URLs)
Logistic Regression	93.6%	93.6%	Kaggle 87-feat (11,430 URLs)
Raw-URL Ensemble (29 lexical features)	89.1%	89.5%	Kaggle URLs + synthetic (12,785)
Prediction uses a weighted ensemble: 60% Kaggle 87-feat model + 40% raw-URL lexical model, giving the best of both worlds — high accuracy on structural features plus strong sensitivity to URL text patterns.

Top predictive features from the Kaggle dataset:

google_index, page_rank, nb_hyperlinks, web_traffic
domain_age, ratio_extHyperlinks, phish_hints
safe_anchor, ratio_intHyperlinks, nb_www
Email Detection — NLP Pipeline
Trained on 5 real Kaggle email datasets merged together (33,868 emails total):

Dataset	Rows Used	Type
Enron Email Dataset	10,000	Ham + Spam
Nazario Phishing Dataset	1,000	Phishing only
CEAS-08 Email Corpus	10,000	Ham + Spam
Ling Spam Dataset	2,458	Ham + Phishing
phishing_email.csv	10,000	Phishing + Ham
Synthetic templates (handcrafted)	350	Phishing + Legit
Model: TF-IDF (trigrams, 10,000 features, sublinear TF) + Logistic Regression
Accuracy: 98.5% | Precision: 98.1% | Recall: 98.8% | F1: 98.5%

⚡ Quick Start (Windows + PyCharm)
Step 1 — Install Python
Download Python 3.11 from python.org/downloads
Run the installer — ✅ tick "Add Python to PATH" on the first screen
Verify: open Command Prompt → python --version → should show Python 3.11.x
Step 2 — Extract & Open in PyCharm
Extract phishguard.zip somewhere, e.g. C:\Projects\phishing_platform
Open PyCharm → File → Open → select the phishing_platform folder
Step 3 — Create Virtual Environment
File → Settings (Ctrl+Alt+S)
Project: phishing_platform → Python Interpreter
Click ⚙ gear icon → Add Interpreter → Add Local Interpreter
Select Virtualenv Environment → New
Leave the path as-is → click OK
Step 4 — Install Dependencies
Open the Terminal tab at the bottom of PyCharm and run:

pip install -r requirements.txt
This installs Flask, scikit-learn, pandas, joblib, and all other dependencies. Takes 1–3 minutes.

Step 5 — Configure Run
Click Run → Edit Configurations
Click + → Python
Set:
Name: PhishGuard
Script path: browse to run.py in the project root
Working directory: project root (auto-fills)
Click OK
Step 6 — Run
Click the ▶ Run button (or press Shift+F10).

You will see:

═══════════════════════════════════════════════════════
  PhishGuard — Phishing Detection & Awareness Platform
═══════════════════════════════════════════════════════
[+] Database initialized.
[*] Training ML models on Kaggle data (first run — ~60 seconds)...
[+] URL models trained:  RF=96.0%  GB=96.2%  LR=93.6%
[+] Email model trained: Accuracy=98.5%  F1=98.5%
[+] Server started at http://127.0.0.1:5000
The first run trains all models — this takes ~60 seconds. Subsequent runs load saved models instantly.

Step 7 — Open in Browser
Go to: http://127.0.0.1:5000

Default login credentials:

Username: admin
Password: admin123
⚠️ Change the password after first login via Settings → Change Password

🧭 Using the Platform
Scanning a URL
Click URL Scanner in the navbar
Paste any URL (e.g. http://paypal-verify-account.ml/login)
Choose a model (Random Forest is recommended)
Click Scan URL
See the risk score, prediction, feature breakdown, and specific red flags
Scanning an Email
Click Email Scanner
Paste the subject, sender address, and email body
Click Scan Email
See phishing probability, risk indicators (urgency words, credential requests, suspicious links), and brand mismatch detection
Bulk Scanning
Click Tools → Bulk URL Scanner
Paste up to 50 URLs, one per line (or click Load Sample URLs)
Click Scan All URLs
Filter results by Phishing / Legitimate, then click Export CSV to download
Domain Analyzer
Click Tools → Domain Analyzer
Enter a domain or full URL (e.g. paypal-verify.xyz)
See: TLD risk category, subdomain depth, entropy score, phishing keywords, brand impersonation detection, structural flags
Phishing Simulation
Click Simulations → + New Campaign
Choose a template (Generic / Bank / IT Support / HR / Prize)
Copy the generated simulation link and send it to a test user
When the user clicks the link, they are immediately shown an education page — no credentials are collected, ever
Track click rates and education completions on the campaign detail page
REST API
All endpoints accept X-API-Key: your_key_here in the header (generate keys in Settings → API Keys).

# Scan a single URL
curl -X POST http://127.0.0.1:5000/api/scan/url \
  -H "Content-Type: application/json" \
  -H "X-API-Key: pg_your_key_here" \
  -d '{"url": "http://suspicious-site.xyz/login", "model": "random_forest"}'

# Scan an email
curl -X POST http://127.0.0.1:5000/api/scan/email \
  -H "Content-Type: application/json" \
  -H "X-API-Key: pg_your_key_here" \
  -d '{"subject": "URGENT: Verify account", "body": "Click here...", "sender": "noreply@bank.ml"}'

# Bulk scan (up to 50 URLs)
curl -X POST http://127.0.0.1:5000/bulk/api \
  -H "Content-Type: application/json" \
  -H "X-API-Key: pg_your_key_here" \
  -d '{"urls": ["https://google.com", "http://phish.tk/login"]}'

# Platform statistics
curl http://127.0.0.1:5000/api/stats \
  -H "X-API-Key: pg_your_key_here"
Available models: random_forest | gradient_boosting | logistic_regression

🗂️ Project Structure
phishing_platform/
│
├── run.py                          ← Start here — initialises DB + trains models + starts server
├── requirements.txt
├── README.md
│
├── datasets/
│   ├── kaggle/                     ← Real Kaggle datasets (place downloaded files here)
│   │   ├── dataset_phishing.csv    ← Web page phishing (11,430 URLs, 87 features)
│   │   ├── Enron.csv               ← Enron email corpus
│   │   ├── Nazario.csv             ← Nazario phishing emails
│   │   ├── CEAS_08.csv             ← CEAS 2008 spam corpus
│   │   ├── Ling.csv                ← Ling spam dataset
│   │   └── phishing_email.csv      ← Phishing email dataset
│   ├── url_dataset.csv             ← Auto-generated synthetic URL dataset (fallback)
│   └── email_dataset.csv           ← Auto-generated synthetic email dataset (fallback)
│
├── app/
│   ├── __init__.py                 ← Flask application factory
│   │
│   ├── ml/
│   │   ├── dataset_generator.py    ← Synthetic dataset generator (fallback)
│   │   ├── url_features.py         ← 29-feature raw-URL extractor
│   │   ├── train.py                ← Model training (uses Kaggle data)
│   │   ├── predictor.py            ← Inference engine (ensemble prediction)
│   │   └── saved_models/           ← Trained .pkl + .json files (auto-created)
│   │       ├── url_model.pkl           Random Forest (Kaggle 87-feat)
│   │       ├── url_gb_model.pkl        Gradient Boosting (Kaggle 87-feat)
│   │       ├── url_lr_model.pkl        Logistic Regression (Kaggle 87-feat)
│   │       ├── url_rawstring_model.pkl Raw-URL lexical RF (ensemble partner)
│   │       ├── url_scaler.pkl          StandardScaler for LR
│   │       ├── url_feature_cols.pkl    Feature column names
│   │       ├── url_model_meta.json     URL model performance stats
│   │       └── email_model_meta.json   Email model performance stats
│   │
│   ├── models/
│   │   ├── user.py                 ← User + APIKey models
│   │   ├── scan.py                 ← URLScan + EmailScan records
│   │   ├── campaign.py             ← Campaign + CampaignClick records
│   │   └── log.py                  ← AuditLog
│   │
│   ├── routes/
│   │   ├── auth.py                 ← Login / logout / register
│   │   ├── dashboard.py            ← Main dashboard
│   │   ├── url_scanner.py          ← URL scanner page
│   │   ├── email_scanner.py        ← Email scanner page
│   │   ├── bulk_scan.py            ← Bulk URL scanner + CSV export
│   │   ├── domain_analyzer.py      ← Domain heuristic analyzer
│   │   ├── simulation.py           ← Awareness campaign manager
│   │   ├── settings.py             ← Profile / password / API keys
│   │   ├── reports.py              ← Analytics charts
│   │   └── api.py                  ← REST API (X-API-Key auth)
│   │
│   ├── templates/                  ← Jinja2 HTML templates (Bootstrap 5 dark theme)
│   └── static/css/main.css         ← Custom dark theme stylesheet
│
└── phishguard.db                   ← SQLite database (auto-created on first run)
🔧 Troubleshooting
Problem	Fix
python not recognised	Reinstall Python with "Add to PATH" ticked, then restart PyCharm
pip install fails with SSL error	Run python -m pip install --upgrade pip first
ModuleNotFoundError	Make sure the virtual environment is set as the Python interpreter in PyCharm settings
Port 5000 already in use	Edit run.py line near the bottom, change port=5000 to port=5001, then visit http://127.0.0.1:5001
Models not retraining	Delete the app/ml/saved_models/ folder contents and re-run python run.py
Microsoft Visual C++ required	Install Microsoft C++ Build Tools
UNIQUE constraint failed: users.username	The DB already has an admin user — this is harmless, the app continues normally
🔒 Security & Ethics
No real attacks are performed. The simulation module tracks clicks and immediately shows educational content — no passwords or personal data are ever collected.
Passwords are hashed with Werkzeug PBKDF2 (industry standard).
CSRF protection is enabled on all forms via Flask-WTF.
Security headers are set on all responses (X-Frame-Options, X-Content-Type, etc.).
This platform is for educational and defensive purposes only.
🛠️ Tech Stack
Layer	Technology
Backend	Python 3.11, Flask 3.0, Flask-SQLAlchemy, Flask-Login, Flask-WTF
Database	SQLite (zero-config, file-based)
ML — URL	Scikit-learn: RandomForest + GradientBoosting + LogisticRegression, 87 Kaggle features
ML — Email	Scikit-learn: TF-IDF (trigram) + LogisticRegression, trained on 33k real emails
Frontend	Bootstrap 5.3 (dark theme), Chart.js, Vanilla JS
Security	Werkzeug PBKDF2, Flask-WTF CSRF, Secure HTTP headers
📊 Dataset Sources
Dataset	Source	Rows Used
Web Page Phishing Detection	Kaggle — fathykhader / shashwatwork	11,430
Enron Email Corpus	Kaggle	10,000
Nazario Phishing Emails	Kaggle	1,000
CEAS-08 Spam Corpus	Kaggle	10,000
Ling Spam Dataset	Kaggle	2,458
Phishing Email Dataset	Kaggle	10,000
👨‍💻 Project Information
Project Title: PhishGuard – AI-Powered Phishing Detection & Awareness Platform

Submitted By: Lakshya Choudhary

Course: B.Tech CSE (Cyber Security)

Academic Project: Cyber Security

Built with Python, Flask, and scikit-learn. For educational use only.
