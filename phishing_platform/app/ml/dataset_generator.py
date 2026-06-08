"""
PhishGuard Dataset Generator — v2.0
Generates large, realistic, diverse phishing / legitimate datasets.

URL dataset:  ~1,400+ samples
Email dataset: ~300+ samples
"""

import os
import random
import pandas as pd

random.seed(42)

# ══════════════════════════════════════════════════════════════════════════════
# URL DATASETS
# ══════════════════════════════════════════════════════════════════════════════

# Hand-crafted legitimate URLs (80 unique)
LEGITIMATE_URLS_BASE = [
    # Tech / Dev
    "https://www.google.com/search?q=python+flask",
    "https://github.com/pallets/flask",
    "https://stackoverflow.com/questions/tagged/python",
    "https://docs.python.org/3/library/os.html",
    "https://pypi.org/project/flask/",
    "https://numpy.org/doc/stable/",
    "https://scikit-learn.org/stable/",
    "https://pandas.pydata.org/docs/",
    "https://flask.palletsprojects.com/en/3.0.x/",
    "https://developer.mozilla.org/en-US/docs/Web",
    "https://www.w3schools.com/python/",
    "https://realpython.com/flask-by-example-part-1/",
    "https://www.digitalocean.com/community/tutorials",
    "https://aws.amazon.com/documentation/",
    "https://cloud.google.com/docs",
    "https://portal.azure.com/#home",
    "https://www.stripe.com/docs",
    "https://api.slack.com/",
    "https://docs.github.com/en/actions",
    "https://kubernetes.io/docs/home/",
    "https://hub.docker.com/_/python",
    "https://www.postgresql.org/docs/",
    "https://redis.io/documentation",
    "https://www.elastic.co/guide/index.html",
    "https://www.nginx.com/resources/wiki/",
    # News / Media
    "https://www.bbc.com/news/technology",
    "https://www.nytimes.com/section/technology",
    "https://www.reuters.com/technology/",
    "https://techcrunch.com/",
    "https://www.theverge.com/",
    "https://arstechnica.com/",
    "https://www.wired.com/",
    "https://www.nature.com/",
    "https://www.scientificamerican.com/",
    # Shopping / Finance (real ones)
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://www.ebay.com/itm/123456789",
    "https://www.etsy.com/listing/123456",
    "https://www.paypal.com/us/home",
    "https://www.stripe.com/en-us",
    "https://www.bankofamerica.com/",
    "https://www.chase.com/personal/banking",
    "https://www.wellsfargo.com/",
    "https://www.schwab.com/",
    "https://www.fidelity.com/",
    # Social / Communication
    "https://www.linkedin.com/in/example-profile",
    "https://twitter.com/python",
    "https://www.reddit.com/r/learnpython",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.facebook.com/groups/pythonprogramming",
    "https://www.instagram.com/nasa/",
    "https://discord.com/invite/python",
    "https://t.me/pythonl",
    # Education
    "https://www.coursera.org/learn/machine-learning",
    "https://www.udemy.com/course/the-complete-python-course",
    "https://www.edx.org/learn/python",
    "https://www.khanacademy.org/computing",
    "https://www.mit.edu/research/",
    "https://www.stanford.edu/",
    "https://ocw.mit.edu/",
    # Tools / SaaS
    "https://www.notion.so/",
    "https://trello.com/b/example",
    "https://www.atlassian.com/software/jira",
    "https://www.figma.com/resources/",
    "https://www.canva.com/templates/",
    "https://zoom.us/pricing",
    "https://workspace.google.com/",
    "https://www.dropbox.com/features",
    "https://www.box.com/en-us/home",
    "https://asana.com/product",
    # Government / Health
    "https://www.irs.gov/individuals",
    "https://www.usa.gov/",
    "https://www.cdc.gov/coronavirus/",
    "https://www.nih.gov/",
    "https://www.who.int/health-topics/",
    "https://www.medicare.gov/",
    "https://www.fda.gov/",
    "https://www.sec.gov/",
    # Misc
    "https://www.wikipedia.org/wiki/Machine_learning",
    "https://medium.com/@example/python-tips",
    "https://www.ibm.com/docs/en",
    "https://www.twilio.com/docs",
]

# Hand-crafted phishing URLs (80 unique, varied attack categories)
PHISHING_URLS_BASE = [
    # Brand impersonation — PayPal
    "http://secure-paypal-verify.com/account/login",
    "http://paypal.com.account-verify.net/",
    "http://verify-paypal-account.phishing.ml/",
    "http://paypal-account-suspended.xyz/restore",
    "http://myaccount.paypal.com.update-verify.tk/",
    "http://paypal-secure-confirm.info/signin",
    # Brand impersonation — Amazon
    "http://www.amazon-security-alert.com/signin",
    "http://signin.amazon.com.malicious-domain.tk/",
    "http://secure.amazon.com-login-verify.xyz/",
    "http://amazon-update-account.ml/login",
    "http://amazon-prime-suspended.net/reactivate",
    "http://amazon-order-confirm-555.xyz/track",
    # Brand impersonation — Apple / Google / Microsoft
    "http://apple-id-verify.support-login.com/",
    "http://account-suspended-apple.com/id/verify",
    "http://apple.com.id-verify.suspicious.xyz/",
    "http://login-google-secure.tk/accounts",
    "http://account.google.com.sign-in.phish.net/",
    "http://microsoft-account-suspended.xyz/verify",
    "http://login.microsoftonline.com.phishing.tk/",
    "http://office365-password-expired.net/renew",
    "http://2fa-verify-signin.com/microsoft/auth",
    # Brand impersonation — Banking
    "http://bankofamerica.secure-login.ml/verify",
    "http://wellsfargo.com.securelogin.xyz/verify",
    "http://chase-bank-alert.com/suspended/login",
    "http://citibank-secure-verify.tk/signin",
    "http://hsbc-account-security.xyz/verify",
    "http://barclays-online-verify.net/signin",
    # Brand impersonation — Streaming / Social
    "http://netflix-update-billing.com/login",
    "http://netflix-account-problem.xyz/update",
    "http://facebook-security-check.com/login.php",
    "http://instagram-security-alert.net/verify",
    "http://twitter-account-suspended.com/login",
    "http://linkedin-account-verify.com/signin",
    # Delivery scams
    "http://fedex-delivery-confirm.net/track/login",
    "http://dhl-parcel-suspended.com/verify",
    "http://usps-delivery-failed.xyz/redeliver",
    "http://ups-package-held.ml/reschedule",
    "http://royalmail-delivery-issue.tk/track",
    "http://parcel-delivery-fee.xyz/pay",
    # Government / Tax scams
    "http://irs-tax-refund-claim.com/submit",
    "http://irs-gov-refund.ml/claim",
    "http://gov-covid-relief-payment.xyz/apply",
    "http://hmrc-tax-refund.tk/claim",
    "http://ssa-benefits-update.net/verify",
    # Prize / Lottery scams
    "http://free-iphone-winner.click/claim",
    "http://prize-winner-claim-now.tk/free",
    "http://congratulations-selected.xyz/reward",
    "http://amazon-giveaway-winner.ml/claim",
    "http://survey-reward-500.net/redeem",
    # Crypto / Financial scams
    "http://urgent-bitcoin-transfer.com/verify",
    "http://wallet-crypto-suspended.com/verify",
    "http://coinbase-verify-wallet.xyz/signin",
    "http://binance-account-suspended.ml/restore",
    "http://crypto-investment-profit.tk/withdraw",
    # IP-based / raw (highly suspicious)
    "http://192.168.1.1/admin/login.php",
    "http://203.0.113.42/account/verify",
    "http://10.0.0.1/signin.php",
    "http://198.51.100.7/paypal/login",
    # Homoglyph / typosquat
    "http://arnazon.com/signin",
    "http://paypall.com/account",
    "http://goog1e.com/accounts/signin",
    "http://rnikrosoft.com/login",
    "http://lnstagram.com/signin",
    # Excessive hyphens / keywords
    "http://your-account-has-been-compromised.ml/",
    "http://update-your-credentials-immediately.net/",
    "http://urgent-account-action-required.net/",
    "http://secure-banking-alert-verify-now.xyz/",
    "http://click-here-to-restore-your-account.tk/",
    # Cloud phishing (file share lures)
    "http://dropbox-file-shared.phish.com/view",
    "http://google-docs-shared.verify-login.ml/",
    "http://onedrive-file-share.malicious.xyz/open",
    "http://sharepoint-document-alert.net/view",
    # Miscellaneous
    "http://covid-relief-payment.gov.ml/claim",
    "http://scholarship-application-open.xyz/apply",
    "http://job-offer-work-from-home.tk/apply",
    "http://cheap-pharmacy-pills.xyz/order",
    "http://dating-site-meet-now.ml/join",
    "http://download-free-software.tk/get",
]


def _synthetic_phishing_urls(n=600):
    """Generate n synthetic phishing URLs with realistic patterns."""
    records = []
    brands  = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix',
               'facebook', 'instagram', 'twitter', 'linkedin', 'chase', 'wellsfargo',
               'bankofamerica', 'citibank', 'coinbase', 'binance', 'dropbox', 'onedrive',
               'fedex', 'dhl', 'usps', 'ups', 'irs', 'hmrc']
    bad_tlds = ['.tk', '.ml', '.xyz', '.click', '.info', '.gq', '.cf', '.ga', '.top',
                '.win', '.loan', '.online', '.site', '.pw', '.club']
    keywords = ['verify', 'secure', 'login', 'account', 'update', 'alert', 'confirm',
                'suspended', 'restore', 'validate', 'signin', 'authenticate', 'billing',
                'payment', 'support', 'service', 'access', 'unlock', 'renew', 'urgent']
    paths    = ['/signin', '/login', '/verify', '/account/confirm', '/secure/login',
                '/update', '/restore', '/validate', '/auth', '/billing/update']

    for _ in range(n):
        brand   = random.choice(brands)
        kw      = random.choice(keywords)
        tld     = random.choice(bad_tlds)
        path    = random.choice(paths)
        pattern = random.randint(0, 5)

        if pattern == 0:
            url = f"http://{brand}-{kw}-{random.randint(10,9999)}{tld}{path}"
        elif pattern == 1:
            url = f"http://www.{brand}.com.{kw}-verify{tld}{path}"
        elif pattern == 2:
            url = f"http://{kw}-{brand}-secure{tld}{path}"
        elif pattern == 3:
            url = f"http://{brand}.account-{kw}{tld}{path}"
        elif pattern == 4:
            # IP-based
            ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            url = f"http://{ip}{path}"
        else:
            # Long obfuscated URL
            hex_part = ''.join(random.choice('0123456789abcdef') for _ in range(6))
            url = f"http://{brand}-{kw}.{random.choice(['net','com','org'])}/verify/%{hex_part}/account{path}"

        records.append({'url': url, 'label': 1})
    return records


def _synthetic_legit_urls(n=300):
    """Generate n synthetic legitimate URLs."""
    records = []
    legit_domains = [
        'github.com', 'python.org', 'docs.python.org', 'flask.palletsprojects.com',
        'developer.mozilla.org', 'stackoverflow.com', 'npmjs.com', 'pypi.org',
        'docs.aws.amazon.com', 'cloud.google.com', 'docs.microsoft.com',
        'support.apple.com', 'help.netflix.com', 'en.wikipedia.org',
        'arxiv.org', 'pubmed.ncbi.nlm.nih.gov', 'www.coursera.org',
        'www.udemy.com', 'www.edx.org', 'www.khanacademy.org',
        'www.bbc.co.uk', 'www.reuters.com', 'apnews.com',
        'www.amazon.com', 'www.ebay.com', 'shop.microsoft.com',
        'store.apple.com', 'www.bestbuy.com', 'www.walmart.com',
    ]
    path_parts = ['docs', 'guide', 'reference', 'api', 'tutorial', 'help',
                  'learn', 'blog', 'news', 'article', 'products', 'about',
                  'support', 'downloads', 'community', 'forum', 'wiki']

    for _ in range(n):
        domain = random.choice(legit_domains)
        depth  = random.randint(1, 3)
        path   = '/'.join(random.sample(path_parts, depth))
        slug   = f"-{random.randint(100,9999)}" if random.random() > 0.6 else ""
        url    = f"https://{domain}/{path}{slug}"
        records.append({'url': url, 'label': 0})
    return records


def generate_url_dataset(output_path: str):
    records = []
    for url in LEGITIMATE_URLS_BASE:
        records.append({'url': url, 'label': 0})
    for url in PHISHING_URLS_BASE:
        records.append({'url': url, 'label': 1})
    records += _synthetic_phishing_urls(600)
    records += _synthetic_legit_urls(300)

    df = pd.DataFrame(records).drop_duplicates(subset='url')
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[+] URL dataset: {output_path}  ({len(df)} rows, "
          f"phishing={df['label'].sum()}, legit={len(df)-df['label'].sum()})")
    return df


# ══════════════════════════════════════════════════════════════════════════════
# EMAIL DATASETS
# ══════════════════════════════════════════════════════════════════════════════

PHISHING_EMAIL_TEMPLATES = [
    # --- Account / credential theft ---
    {
        "subject": "URGENT: Your account has been suspended",
        "body": "Dear Customer,\n\nWe detected unusual activity on your account. It has been temporarily suspended. Verify your identity immediately:\nhttp://secure-login-verify.xyz/account\n\nProvide: Full name, password, credit card number.\n\nFailure within 24 hours = permanent closure.\n\nSecurity Team",
        "sender": "security@account-secure-verify.com", "label": 1
    },
    {
        "subject": "Your PayPal account is limited",
        "body": "Hello,\n\nYour PayPal account has been limited due to unusual activity.\n\nRestore access: http://paypal-verify-account.ml/login\n\nRequired: SSN, credit card details, bank account number.\n\nAct now to avoid permanent suspension.\n\nPayPal Security",
        "sender": "no-reply@paypal-secure-verify.net", "label": 1
    },
    {
        "subject": "Your Apple ID has been disabled",
        "body": "Your Apple ID was disabled for security reasons.\n\nSign-in attempt from unknown device detected.\n\nVerify now: http://apple-id.support-verify.tk/\n\nEnter Apple ID credentials and credit card to confirm identity.\n\nAct within 12 hours or lose access permanently.\n\nApple Support",
        "sender": "appleid@apple.com.verify-support.xyz", "label": 1
    },
    {
        "subject": "Microsoft: Your password expires today",
        "body": "Microsoft Account Alert\n\nYour password expires in 24 hours. Your account will be locked unless you update it.\n\nUpdate now: http://microsoft-password-expire.net/update\n\nConfirm identity with SSN and date of birth.\n\nMicrosoft Security Team",
        "sender": "security@microsoft-account-expire.tk", "label": 1
    },
    {
        "subject": "Google Account: Immediate action required",
        "body": "We noticed suspicious activity in your Google Account.\n\nUnusual sign-in from Russia detected. Secure your account:\nhttp://google-accounts-verify.ml/secure\n\nIf you don't verify within 24 hours, your account will be permanently deleted.\n\nGoogle Security Team",
        "sender": "no-reply@google-account-secure.xyz", "label": 1
    },
    {
        "subject": "Your Netflix account will be cancelled",
        "body": "Hi,\n\nThere was a problem with your Netflix payment. Update payment info:\nhttp://netflix-billing-update.xyz/payment\n\nStreaming cancelled in 24 hours unless you update.\n\nEnter: card number, expiry, CVV.\n\nNetflix Billing",
        "sender": "billing@netflix-update-payment.com", "label": 1
    },
    {
        "subject": "Amazon: Unusual sign-in detected",
        "body": "We detected a sign-in to your Amazon account from an unrecognized device.\n\nIf this wasn't you, secure your account immediately:\nhttp://amazon-security-verify.xyz/signin\n\nProvide your full name, password and payment method.\n\nAmazon Security",
        "sender": "security@amazon-account-alert.net", "label": 1
    },
    {
        "subject": "CHASE Bank: Your account has been frozen",
        "body": "Dear Valued Customer,\n\nYour Chase bank account has been frozen due to suspicious activity.\n\nUnlock your account: http://chase-bank-verify.ml/unlock\n\nYou will need: account number, SSN, and online banking password.\n\nChase Fraud Team",
        "sender": "fraud-alert@chase-bank-verify.com", "label": 1
    },
    # --- Tax / government scams ---
    {
        "subject": "IRS Tax Refund - Claim Your $3,240 Refund",
        "body": "Dear Taxpayer,\n\nYou are eligible for a $3,240.00 tax refund.\n\nClaim: http://irs-refund-claim.com/submit\n\nProvide SSN, bank account details, tax ID.\n\nYou have 48 hours. After this, your refund will be forfeited.\n\nInternal Revenue Service",
        "sender": "refunds@irs.gov.refund-claim.ml", "label": 1
    },
    {
        "subject": "HMRC: Tax refund notification",
        "body": "Dear Taxpayer,\n\nFollowing our annual calculation you are due a tax refund of £847.20.\n\nTo receive your refund: http://hmrc-tax-refund.tk/claim\n\nYou must provide bank account details and National Insurance number.\n\nHM Revenue & Customs",
        "sender": "noreply@hmrc-online-refund.co.uk.phish.net", "label": 1
    },
    {
        "subject": "COVID-19 Relief Payment: Claim your $1,400",
        "body": "You are eligible for COVID-19 economic relief payment.\n\nClaim $1,400.00: http://covid-relief-payment.xyz/apply\n\nRequired: Name, SSN, bank routing number.\n\nDeadline: 5 days.\n\nDepartment of Treasury",
        "sender": "payments@gov-covid-relief.ml", "label": 1
    },
    # --- Delivery scams ---
    {
        "subject": "DHL: Parcel Delivery Failed - Action Required",
        "body": "DHL Express Notification\n\nWe attempted delivery but were unsuccessful.\n\nReschedule: http://dhl-delivery-failed.xyz/reschedule\n\nDelivery fee: $2.99. Pay now to receive your package.\n\nRequired: Credit card details.\n\nDHL Customer Service",
        "sender": "noreply@dhl-delivery-confirm.ml", "label": 1
    },
    {
        "subject": "USPS: Your package is on hold",
        "body": "USPS Package Notification\n\nYour package is on hold due to incorrect address.\n\nUpdate your address and pay the redelivery fee ($3.50):\nhttp://usps-delivery-hold.xyz/update\n\nPayment required within 24 hours.\n\nUSPS Delivery Team",
        "sender": "tracking@usps-package-hold.com", "label": 1
    },
    {
        "subject": "FedEx: Confirm delivery address",
        "body": "Your FedEx package could not be delivered.\n\nPlease confirm your delivery address and pay $1.99 storage fee:\nhttp://fedex-confirm-address.net/update\n\nPackage will be returned if not claimed within 48 hours.\n\nFedEx Customer Support",
        "sender": "delivery@fedex-delivery-update.ml", "label": 1
    },
    # --- Prize / lottery scams ---
    {
        "subject": "WINNER! You have been selected",
        "body": "Congratulations! You have been randomly selected as today's winner!\n\nYou have won: $10,000 Amazon Gift Card + iPhone 15 Pro!\n\nClaim: http://free-winner-claim.click/prize\n\nACT NOW - Only 2 hours remaining!\n\nSend full name, address, and phone number.\n\nPrize Department",
        "sender": "winner@prize-claim-now.xyz", "label": 1
    },
    {
        "subject": "You've won a $500 Walmart Gift Card!",
        "body": "Dear Shopper,\n\nYou were selected from our customer survey to receive a $500 Walmart Gift Card.\n\nClaim your reward: http://walmart-gift-winner.tk/claim\n\nExpires in 24 hours.\n\nWalmart Rewards Program",
        "sender": "rewards@walmart-survey-winner.xyz", "label": 1
    },
    {
        "subject": "Your survey reward is waiting",
        "body": "You completed a survey and earned a reward!\n\nYour $250 reward is ready: http://survey-reward-claim.ml/get\n\nJust provide your credit card for a small shipping fee ($1.00).\n\nRewards Team",
        "sender": "rewards@survey-prize-now.tk", "label": 1
    },
    # --- Crypto / investment scams ---
    {
        "subject": "Coinbase: Verify your wallet to avoid suspension",
        "body": "Your Coinbase account requires verification.\n\nUnusual activity detected. Verify wallet:\nhttp://coinbase-wallet-verify.xyz/secure\n\nProvide seed phrase and 2FA codes to restore access.\n\nCoinbase Security",
        "sender": "security@coinbase-account-verify.ml", "label": 1
    },
    {
        "subject": "URGENT: Your crypto withdrawal is pending",
        "body": "You have a pending withdrawal of 2.5 BTC ($89,000).\n\nVerify your identity to release funds:\nhttp://crypto-withdrawal-verify.tk/release\n\nRequired: wallet address, private key, 2FA code.\n\nCrypto Exchange Security",
        "sender": "withdrawals@crypto-secure-release.xyz", "label": 1
    },
    {
        "subject": "Investment opportunity: 300% returns guaranteed",
        "body": "Dear Investor,\n\nWe have a limited-time investment opportunity with guaranteed 300% returns.\n\nInvest now: http://guaranteed-returns-invest.xyz/join\n\nMinimum investment: $500. Returns in 7 days.\n\nInvestment Group",
        "sender": "invest@guaranteed-profit-now.ml", "label": 1
    },
    # --- Job / HR scams ---
    {
        "subject": "Job offer: Work from home $5,000/week",
        "body": "Congratulations! You've been selected for a remote work opportunity.\n\nEarn $5,000/week working from home.\n\nApply now: http://job-work-from-home-5000.xyz/apply\n\nNo experience required. Start immediately.\n\nHR Department",
        "sender": "hr@work-from-home-jobs.tk", "label": 1
    },
    {
        "subject": "Your LinkedIn application was reviewed",
        "body": "A recruiter has reviewed your application and wants to interview you.\n\nView your offer: http://linkedin-job-offer.ml/view\n\nLogin with your LinkedIn credentials to see the full offer.\n\nLinkedIn Jobs",
        "sender": "jobs@linkedin-career-notify.xyz", "label": 1
    },
    # --- Cloud / IT phishing ---
    {
        "subject": "OneDrive: Someone shared a document with you",
        "body": "A file has been shared with you.\n\nDocument: 'Q4_Financial_Report.xlsx'\n\nView document: http://onedrive-file-shared.xyz/view\n\nSign in with your Microsoft credentials to access.\n\nMicrosoft OneDrive",
        "sender": "sharing-noreply@onedrive-files.ml", "label": 1
    },
    {
        "subject": "IT Security: Password reset required",
        "body": "Dear Employee,\n\nOur IT security system has flagged your account. You must reset your password within 24 hours or lose access.\n\nReset now: http://it-security-reset.xyz/password\n\nEnter current password and choose a new one.\n\nIT Security Team",
        "sender": "itsecurity@company-it-alert.tk", "label": 1
    },
    {
        "subject": "Dropbox: Your storage is almost full",
        "body": "Your Dropbox account is 95% full.\n\nUpgrade or verify your account to keep your files:\nhttp://dropbox-verify-upgrade.ml/account\n\nSign in with your credentials to review your plan.\n\nDropbox Team",
        "sender": "noreply@dropbox-account-alert.xyz", "label": 1
    },
    # --- Romance / social engineering ---
    {
        "subject": "Someone likes you on our dating site",
        "body": "Hi! Someone viewed your profile and sent you a message!\n\nSee who: http://dating-meet-now.tk/view\n\nCreate a free account to read your messages.\n\nDating Team",
        "sender": "matches@dating-meet-online.xyz", "label": 1
    },
    {
        "subject": "You have a new secret admirer",
        "body": "Someone sent you a secret message!\n\nClick to reveal: http://secret-admirer-reveal.ml/message\n\nSign up free to see who it is.\n\nSocial App",
        "sender": "alerts@secret-admirer-app.tk", "label": 1
    },
    # --- Blackmail / sextortion ---
    {
        "subject": "I have recorded you - Pay $1,500 Bitcoin",
        "body": "I have compromising video of you. Pay $1,500 in Bitcoin within 48 hours or I will send it to all your contacts.\n\nBitcoin address: 1A2B3C4D5E6F7G8H9IXXX\n\nDo not contact police.\n\nAnonymous",
        "sender": "anonymous@protonmail-anon.xyz", "label": 1
    },
    # --- Pharmacy / health scams ---
    {
        "subject": "Buy cheap prescription pills online",
        "body": "Best prices on prescription medication — no prescription required!\n\nOrder now: http://cheap-pills-online.xyz/order\n\nFree shipping on orders over $50. Discreet packaging.\n\nOnline Pharmacy",
        "sender": "orders@cheap-pharmacy-pills.tk", "label": 1
    },
    # --- Tech support scams ---
    {
        "subject": "VIRUS DETECTED on your computer",
        "body": "URGENT: Our security scan detected 5 viruses on your computer.\n\nRemove now: http://tech-support-virus-remove.xyz/clean\n\nCall our toll-free number: 1-800-FAKE-999\n\nFree virus removal for 24 hours only.\n\nMicrosoft Tech Support",
        "sender": "alert@microsoft-techsupport-alert.ml", "label": 1
    },
]

LEGITIMATE_EMAIL_TEMPLATES = [
    {
        "subject": "Your order has been shipped",
        "body": "Hi Sarah,\n\nGreat news! Your order #ORD-2024-78234 has been shipped.\n\nOrder: Python Crash Course Book x1, USB-C Hub x1\nEstimated delivery: 3-5 business days\nTracking: UPS 1Z999AA10123456784\n\nTrack at: https://www.ups.com/track\n\nBest,\nCustomer Service",
        "sender": "orders@bookstore.com", "label": 0
    },
    {
        "subject": "Weekly team meeting - agenda",
        "body": "Hi team,\n\nReminder: weekly meeting tomorrow at 2 PM.\n\nAgenda:\n1. Sprint review (15 min)\n2. Q3 roadmap (30 min)\n3. Feature proposals (15 min)\n\nMeeting: https://meet.google.com/abc-defg-hij\n\nSee you!\nJennifer",
        "sender": "jennifer.smith@company.com", "label": 0
    },
    {
        "subject": "GitHub: Your pull request was merged",
        "body": "Hi developer,\n\nPull request #342 'Add user authentication module' has been merged into main.\n\nRepo: company/project-name\nMerged by: john.doe\n\nView: https://github.com/company/project-name/pull/342\n\nGitHub",
        "sender": "noreply@github.com", "label": 0
    },
    {
        "subject": "Your subscription renewal confirmation",
        "body": "Hi,\n\nYour annual subscription has been renewed.\n\nPlan: Professional\nAmount: $99.00/year\nNext renewal: Dec 15, 2025\nPayment: Visa ending 4242\n\nHelp center: https://help.example.com\n\nBilling Team",
        "sender": "billing@saas-service.com", "label": 0
    },
    {
        "subject": "Python Weekly Newsletter #287",
        "body": "Python Weekly — Issue #287\n\nHIGHLIGHTS:\n\n1. Python 3.12 Performance: 25% speed improvement\nhttps://docs.python.org/3.12/whatsnew/\n\n2. FastAPI 0.104 released\n3. Pydantic v2 migration guide\n\nHappy coding!\nPython Weekly",
        "sender": "newsletter@pythonweekly.com", "label": 0
    },
    {
        "subject": "Appointment confirmed - Dr. Johnson",
        "body": "Dear Patient,\n\nYour appointment is confirmed.\n\nDoctor: Dr. Sarah Johnson, MD\nDate: Friday, Dec 20\nTime: 10:30 AM\nLocation: Medical Center, Suite 204\n\nBring insurance card and photo ID.\n\nReschedule: https://patient.medicalcenter.org\n\nReception",
        "sender": "appointments@medicalcenter.org", "label": 0
    },
    {
        "subject": "Welcome to FlaskCon 2024",
        "body": "Hello Developer,\n\nWelcome to FlaskCon 2024! Registration confirmed.\n\nDate: March 15-16, 2024\nLocation: Tech Convention Center, San Francisco\nTicket: FLASK-2024-00923\n\nSchedule: https://flaskcon.io/2024/schedule\n\nSee you there!\nFlaskCon Team",
        "sender": "registration@flaskcon.io", "label": 0
    },
    {
        "subject": "Course completion: Machine Learning certificate",
        "body": "Congratulations!\n\nYou completed Introduction to Machine Learning with Python.\n\nGrade: 94/100 — Distinction\nCertificate: https://learn.platform.com/certificates/ml-python-2024\n\nSkills: Supervised Learning, Neural Networks, Feature Engineering\n\nEducation Platform",
        "sender": "certificates@learn-platform.com", "label": 0
    },
    {
        "subject": "Slack: New message from Alex",
        "body": "Hi,\n\nAlex Chen sent you a message in #general:\n\n'Hey, can you review the PR I opened for the login module? I addressed all the comments.'\n\nView in Slack: https://app.slack.com/client/T123/C456\n\nSlack",
        "sender": "notifications@slack.com", "label": 0
    },
    {
        "subject": "Your Jira task has been assigned",
        "body": "Jira Notification\n\nIssue PROJ-1234 has been assigned to you.\n\nTitle: Fix null pointer exception in auth module\nPriority: High\nDue: Nov 30, 2024\n\nView: https://company.atlassian.net/browse/PROJ-1234\n\nJira",
        "sender": "jira@atlassian.com", "label": 0
    },
    {
        "subject": "Invoice #INV-20241105 from Vercel",
        "body": "Hi,\n\nInvoice INV-20241105 is ready.\n\nPlan: Pro\nAmount: $20.00\nPeriod: Nov 1-30, 2024\n\nView invoice: https://vercel.com/account/billing\n\nVercel Billing",
        "sender": "billing@vercel.com", "label": 0
    },
    {
        "subject": "AWS: Your EC2 instance is running",
        "body": "Hi,\n\nYour EC2 instance i-0abc123def456 has started successfully.\n\nRegion: us-east-1\nInstance type: t3.micro\nPublic IP: 54.123.45.67\n\nManage: https://console.aws.amazon.com/ec2/\n\nAWS",
        "sender": "no-reply@sns.amazonaws.com", "label": 0
    },
    {
        "subject": "Zoom: Meeting starts in 15 minutes",
        "body": "Reminder: 'Q4 Planning Call' starts in 15 minutes.\n\nJoin: https://zoom.us/j/123456789?pwd=abc\nMeeting ID: 123 456 789\nPasscode: hello\n\nZoom",
        "sender": "no-reply@zoom.us", "label": 0
    },
    {
        "subject": "Stripe: New payment received",
        "body": "You received a new payment.\n\nAmount: $149.00\nCustomer: John Smith\nProduct: Annual Pro Plan\n\nView dashboard: https://dashboard.stripe.com/payments\n\nStripe",
        "sender": "no-reply@stripe.com", "label": 0
    },
    {
        "subject": "LinkedIn: 3 new connection requests",
        "body": "Hi,\n\nYou have 3 new connection requests.\n\n- Alice Johnson (Software Engineer at Google)\n- Bob Williams (Product Manager at Microsoft)\n- Carol Davis (Data Scientist at Meta)\n\nView: https://www.linkedin.com/mynetwork/\n\nLinkedIn",
        "sender": "messages-noreply@linkedin.com", "label": 0
    },
    {
        "subject": "Notion: Alex shared a page with you",
        "body": "Alex Chen shared 'Project Roadmap Q1 2025' with you.\n\nView page: https://www.notion.so/team/project-roadmap\n\nNotion",
        "sender": "notion@mail.notion.so", "label": 0
    },
    {
        "subject": "Your Figma prototype is ready",
        "body": "Hi,\n\nThe prototype for 'Mobile App Redesign' has been shared with you.\n\nView prototype: https://www.figma.com/proto/abc123\n\nFigma",
        "sender": "no_reply@figma.com", "label": 0
    },
    {
        "subject": "Airbnb: Booking confirmed",
        "body": "Your booking is confirmed!\n\nProperty: Cozy Studio in Downtown SF\nCheck-in: Dec 20, 2024\nCheck-out: Dec 23, 2024\nGuests: 2\nTotal: $387.00\n\nManage: https://www.airbnb.com/trips\n\nAirbnb",
        "sender": "automated@airbnb.com", "label": 0
    },
    {
        "subject": "Heroku: Deployment successful",
        "body": "Your app 'my-flask-app' was deployed successfully.\n\nRelease: v45\nBranch: main\nBuild time: 42s\n\nView: https://my-flask-app.herokuapp.com\nLogs: https://dashboard.heroku.com/apps/my-flask-app/logs\n\nHeroku",
        "sender": "notification@heroku.com", "label": 0
    },
    {
        "subject": "DocuSign: Please sign the document",
        "body": "Hi,\n\nYou have a document to sign.\n\nFrom: HR Department\nDocument: Employment Contract 2025\nExpires: Dec 31, 2024\n\nSign: https://www.docusign.net/signing/\n\nDo NOT share the link.\n\nDocuSign",
        "sender": "dse_NA4@docusign.net", "label": 0
    },
    {
        "subject": "Google Calendar: Reminder - Team standup",
        "body": "Reminder: 'Daily Standup' in 30 minutes.\n\nTime: 9:00 AM – 9:15 AM\nLocation: Google Meet\n\nJoin: https://meet.google.com/xyz-uvwx-rst\n\nGoogle Calendar",
        "sender": "calendar-notification@google.com", "label": 0
    },
    {
        "subject": "npm: Package published successfully",
        "body": "Hi,\n\nYour package '@myorg/utils' (v2.1.0) was published to the npm registry.\n\nView: https://www.npmjs.com/package/@myorg/utils\n\nnpm",
        "sender": "npm@npmjs.com", "label": 0
    },
    {
        "subject": "Coursera: Assignment graded",
        "body": "Hi Learner,\n\nYour Week 3 assignment has been graded.\n\nCourse: Machine Learning Specialization\nAssignment: Linear Regression Implementation\nScore: 95/100\n\nView feedback: https://www.coursera.org/learn/machine-learning\n\nCoursera",
        "sender": "no-reply@coursera.org", "label": 0
    },
    {
        "subject": "Apple: Your receipt from the App Store",
        "body": "Thank you for your purchase!\n\nDate: Nov 28, 2024\nOrder ID: MYYQP5VKWN\n\nItems:\n- Procreate (iPad App) $12.99\n\nIf you did not make this purchase, visit:\nhttps://reportaproblem.apple.com\n\nApple",
        "sender": "no_reply@email.apple.com", "label": 0
    },
    {
        "subject": "Spotify: Your playlist was liked",
        "body": "Hi,\n\n'Chill Study Beats' was liked by 5 people this week!\n\nView your playlist: https://open.spotify.com/playlist/abc123\n\nSpotify",
        "sender": "no-reply@spotify.com", "label": 0
    },
    {
        "subject": "Stack Overflow: Your answer was accepted",
        "body": "Congratulations!\n\nYour answer on 'How to handle CORS in Flask' was accepted.\n\n+15 reputation points!\n\nView: https://stackoverflow.com/a/123456\n\nStack Overflow",
        "sender": "noreply@stackoverflow.com", "label": 0
    },
    {
        "subject": "Medium: Your story is gaining traction",
        "body": "Hi,\n\nYour story 'Building a REST API with Flask' got 250 reads today!\n\nView stats: https://medium.com/me/stats\n\nKeep writing!\nMedium",
        "sender": "noreply@medium.com", "label": 0
    },
    {
        "subject": "HubSpot: Weekly report",
        "body": "Hi,\n\nHere's your HubSpot weekly summary.\n\nWebsite visits: 1,234 (+12%)\nNew contacts: 45\nEmails sent: 3,200\nOpen rate: 24.3%\n\nFull report: https://app.hubspot.com/reports\n\nHubSpot",
        "sender": "notifications@hubspot.com", "label": 0
    },
    {
        "subject": "Dropbox: Monthly storage report",
        "body": "Hi,\n\nYour monthly Dropbox storage report.\n\nUsed: 12.4 GB of 2 TB (0.6%)\nFiles synced: 3,456\nShared folders: 8\n\nManage storage: https://www.dropbox.com/account/plan\n\nDropbox",
        "sender": "no-reply@dropbox.com", "label": 0
    },
    {
        "subject": "Twilio: Usage alert — $80 spent this month",
        "body": "Hi,\n\nYour Twilio account has spent $80.00 this month.\n\nBreakdown:\n- SMS: $42.00\n- Voice: $38.00\n\nYour alert threshold is $100.00.\n\nManage: https://console.twilio.com\n\nTwilio",
        "sender": "no-reply@twilio.com", "label": 0
    },
]


def _synthetic_phishing_emails(n=150):
    """Generate synthetic phishing email variations."""
    records = []
    subjects = [
        "URGENT: Verify your {brand} account",
        "Your {brand} account has been suspended",
        "Action required: {brand} billing issue",
        "Security alert: Unusual activity on your {brand} account",
        "Your {brand} password needs to be updated immediately",
        "Final notice: {brand} account closure",
        "Congratulations! You won a {brand} gift card",
        "Important: Your {brand} subscription is expiring",
    ]
    brands = ['PayPal', 'Amazon', 'Apple', 'Google', 'Microsoft', 'Netflix',
              'Facebook', 'Bank of America', 'Chase', 'Coinbase', 'DHL', 'USPS']
    bad_domains = ['verify-now.xyz', 'secure-update.ml', 'account-alert.tk',
                   'login-verify.net', 'urgent-action.xyz', 'claim-reward.click']

    for i in range(n):
        brand = random.choice(brands)
        subj  = random.choice(subjects).format(brand=brand)
        domain = random.choice(bad_domains)
        body  = (
            f"Dear Customer,\n\nWe have detected a problem with your {brand} account. "
            f"You must verify your identity within 24 hours to avoid suspension.\n\n"
            f"Click here: http://{brand.lower().replace(' ','-')}-{domain}/verify\n\n"
            f"Provide your username, password, and credit card details.\n\n"
            f"Failure to comply will result in permanent account closure.\n\n{brand} Security Team"
        )
        sender = f"security@{brand.lower().replace(' ','-')}-{domain}"
        records.append({"subject": subj, "body": body, "sender": sender, "label": 1})
    return records


def _synthetic_legit_emails(n=120):
    """Generate synthetic legitimate email variations."""
    records = []
    services = [
        ('GitHub', 'noreply@github.com', 'Your build passed on branch {branch}', 
         'Build #{n} on {branch} passed all checks.\n\nView: https://github.com/org/repo/actions/runs/{n}'),
        ('AWS', 'no-reply@sns.amazonaws.com', 'AWS Budget alert: {pct}% used',
         'Your AWS budget "{name}" has reached {pct}%.\n\nView: https://console.aws.amazon.com/billing/'),
        ('Stripe', 'no-reply@stripe.com', 'Payment received: ${amount}',
         'You received ${amount} from {customer}.\n\nDashboard: https://dashboard.stripe.com'),
        ('Slack', 'notifications@slack.com', 'You have new messages in #{channel}',
         'You have {n} unread messages in #{channel}.\n\nOpen Slack: https://app.slack.com'),
        ('Jira', 'jira@atlassian.com', '{issue} updated by {user}',
         '{user} updated {issue}: status changed to In Review.\n\nView: https://company.atlassian.net/browse/{issue}'),
        ('Google Analytics', 'analytics-noreply@google.com', 'Weekly report for {site}',
         'Weekly report for {site}:\nSessions: {sessions}\nUsers: {users}\nBounce rate: {bounce}%\n\nView: https://analytics.google.com'),
    ]
    branches = ['main', 'develop', 'feature/auth', 'hotfix/bug-123']
    names    = ['Alice', 'Bob', 'Carol', 'Dave', 'Eve', 'Frank']
    channels = ['general', 'dev', 'backend', 'frontend', 'alerts', 'releases']
    issues   = ['PROJ-1234', 'ENG-567', 'BACK-89', 'FRONT-321']

    for i in range(n):
        svc = random.choice(services)
        name, sender_addr, subj_tmpl, body_tmpl = svc
        n_val = random.randint(1, 9999)
        branch = random.choice(branches)
        pct = random.randint(50, 95)
        amount = round(random.uniform(10, 2000), 2)
        customer = random.choice(names) + ' ' + random.choice(['Smith', 'Jones', 'Lee'])
        channel = random.choice(channels)
        user = random.choice(names)
        issue = random.choice(issues)
        subj = subj_tmpl.format(n=n_val, branch=branch, pct=pct, amount=amount,
                                customer=customer, channel=channel, user=user,
                                issue=issue, name='Monthly Budget', site='mysite.com')
        body = body_tmpl.format(n=n_val, branch=branch, pct=pct, amount=amount,
                                customer=customer, channel=channel, user=user,
                                issue=issue, name='Monthly Budget', site='mysite.com',
                                sessions=random.randint(1000,50000),
                                users=random.randint(500,30000),
                                bounce=random.randint(20,70))
        records.append({"subject": subj, "body": body, "sender": sender_addr, "label": 0})
    return records


def generate_email_dataset(output_path: str):
    records = []
    for e in PHISHING_EMAIL_TEMPLATES:
        records.append(e)
    for e in LEGITIMATE_EMAIL_TEMPLATES:
        records.append(e)
    records += _synthetic_phishing_emails(150)
    records += _synthetic_legit_emails(120)

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[+] Email dataset: {output_path}  ({len(df)} rows, "
          f"phishing={df['label'].sum()}, legit={len(df)-df['label'].sum()})")
    return df


if __name__ == '__main__':
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    base = os.path.join(os.path.dirname(__file__), '..', '..', 'datasets')
    generate_url_dataset(os.path.join(base, 'url_dataset.csv'))
    generate_email_dataset(os.path.join(base, 'email_dataset.csv'))
