"""
Checkify backend — real-time fraud/impersonation analysis for arbitrary text and links.

Every score in this file is computed live from the actual input: WHOIS is a real
socket query to the registry, SSL info is a real TLS handshake, Telegram/Instagram
data is a real HTTP fetch of the public page, and text scoring is a real regex/lexicon
pass over whatever string is submitted. Nothing here is looked up from a table of
pre-written cases.

Run:  python server.py
Open: http://localhost:5000
"""

import base64
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import httpx
import numpy as np
import requests
import urllib3
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.x509.oid import NameOID
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory
from groq import Groq
from PIL import Image, ImageChops, ImageDraw
from rapidfuzz import fuzz

load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

OCR_AVAILABLE = False
OCR_UNAVAILABLE_REASON = None
try:
    import pytesseract
    for _candidate in (
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    ):
        if os.path.isfile(_candidate):
            pytesseract.pytesseract.tesseract_cmd = _candidate
            break
    pytesseract.get_tesseract_version()
    OCR_AVAILABLE = True
except ImportError:
    pytesseract = None
    OCR_UNAVAILABLE_REASON = "pytesseract is not installed (pip install pytesseract)."
except Exception as e:
    OCR_UNAVAILABLE_REASON = f"Tesseract OCR engine not found or not runnable: {e}"

# We deliberately retry with verify=False when strict TLS verification fails (see
# check_ssl/fetch_page) so a link can still be analyzed on networks with TLS-inspecting
# proxies/antivirus — the resulting warning on every such request is expected, not a bug.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "").strip()
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
GROQ_AVAILABLE = False
GROQ_UNAVAILABLE_REASON = None
groq_client = None
if not GROQ_API_KEY:
    GROQ_UNAVAILABLE_REASON = "No GROQ_API_KEY configured — set it in checkify/.env to enable AI-assisted analysis."
else:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY, timeout=12.0)
        groq_client.models.list()
        GROQ_AVAILABLE = True
    except Exception:
        # Same TLS-inspecting-proxy/antivirus situation handled elsewhere in this file
        # (see check_ssl) can also break the Groq SDK's own verified HTTPS connection.
        try:
            groq_client = Groq(api_key=GROQ_API_KEY, timeout=12.0, http_client=httpx.Client(verify=False, timeout=12.0))
            groq_client.models.list()
            GROQ_AVAILABLE = True
        except Exception as e2:
            groq_client = None
            GROQ_UNAVAILABLE_REASON = f"Could not reach Groq API: {e2}"

app = Flask(__name__, static_folder="static", static_url_path="")

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": UA, "Accept-Language": "en-IN,en;q=0.9"})

HISTORY = []  # in-memory session history: list of analysis result dicts

# --------------------------------------------------------------------------- reference data

SHORTENERS = {
    "bit.ly", "tinyurl.com", "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at",
    "tiny.cc", "rb.gy", "t.co", "ow.ly", "buff.ly", "lnkd.in", "s.id", "bl.ink",
}
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "support",
    "loan", "win", "review", "country", "kim", "gdn", "mom", "icu", "cam",
}
OFFICIAL_FINANCE_DOMAINS = {
    "sebi.gov.in", "nseindia.com", "bseindia.com", "rbi.org.in", "incometax.gov.in",
}
BRAND_KEYWORDS = ["sebi", "nse", "bse", "rbi"]
CONFUSABLE_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})


def normalize_confusables(s):
    return s.translate(CONFUSABLE_MAP)


def decode_punycode_labels(host):
    """Decodes any xn-- (punycode/IDN) labels back to Unicode. Real phishing domains use
    this to render as visually-identical lookalikes of ASCII brand names using Cyrillic/
    Greek/other confusable characters — e.g. xn--80ak6aa92e.com decodes to a Cyrillic
    string that renders identically to 'apple'. A finance/SEBI-related link should never
    legitimately need an internationalized domain, so any hit here is a strong signal."""
    decoded_labels = []
    any_idn = False
    for label in host.split("."):
        if label.startswith("xn--"):
            any_idn = True
            try:
                decoded_labels.append(label.encode("ascii").decode("idna"))
            except Exception:
                decoded_labels.append(label)
        else:
            decoded_labels.append(label)
    return any_idn, ".".join(decoded_labels)

INDIAN_STOCKS = [
    "TCS", "INFOSYS", "INFY", "RELIANCE", "HDFC", "HDFCBANK", "ICICI", "ICICIBANK",
    "SBI", "SBIN", "ADANI", "ADANIENT", "ADANIPORTS", "TATAMOTORS", "TATASTEEL",
    "TATAPOWER", "WIPRO", "ITC", "HUL", "HINDUNILVR", "BAJAJFINANCE", "BAJFINANCE",
    "MARUTI", "ONGC", "NTPC", "ZOMATO", "PAYTM", "NYKAA", "LT", "KOTAKBANK",
    "AXISBANK", "YESBANK", "IRCTC", "DMART", "ASIANPAINT", "SUNPHARMA", "DRREDDY",
    "CIPLA", "COALINDIA", "POWERGRID", "GAIL", "BPCL", "IOC", "HINDALCO",
    "JSWSTEEL", "GRASIM", "ULTRACEMCO", "NESTLEIND", "BRITANNIA", "TITAN",
    "BHARTIARTL", "INDUSINDBK", "EICHERMOT", "HEROMOTOCO", "PNB", "BANKBARODA",
    "CANBK", "IDFCFIRSTB", "SUZLON", "IRFC", "RVNL", "VODAFONE", "IDEA",
]

SEBI_PREFIXES = {
    "INH": "Research Analyst", "INA": "Investment Adviser", "INZ": "Stock Broker",
    "INP": "Portfolio Manager", "INM": "Merchant Banker",
}

# ILLUSTRATIVE ONLY — a small seed list to demonstrate fuzzy name-matching against a
# registry. This is NOT SEBI's real intermediary database. Swap in the real dataset
# (SEBI publishes a monthly PDF/Excel of registered intermediaries) before relying on
# this for anything beyond a demo.
ILLUSTRATIVE_ADVISOR_REGISTRY = [
    {"name": "Rakesh Sharma", "reg": "INH000012345", "category": "Research Analyst"},
    {"name": "Priya Menon", "reg": "INA000054321", "category": "Investment Adviser"},
    {"name": "Arjun Verma", "reg": "INZ000067890", "category": "Stock Broker"},
    {"name": "Deepa Krishnan", "reg": "INH000008841", "category": "Research Analyst"},
    {"name": "Sanjay Iyer", "reg": "INA000031122", "category": "Investment Adviser"},
]
NAME_CANDIDATE_PATTERNS = [
    re.compile(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b(?=[,\s]*(?:is\s+)?(?:a\s+)?SEBI[- ]?(?:registered|approved|certified))"),
    re.compile(r"SEBI[- ]?(?:registered|approved|certified)\s+(?:research\s+)?(?:analyst|adviser|advisor)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})"),
    re.compile(r"\bI\s?(?:a|')m\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b"),
    re.compile(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\s+(?:is\s+(?:a\s+)?)?(?:certified|registered|approved)?\s*(?:research\s+)?(?:analyst|adviser|advisor)\b"),
]


def match_advisor_name(text):
    """Best-effort name extraction + fuzzy match against the illustrative registry.
    Real name extraction without a full NER model is inherently imperfect — treat this
    as a demo of the matching mechanism, not a production-grade name parser."""
    candidate = None
    for pat in NAME_CANDIDATE_PATTERNS:
        m = pat.search(text)
        if m:
            candidate = m.group(1).strip()
            break
    if not candidate:
        return None

    best = None
    for advisor in ILLUSTRATIVE_ADVISOR_REGISTRY:
        similarity = fuzz.token_sort_ratio(candidate.lower(), advisor["name"].lower())
        if best is None or similarity > best["similarity"]:
            best = {"similarity": similarity, **advisor}

    if best and best["similarity"] >= 90:
        return {"claimedName": candidate, "matchType": "exact", "similarity": best["similarity"],
                "matchedRecord": {"name": best["name"], "reg": best["reg"], "category": best["category"]},
                "note": f"'{candidate}' matches registered {best['category']} {best['name']} ({best['reg']}) in the illustrative registry."}
    if best and best["similarity"] >= 70:
        return {"claimedName": candidate, "matchType": "fuzzy", "similarity": best["similarity"],
                "matchedRecord": {"name": best["name"], "reg": best["reg"], "category": best["category"]},
                "note": (f"'{candidate}' is suspiciously similar ({best['similarity']:.0f}% match) to registered advisor "
                         f"'{best['name']}' but not an exact match — a classic impersonation pattern (altered spelling, "
                         "swapped initials) used to borrow a real advisor's credibility.")}
    return {"claimedName": candidate, "matchType": "none", "similarity": round(best["similarity"], 0) if best else 0,
            "matchedRecord": None,
            "note": f"'{candidate}' does not match any name in the illustrative registry — this checks against a demo "
                    "dataset of 5 names, not SEBI's real ~1,300-entry registry, so absence of a match here is not proof "
                    "of anything on its own."}

CONTENT_PATTERNS = [
    ("guaranteed_return", 22, [
        r"\bguarantee[ds]?\b", r"\bguaranteed\b", r"\b100\s?%\s*(safe|sure|guaranteed)\b", r"\brisk[- ]?free\b",
        r"\bno\s+loss\b", r"\bno\s+risk\b", r"\bsure[- ]?shot\b", r"\bfixed\s+returns?\b", r"\bcertain\s+profit\b",
        r"\bassured\s+returns?\b", r"\bconfirmed\s+profit\b", r"\bzero\s+risk\b",
    ]),
    ("urgency", 12, [
        r"\bact\s+(now|fast|immediately|quickly|today)\b", r"\btoday\s+only\b", r"\blimited\s+(time|slots?|seats?|period|offer)\b",
        r"\bhurry(\s+up)?\b", r"\bclosing\s+soon\b", r"\blast\s+chance\b", r"\bdon.?t\s+(wait|delay)\b",
        r"\bexpires?\s+(today|tonight|soon)\b", r"\btime\s+is\s+running\s+out\b", r"\bbook\s+now\b",
        r"\bgrab\s+(this\s+)?now\b", r"\bhurry\s+before\b", r"\bwithin\s+\d{1,3}\s+(hours?|minutes?)\b",
        r"\brespond\s+immediately\b", r"\bimmediate\s+action\b", r"\bquick(ly)?\s+decision\b",
    ]),
    ("fomo", 10, [
        r"\bdon.?t\s+miss\b", r"\bexclusive\b", r"\bselected\s+few\b",
        r"\bbefore\s+it.?s\s+too\s+late\b", r"\bonce[- ]in[- ]a[- ]lifetime\b",
        r"\bonly\s+\d{1,3}\s+(slots?|seats?|spots?)\s+left\b", r"\bfew\s+(slots?|seats?|spots?)\s+(left|remaining)\b",
        r"\bnot\s+everyone\s+gets\s+this\b", r"\bfor\s+serious\s+investors\s+only\b",
    ]),
    ("authority_claim", 16, [
        r"\bsebi[- ]?(registered|approved|certified)\b", r"\bcertified\s+analyst\b",
        r"\binsider\s+(info|tip|information)\b", r"\bgovernment\s+approved\b", r"\brbi\s+approved\b",
        r"\blicensed\s+(broker|advisor|adviser)\b",
    ]),
    ("payment_solicitation", 14, [
        r"\bupi\b", r"[\w.\-]+@(?:ok\w{2,6}|ybl|paytm|apl|ibl)\b",
        r"\bjoin\s+(?:our\s+)?(?:vip|premium|paid)\s+group\b", r"\bsubscription\s+fee\b",
        r"\bpay\s+(?:rs\.?|₹|inr)\s?\d+", r"\bpay\s+(now|immediately|to\s+join|to\s+start)\b",
        r"\b(send|transfer|deposit)\s+(money|funds|payment|amount)\b", r"\bmake\s+(a\s+)?payment\s+(now|today|to)\b",
        r"\bactivation\s+fee\b", r"\bregistration\s+fee\b", r"\bprocessing\s+fee\b",
    ]),
]

# Every text-derived category rolls up into one of these three explainable risk buckets —
# used both for scoring and for the human-readable "why" text, so the number on screen and
# the sentence explaining it are always generated from the same underlying signal.
CATEGORY_BUCKET = {
    "guaranteed_return": "financial_claim",
    "return": "financial_claim",
    "urgency": "urgency_manipulation",
    "fomo": "urgency_manipulation",
    "authority_claim": "credibility",
    "payment_solicitation": "credibility",
}
SIGNAL_LABELS = {
    "guaranteed_return": "Guaranteed return language",
    "return": "Extreme return claim",
    "urgency": "Urgency pressure",
    "fomo": "Fear-of-missing-out pressure",
    "authority_claim": "Unverified authority claim",
    "payment_solicitation": "Payment solicitation",
}
SIGNAL_WHY = {
    "guaranteed_return": "Legitimate investments always carry risk — no genuine advisor or platform can guarantee a return, so this language alone is a strong warning sign.",
    "return": "Real markets don't produce extraordinary returns this fast; a claim this large is a mathematical red flag, not just an optimistic estimate.",
    "urgency": "Manufactured time pressure is a classic manipulation tactic used to stop a target from pausing to verify the claim before acting.",
    "fomo": "Scarcity and fear-of-missing-out language is designed to short-circuit careful decision-making by making hesitation feel costly.",
    "authority_claim": "Claiming regulatory or insider status without a verifiable registration number is a common way to borrow trust that hasn't been earned.",
    "payment_solicitation": "A direct request to pay or transfer funds — especially to a personal handle rather than a regulated institution — is how the actual financial loss happens.",
}
NEGATION_RE = re.compile(r"\b(not|n't|no|without|never|cannot|doesn.?t|does\s+not|isn.?t|aren.?t)\b", re.I)


def is_negated(text, start):
    """'Past performance does not guarantee returns' matches the same regex as 'we
    guarantee returns' unless negation is checked — this treats a real risk disclosure
    as the opposite of what it says, so any category match is dropped when a negation
    word appears in the ~30 characters immediately before it."""
    return bool(NEGATION_RE.search(text[max(0, start - 30):start]))


REG_NUMBER_RE = re.compile(r"\b(IN[HAZPM])\s?[- ]?(\d{6,12})\b", re.I)
PCT_RE = re.compile(r"(\d{1,4})\s?(?:%|percent\b|per\s?cent\b|pct\b)", re.I)
PROFIT_WORD_RE = re.compile(r"\b(returns?|profit|gains?|increase|double|triple|multibagger|jackpot)\b", re.I)
UPI_RE = re.compile(r"[\w.\-]+@(?:ok\w{2,6}|ybl|paytm|apl|ibl)\b", re.I)
UTR_RE = re.compile(r"\b\d{12}\b")
INSTITUTIONAL_VPA_HINTS = ["iccl", "ncl", "clearing", "escrow", "broking", "securities", "stockholding"]


def classify_vpa(handle):
    local = handle.split("@")[0].lower()
    if any(h in local for h in INSTITUTIONAL_VPA_HINTS):
        return {"handle": handle, "type": "institutional-style",
                "note": "Local part resembles an institutional/clearing-account naming pattern (lower risk, but not a verified registry match)."}
    return {"handle": handle, "type": "personal-style",
            "note": "Local part looks like a personal UPI handle. Legitimate brokers settle client funds through "
                    "designated clearing-corporation accounts (ICCL/NCL), never personal UPI IDs — being asked to pay "
                    "a personal handle for 'trading' or 'IPO' purposes is a strong fraud signal."}
DAILY_RE = re.compile(r"\b(daily|per\s+day|each\s+day)\b", re.I)
MONTHLY_RE = re.compile(r"\b(monthly|per\s+month|each\s+month)\b", re.I)
PERIOD_DAYS_RE = re.compile(r"\bin\s+(\d{1,3})\s+days?\b", re.I)
DOUBLE_RE = re.compile(r"\bdouble(?:s|d)?\b", re.I)
TRIPLE_RE = re.compile(r"\btriple(?:s|d)?\b", re.I)
IPO_ASBA_RE = re.compile(r"\bipo\b.{0,40}\b(allotment|apply|application)\b", re.I | re.S)

NIFTY_ANNUAL_PCT = 12.5   # illustrative long-run historical average, not live data
FD_ANNUAL_PCT = 7.0       # illustrative typical bank FD rate, not live data


def compute_math_reality(text, pct_hits):
    """Projects a claimed return rate to its 1-year compounded value. Pure arithmetic —
    no live market data — labeled as illustrative in the UI."""
    if not pct_hits:
        return None
    top = max(pct_hits, key=lambda p: p["value"])
    pct = top["value"]
    principal = 10000

    if DAILY_RE.search(text):
        daily_rate = pct / 100
        basis = f"{pct}% daily"
    elif MONTHLY_RE.search(text):
        daily_rate = (1 + pct / 100) ** (1 / 30) - 1
        basis = f"{pct}% monthly"
    else:
        m = PERIOD_DAYS_RE.search(text)
        if m:
            days = max(int(m.group(1)), 1)
            daily_rate = (1 + pct / 100) ** (1 / days) - 1
            basis = f"{pct}% in {days} days"
        elif DOUBLE_RE.search(text):
            daily_rate = (2.0) ** (1 / 30) - 1
            basis = "doubles in ~30 days (assumed)"
        elif TRIPLE_RE.search(text):
            daily_rate = (3.0) ** (1 / 30) - 1
            basis = "triples in ~30 days (assumed)"
        else:
            daily_rate = (1 + pct / 100) ** (1 / 30) - 1
            basis = f"{pct}% (assumed over 30 days)"

    final_amount = principal * (1 + daily_rate) ** 365
    implied_annual_pct = (final_amount / principal - 1) * 100

    def fmt_inr(n):
        if n >= 1e7:
            return f"₹{n/1e7:,.1f} crore"
        if n >= 1e5:
            return f"₹{n/1e5:,.1f} lakh"
        return f"₹{n:,.0f}"

    verdict = (
        "mathematically impossible — no legitimate investment sustains this"
        if implied_annual_pct > 200 else
        "far beyond any legitimate market return"
        if implied_annual_pct > FD_ANNUAL_PCT * 3 else
        "plausible, within normal market variance"
    )
    return {
        "basis": basis,
        "principal": principal,
        "finalAmount": round(final_amount, 2),
        "finalAmountFormatted": fmt_inr(final_amount),
        "impliedAnnualPct": round(implied_annual_pct, 1),
        "niftyAnnualPct": NIFTY_ANNUAL_PCT,
        "fdAnnualPct": FD_ANNUAL_PCT,
        "verdict": verdict,
        "explanation": (
            f"If ₹10,000 actually compounded at the rate implied by \"{basis}\", it would become "
            f"{fmt_inr(final_amount)} in 365 days — an implied annual return of {implied_annual_pct:,.0f}%. "
            f"For comparison, Nifty 50 has historically averaged ~{NIFTY_ANNUAL_PCT}%/year and bank FDs ~{FD_ANNUAL_PCT}%/year. "
            f"This is {verdict}."
        ),
    }


# --------------------------------------------------------------------------- OCR (image -> text)

def run_ocr(image_bytes):
    """Real OCR via Tesseract (installed locally, not simulated). Returns per-word bounding
    boxes so the frontend can highlight exactly which region of the image produced which
    piece of extracted text. If Tesseract isn't available on this machine, says so plainly
    instead of pretending text was read."""
    if not OCR_AVAILABLE:
        return {"available": False, "text": "", "confidence": None, "words": [],
                "reason": OCR_UNAVAILABLE_REASON or "OCR engine not available."}
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception as e:
        return {"available": False, "text": "", "confidence": None, "words": [], "reason": f"Could not open image: {e}"}

    # Tesseract does noticeably better on upscaled, high-contrast screenshots than on
    # small compressed phone screenshots — a light, real preprocessing pass, not a trick.
    scale = 1.0
    if max(img.size) < 1000:
        scale = 1600 / max(img.size)
        img = img.resize((int(img.width * scale), int(img.height * scale)), Image.LANCZOS)

    try:
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
    except Exception as e:
        return {"available": False, "text": "", "confidence": None, "words": [], "reason": f"OCR failed: {e}"}

    words = []
    confs = []
    for i in range(len(data["text"])):
        word = data["text"][i].strip()
        conf = data["conf"][i]
        try:
            conf = float(conf)
        except (TypeError, ValueError):
            conf = -1
        if word and conf >= 0:
            words.append({
                "text": word, "conf": round(conf, 1),
                "x": round(data["left"][i] / scale), "y": round(data["top"][i] / scale),
                "w": round(data["width"][i] / scale), "h": round(data["height"][i] / scale),
            })
            confs.append(conf)

    full_text = pytesseract.image_to_string(img).strip()
    avg_conf = round(sum(confs) / len(confs), 1) if confs else 0.0
    return {
        "available": True,
        "text": full_text,
        "confidence": avg_conf,
        "lowConfidence": avg_conf < 60,
        "words": words,
        "wordCount": len(words),
    }


# --------------------------------------------------------------------------- rich entity extraction

PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s\-]?)?[6-9]\d{9}(?!\d)")
EMAIL_RE = re.compile(r"[\w.+\-]+@[\w\-]+\.[a-zA-Z]{2,}")
SOCIAL_HANDLE_RE = re.compile(r"(?<![\w.+\-])@([A-Za-z][A-Za-z0-9_]{3,31})\b(?!\.[a-zA-Z])")
BARE_URL_RE = re.compile(
    r"\b(?:https?://)?(?:www\.)?"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\."
    r"(?:com|in|co|org|net|io|info|xyz|club|online|site|vip|live|shop|biz|me|app|gov\.in|co\.in|org\.in))"
    r"(?:/[^\s]*)?",
    re.I,
)
CURRENCY_RE = re.compile(r"(?:₹|Rs\.?|INR|\$|USD|€|EUR)\s?[\d,]+(?:\.\d+)?(?:\s?(?:lakh|lakhs|crore|crores|k|K))?", re.I)
WA_RE = re.compile(r"(?:wa\.me/|whatsapp[:\s]+\+?)(\d{10,15})", re.I)
TELEGRAM_URL_RE = re.compile(r"t(?:elegram)?\.me/\+?([A-Za-z0-9_]{3,})", re.I)
INSTAGRAM_URL_RE = re.compile(r"instagram\.com/([A-Za-z0-9_.]{2,30})", re.I)


def extract_rich_entities(text):
    """Everything here is a plain regex pass over the actual combined text (manually typed
    + OCR-extracted) — no invented data. Every field is either a real match or an empty list."""
    if not text:
        return {
            "phones": [], "emails": [], "socialHandles": [], "urls": [],
            "currencyAmounts": [], "telegramUsernames": [], "instagramUsernames": [], "whatsappNumbers": [],
        }
    phones = sorted(set(PHONE_RE.findall(text)))
    emails = sorted(set(EMAIL_RE.findall(text)))
    wa_numbers = sorted(set(WA_RE.findall(text)))
    tg_from_url = set(TELEGRAM_URL_RE.findall(text))
    ig_from_url = set(INSTAGRAM_URL_RE.findall(text))
    raw_handles = set(SOCIAL_HANDLE_RE.findall(text))
    # heuristic: which platform a bare @handle belongs to, from nearby keywords
    telegram_kw = re.search(r"telegram", text, re.I)
    instagram_kw = re.search(r"instagram|insta\b", text, re.I)
    handles = []
    for h in sorted(raw_handles):
        platform = "telegram" if (telegram_kw and not instagram_kw) else "instagram" if (instagram_kw and not telegram_kw) else "unspecified"
        handles.append({"handle": "@" + h, "platform": platform})
    for h in tg_from_url:
        if not any(x["handle"] == "@" + h for x in handles):
            handles.append({"handle": "@" + h, "platform": "telegram"})
    for h in ig_from_url:
        if not any(x["handle"] == "@" + h for x in handles):
            handles.append({"handle": "@" + h, "platform": "instagram"})

    urls = sorted({m.group(1) for m in BARE_URL_RE.finditer(text)})
    currency = sorted(set(CURRENCY_RE.findall(text)), key=len, reverse=True)

    return {
        "phones": phones, "emails": emails, "socialHandles": handles, "urls": urls,
        "currencyAmounts": currency, "telegramUsernames": sorted(tg_from_url),
        "instagramUsernames": sorted(ig_from_url), "whatsappNumbers": wa_numbers,
    }


# --------------------------------------------------------------------------- AI-assisted semantic analysis (Groq)

LLM_BUCKETS = {"financial_claim", "urgency_manipulation", "credibility", "social_signal"}
LLM_SEVERITY_SCORE = {"HIGH": 38, "MEDIUM": 22, "LOW": 10}

LLM_SYSTEM_PROMPT = """You are a financial-fraud analyst reviewing a single message, screenshot caption, or promotional text for investment-scam signals. You are a second, independent check alongside a separate rule-based system — your job is to catch real scam intent that rigid keyword matching misses (paraphrases, unusual phrasing, implied urgency, disguised payment requests), not to repeat obvious keyword hits.

Judge the ACTUAL text given. Do not assume something is a scam just because it mentions investing, stocks, or returns — hedged, factual, or disclaimer-laden financial text is legitimate. Only flag genuine manipulation, unrealistic promises, or fraud indicators.

Respond with ONLY a JSON object, no other text, matching exactly:
{
  "is_scam_language": boolean,
  "confidence": integer 0-100,
  "signals": [
    {"category": "financial_claim" | "urgency_manipulation" | "credibility" | "social_signal",
     "signal": short label (max 6 words),
     "severity": "HIGH" | "MEDIUM" | "LOW",
     "quote": short exact or close quote from the text supporting this,
     "why": one sentence on why this matters}
  ],
  "summary": one or two plain-English sentences giving your overall read of this specific text
}
If nothing suspicious is found, return an empty signals array and is_scam_language: false."""


def llm_analyze_text(text):
    """Groq-hosted LLM as a semantic second opinion alongside the regex/lexicon engine
    above. The rule-based system is the guaranteed baseline — if this call fails for any
    reason (no key, network, rate limit, malformed response), analysis proceeds on the
    rule-based signals alone rather than failing the whole request. Findings from here are
    tagged AI_ASSESSED (not OBSERVED) so the UI never presents model inference as a
    verified regex match, and the model name actually used is always disclosed."""
    if not GROQ_AVAILABLE or not text or not text.strip():
        return {"available": False, "reason": GROQ_UNAVAILABLE_REASON if not GROQ_AVAILABLE else "No text to analyze."}
    try:
        resp = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "system", "content": LLM_SYSTEM_PROMPT}, {"role": "user", "content": text[:6000]}],
            temperature=0.2,
            response_format={"type": "json_object"},
            timeout=12.0,
        )
        parsed = json.loads(resp.choices[0].message.content)
        signals = []
        for s in parsed.get("signals", []):
            category = s.get("category")
            if category not in LLM_BUCKETS:
                continue
            severity = s.get("severity") if s.get("severity") in LLM_SEVERITY_SCORE else "MEDIUM"
            signals.append({
                "signal": str(s.get("signal", "AI-flagged signal"))[:80],
                "severity": severity,
                "evidence": str(s.get("quote", ""))[:200],
                "why": str(s.get("why", ""))[:300],
                "category": category,
                "status": "AI_ASSESSED",
            })
        return {
            "available": True,
            "model": GROQ_MODEL,
            "isScamLanguage": bool(parsed.get("is_scam_language")),
            "confidence": max(0, min(100, int(parsed.get("confidence", 0)))),
            "summary": str(parsed.get("summary", ""))[:500],
            "signals": signals,
        }
    except Exception as e:
        return {"available": False, "reason": f"Groq request failed: {e}"}


# --------------------------------------------------------------------------- text scoring

def score_text(text):
    if not text or not text.strip():
        return None

    spans = []  # (start, end, category)
    hits = {}   # category -> match count
    evidence_by_category = {}  # category -> list of matched substrings (real evidence, not paraphrased)

    for category, weight, patterns in CONTENT_PATTERNS:
        count = 0
        for pat in patterns:
            for m in re.finditer(pat, text, re.I):
                if is_negated(text, m.start()):
                    continue
                spans.append((m.start(), m.end(), category))
                evidence_by_category.setdefault(category, []).append(text[m.start():m.end()])
                count += 1
        if count:
            hits[category] = (weight, count)

    # extreme percentage claims near profit language
    pct_hits = []
    for m in PCT_RE.finditer(text):
        window = text[max(0, m.start() - 40): m.end() + 40]
        if PROFIT_WORD_RE.search(window):
            pct = int(m.group(1))
            spans.append((m.start(), m.end(), "return"))
            evidence_by_category.setdefault("return", []).append(text[m.start():m.end()])
            band = 32 if pct >= 150 else 20 if pct >= 70 else 10 if pct >= 30 else 4
            pct_hits.append({"value": pct, "weight": band})

    stocks_found = sorted({s for s in INDIAN_STOCKS if re.search(r"\b" + re.escape(s) + r"\b", text, re.I)})
    upi_handles = sorted(set(UPI_RE.findall(text)))
    utrs_found = sorted(set(UTR_RE.findall(text)))

    # roll category scores up into the three explainable buckets used across the whole app
    sub_scores = {"financial_claim": 0.0, "urgency_manipulation": 0.0, "credibility": 0.0}
    for category, (weight, count) in hits.items():
        bucket = CATEGORY_BUCKET.get(category)
        if bucket:
            sub_scores[bucket] += weight + min(count - 1, 3) * (weight * 0.15)
    for p in pct_hits:
        sub_scores["financial_claim"] += p["weight"]
    sub_scores = {k: round(min(v, 100)) for k, v in sub_scores.items()}
    score = round(min(sum(sub_scores.values()), 100))

    # merge overlapping spans, keep first-seen / longest
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    merged = []
    last_end = -1
    for start, end, cat in spans:
        if start >= last_end:
            merged.append([start, end, cat])
            last_end = end
    segments = []
    cursor = 0
    for start, end, cat in merged:
        if start > cursor:
            segments.append({"text": text[cursor:start], "flag": None})
        segments.append({"text": text[start:end], "flag": cat})
        cursor = end
    if cursor < len(text):
        segments.append({"text": text[cursor:], "flag": None})

    reasons = []
    findings = []
    label_map = {
        "guaranteed_return": "uses guaranteed / risk-free return language",
        "urgency": "applies artificial time pressure",
        "fomo": "uses fear-of-missing-out phrasing",
        "authority_claim": "claims regulatory or insider authority",
        "payment_solicitation": "solicits direct payment (UPI / group fee)",
    }

    def severity_label(weight_or_score):
        return "HIGH" if weight_or_score >= 18 else "MEDIUM" if weight_or_score >= 8 else "LOW"

    for category, (weight, count) in sorted(hits.items(), key=lambda kv: -kv[1][0]):
        reasons.append({
            "sev": "critical" if weight >= 18 else "warning",
            "text": f"Message {label_map.get(category, category)} ({count} phrase{'s' if count != 1 else ''} matched).",
        })
        findings.append({
            "signal": SIGNAL_LABELS.get(category, category),
            "severity": severity_label(weight),
            "evidence": "; ".join(f'"{e}"' for e in evidence_by_category.get(category, [])[:3]),
            "why": SIGNAL_WHY.get(category, ""),
            "category": CATEGORY_BUCKET.get(category, "credibility"),
            "status": "OBSERVED",
        })
    if pct_hits:
        top = max(pct_hits, key=lambda p: p["value"])
        sev = "critical" if top["value"] >= 70 else "warning"
        reasons.append({"sev": sev, "text": f"Claims a {top['value']}% return tied to profit language — unrealistic short-term promises are a classic pump/scam signal."})
        findings.append({
            "signal": SIGNAL_LABELS["return"], "severity": severity_label(top["weight"] * 2),
            "evidence": "; ".join(f'"{e}"' for e in evidence_by_category.get("return", [])[:3]),
            "why": SIGNAL_WHY["return"], "category": "financial_claim", "status": "OBSERVED",
        })

    reg_match = REG_NUMBER_RE.search(text)
    identity = None
    if reg_match:
        prefix = reg_match.group(1).upper()
        number = reg_match.group(2)
        valid_prefix = prefix in SEBI_PREFIXES
        identity = {
            "available": True,
            "claimedNumber": f"{prefix}{number}",
            "formatValid": valid_prefix,
            "category": SEBI_PREFIXES.get(prefix),
            "note": (
                f"Format matches SEBI's {SEBI_PREFIXES.get(prefix)} numbering convention. "
                "This is a structural check only — confirming the number is actually live "
                "requires a query against SEBI's registry, which isn't connected in this build."
                if valid_prefix else
                f"'{prefix}{number}' does not match any known SEBI intermediary prefix "
                "(INH/INA/INZ/INP/INM) — this alone strongly suggests a fabricated registration number."
            ),
        }
        reasons.append({
            "sev": "safe" if valid_prefix else "critical",
            "text": (f"Registration number {prefix}{number} follows a valid SEBI format." if valid_prefix
                     else f"Registration number {prefix}{number} does not follow any real SEBI prefix format."),
        })
        findings.append({
            "signal": "SEBI registration format", "severity": "SAFE" if valid_prefix else "HIGH",
            "evidence": f'"{prefix}{number}"',
            "why": ("This is a structural format check only — a valid-looking prefix does not confirm the number is "
                    "actually live in SEBI's registry, which isn't connected in this build.") if valid_prefix else
                   "This does not match any real SEBI intermediary prefix (INH/INA/INZ/INP/INM), which strongly suggests a fabricated number.",
            "category": "credibility", "status": "INFERRED" if valid_prefix else "OBSERVED",
        })
        if not valid_prefix:
            sub_scores["credibility"] = min(sub_scores["credibility"] + 30, 100)
            score = round(min(score + 30, 100))

    for handle in upi_handles:
        vc = classify_vpa(handle)
        if vc["type"] == "personal-style" and "payment_solicitation" in hits:
            reasons.append({"sev": "warning", "text": f"Payment handle {handle} looks like a personal UPI ID, not a broker clearing account. {vc['note']}"})
            findings.append({
                "signal": "Personal-style payment handle", "severity": "MEDIUM", "evidence": f'"{handle}"',
                "why": vc["note"], "category": "credibility", "status": "OBSERVED",
            })

    advisor_match = match_advisor_name(text)
    if advisor_match and advisor_match["matchType"] == "fuzzy":
        reasons.append({"sev": "critical", "text": f"Claimed name is a near-match impersonation risk: {advisor_match['note']}"})
        findings.append({
            "signal": "Advisor name impersonation", "severity": "HIGH", "evidence": f'"{advisor_match["claimedName"]}"',
            "why": advisor_match["note"], "category": "credibility", "status": "INFERRED",
        })
        sub_scores["credibility"] = min(sub_scores["credibility"] + 25, 100)
        score = round(min(score + 25, 100))
    elif advisor_match and advisor_match["matchType"] == "exact":
        reasons.append({"sev": "safe", "text": advisor_match["note"]})
        findings.append({
            "signal": "Advisor name match", "severity": "SAFE", "evidence": f'"{advisor_match["claimedName"]}"',
            "why": advisor_match["note"], "category": "credibility", "status": "INFERRED",
        })

    asba_alert = None
    if IPO_ASBA_RE.search(text) and (UPI_RE.search(text) or re.search(r"\bpay\b|\btransfer\b|\bupi\b", text, re.I)):
        asba_alert = (
            "This message asks you to pay/transfer money for an IPO allotment. SEBI mandates ASBA "
            "(Applications Supported by Blocked Amount) for IPO applications — your funds stay blocked "
            "in your own bank account and are never transferred to anyone until allotment. Any request "
            "to send money directly for an IPO is a bypass of this rule and a strong fraud indicator."
        )
        reasons.append({"sev": "critical", "text": "Requests direct payment for an IPO allotment — this bypasses SEBI's mandatory ASBA process."})
        findings.append({
            "signal": "IPO payment bypasses ASBA", "severity": "HIGH", "evidence": "IPO + allotment + payment request found together",
            "why": "SEBI mandates ASBA for IPO applications — funds stay blocked in the investor's own account, never transferred to a third party. A direct payment request bypasses this by design.",
            "category": "credibility", "status": "OBSERVED",
        })
        sub_scores["credibility"] = min(sub_scores["credibility"] + 20, 100)
        score = round(min(score + 20, 100))

    if not reasons:
        reasons.append({"sev": "safe", "text": "No guaranteed-return, urgency, FOMO, authority-claim, or payment-solicitation language detected."})

    return {
        "available": True,
        "score": score,
        "subScores": sub_scores,
        "segments": segments,
        "entities": {"stocks": stocks_found, "pctClaims": [p["value"] for p in pct_hits], "upiHandles": upi_handles,
                     "utrs": utrs_found, "vpaClassification": [classify_vpa(h) for h in upi_handles]},
        "identity": identity,
        "advisorNameCheck": advisor_match,
        "mathReality": compute_math_reality(text, pct_hits),
        "asbaAlert": asba_alert,
        "reasons": reasons,
        "findings": findings,
    }


# --------------------------------------------------------------------------- network safety

def is_safe_host(hostname):
    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception:
        return False, "DNS resolution failed for this host."
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            return False, f"Target resolves to a non-public address ({ip}) and was blocked for safety."
    return True, None


# --------------------------------------------------------------------------- whois

def _whois_query(server, query, timeout=5):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.decode(errors="ignore")


DATE_PATTERNS = [
    re.compile(r"(?:Creation Date|Domain Registration Date|Registered on|created|Registration Time)\s*:?\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", re.I),
    re.compile(r"(?:Creation Date|created)\s*:?\s*([0-9]{2}-[A-Za-z]{3}-[0-9]{4})", re.I),
]
MONTHS = {m.lower(): i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def _parse_whois_date(text):
    for pat in DATE_PATTERNS:
        m = pat.search(text)
        if not m:
            continue
        raw = m.group(1)
        try:
            if "-" in raw and raw[:2].isdigit() is False:
                d, mon, y = raw.split("-")
                return datetime(int(y), MONTHS.get(mon.lower(), 1), int(d), tzinfo=timezone.utc)
            return datetime.strptime(raw[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


TWO_LABEL_SUFFIXES = {"co", "org", "net", "gov", "edu", "ac", "com", "gen", "firm", "ind"}


def registrable_domain(host):
    labels = host.lower().split(".")
    if len(labels) <= 2:
        return host.lower()
    if labels[-2] in TWO_LABEL_SUFFIXES and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def whois_lookup(domain):
    domain = registrable_domain(domain)
    tld = domain.rsplit(".", 1)[-1].lower()
    result = {"registrar": None, "creationDate": None, "domainAgeDays": None, "whoisPrivacy": False,
              "registrantCountry": None, "raw_ok": False, "queriedDomain": domain}
    try:
        iana = _whois_query("whois.iana.org", tld)
    except Exception as e:
        result["error"] = f"IANA lookup failed: {e}"
        return result
    m = re.search(r"^refer:\s*(\S+)", iana, re.I | re.M) or re.search(r"^whois:\s*(\S+)", iana, re.I | re.M)
    server = m.group(1) if m else f"whois.nic.{tld}"
    text = ""
    try:
        text = _whois_query(server, domain)
    except Exception as e:
        result["error"] = f"Registry query to {server} failed: {e}"
        return result
    if re.search(r"no match|not found|no entries found|no data found|status:\s*free", text, re.I):
        result["error"] = f"{domain} is not registered, or {server} reported no match."
        return result
    m2 = re.search(r"(?:Registrar WHOIS Server|ReferralServer)\s*:\s*(?:whois://)?(\S+)", text, re.I)
    if m2 and m2.group(1).strip() != server:
        try:
            deeper = _whois_query(m2.group(1).strip(), domain)
            if len(deeper) > 80:
                text = deeper
        except Exception:
            pass

    result["raw_ok"] = bool(text.strip())
    reg_m = re.search(r"Registrar\s*:\s*(.+)", text, re.I)
    if reg_m:
        result["registrar"] = reg_m.group(1).strip()
    country_m = re.search(r"Registrant Country\s*:\s*(.+)", text, re.I)
    if country_m:
        result["registrantCountry"] = country_m.group(1).strip()
    if re.search(r"redacted for privacy|privacy\s*protect|whoisguard|domains by proxy|private registration", text, re.I):
        result["whoisPrivacy"] = True

    created = _parse_whois_date(text)
    if created:
        result["creationDate"] = created.date().isoformat()
        result["domainAgeDays"] = (datetime.now(timezone.utc) - created).days
    return result


# --------------------------------------------------------------------------- ssl

def check_ssl(hostname, port=443, timeout=5):
    """Fetches the certificate via getpeercert(binary_form=True) rather than the parsed
    dict form — Python's ssl module only populates the parsed dict when verify_mode is
    CERT_REQUIRED, so an unverified fallback connection would otherwise silently return
    an empty dict even though the certificate was received. Parsing the raw DER bytes
    with `cryptography` gives real issuer/expiry data regardless of verification outcome,
    while `verified` still honestly reflects whether the chain actually validated."""
    result = {"verified": False, "issuer": None, "notAfter": None, "daysToExpiry": None, "error": None}
    der = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                result["verified"] = True
    except Exception as e:
        result["error"] = str(e)
    if der is None:
        try:
            ctx2 = ssl._create_unverified_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der = ssock.getpeercert(binary_form=True)
        except Exception as e2:
            result["error"] = (result["error"] + " | " if result["error"] else "") + f"unverified fetch also failed: {e2}"
            return result
    if der:
        try:
            cert = x509.load_der_x509_certificate(der)
            org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            result["issuer"] = (org[0].value if org else None) or (cn[0].value if cn else None)
            not_after = cert.not_valid_after_utc
            result["notAfter"] = not_after.isoformat()
            result["daysToExpiry"] = (not_after - datetime.now(timezone.utc)).days
        except Exception as e3:
            result["error"] = (result["error"] + " | " if result["error"] else "") + f"cert parse failed: {e3}"
    return result


# --------------------------------------------------------------------------- page fetch

def fetch_page(url, timeout=6):
    result = {"finalUrl": url, "statusCode": None, "chain": [url], "title": None, "error": None,
              "textSample": None, "sslVerificationFailed": False}
    for verify in (True, False):
        try:
            resp = SESSION.get(url, timeout=timeout, allow_redirects=True, verify=verify)
            result["chain"] = [r.url for r in resp.history] + [resp.url]
            result["finalUrl"] = resp.url
            result["statusCode"] = resp.status_code
            result["sslVerificationFailed"] = not verify
            soup = BeautifulSoup(resp.text[:300000], "html.parser")
            if soup.title and soup.title.string:
                result["title"] = soup.title.string.strip()[:200]
            result["textSample"] = soup.get_text(" ", strip=True)[:4000]
            result["error"] = None
            return result
        except requests.exceptions.SSLError as e:
            result["error"] = str(e)
            continue
        except Exception as e:
            result["error"] = str(e)
            return result
    return result


# --------------------------------------------------------------------------- telegram / instagram

def parse_abbrev_number(s):
    if not s:
        return None
    m = re.search(r"([\d.,]+)\s*([KMB]?)", s, re.I)
    if not m:
        return None
    try:
        num = float(m.group(1).replace(",", ""))
    except ValueError:
        return None
    mult = {"": 1, "k": 1_000, "m": 1_000_000, "b": 1_000_000_000}.get(m.group(2).lower(), 1)
    return num * mult


def analyze_telegram(url):
    m = re.search(r"t(?:elegram)?\.me/(?:s/)?\+?([A-Za-z0-9_]{3,})", url, re.I)
    if not m:
        return None
    channel = m.group(1)
    try:
        resp = SESSION.get(f"https://t.me/s/{channel}", timeout=6, verify=False)
        if resp.status_code != 200 or "tgme_channel_info" not in resp.text:
            return {"available": False, "channel": channel,
                    "note": "This channel's public preview is disabled or it does not exist — content could not be fetched without joining."}
        soup = BeautifulSoup(resp.text, "html.parser")
        title_el = soup.select_one(".tgme_channel_info_header_title")
        desc_el = soup.select_one(".tgme_channel_info_description")
        subscriber_label = next(
            (c.get_text(" ", strip=True) for c in soup.select(".tgme_channel_info_counter")
             if "subscriber" in c.get_text(" ", strip=True).lower() or "member" in c.get_text(" ", strip=True).lower()),
            None,
        )
        messages = [el.get_text(" ", strip=True) for el in soup.select(".tgme_widget_message_text")][-8:]
        msg_scores = [score_text(msg)["score"] for msg in messages if msg and score_text(msg)]
        avg_risk = round(sum(msg_scores) / len(msg_scores)) if msg_scores else None

        subscriber_count = parse_abbrev_number(subscriber_label)
        view_labels = [v.get_text(strip=True) for v in soup.select(".tgme_widget_message_views")]
        view_counts = [n for n in (parse_abbrev_number(v) for v in view_labels) if n is not None]
        avg_views = sum(view_counts) / len(view_counts) if view_counts else None
        view_ratio_pct = (avg_views / subscriber_count * 100) if (avg_views and subscriber_count) else None
        bot_flag = bool(subscriber_count and subscriber_count > 50000 and view_ratio_pct is not None and view_ratio_pct < 1)

        return {
            "available": True, "channel": channel,
            "title": title_el.get_text(strip=True) if title_el else channel,
            "description": desc_el.get_text(strip=True) if desc_el else None,
            "membersLabel": subscriber_label,
            "subscriberCount": subscriber_count,
            "avgViews": round(avg_views) if avg_views else None,
            "viewToSubscriberPct": round(view_ratio_pct, 2) if view_ratio_pct is not None else None,
            "botNetworkSuspected": bot_flag,
            "recentMessages": messages,
            "messagesRiskAvg": avg_risk,
        }
    except Exception as e:
        return {"available": False, "channel": channel, "note": f"Fetch failed: {e}"}


def analyze_instagram(url):
    m = re.search(r"instagram\.com/([A-Za-z0-9_.]{2,30})/?", url, re.I)
    if not m:
        return None
    handle = m.group(1)
    if handle.lower() in ("p", "reel", "reels", "stories", "explore"):
        return {"available": False, "note": "This looks like a post/reel link rather than a profile — profile checks don't apply here."}
    try:
        resp = SESSION.get(f"https://www.instagram.com/{handle}/", timeout=6, verify=False)
        m2 = re.search(r'content="([\d,.]+[KMk]?) Followers, ([\d,.]+[KMk]?) Following, ([\d,.]+[KMk]?) Posts', resp.text)
        if m2:
            return {"available": True, "handle": handle, "followers": m2.group(1), "following": m2.group(2), "posts": m2.group(3)}
        return {"available": False, "handle": handle,
                "note": "Instagram blocked automated access to this profile (it requires a login for most data since ~2020) — follower/post counts could not be verified remotely."}
    except Exception as e:
        return {"available": False, "handle": handle, "note": f"Fetch failed: {e}"}


# --------------------------------------------------------------------------- link scoring

def analyze_link(raw_url):
    url = raw_url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    host = host.lower()

    flags = []
    score = 0

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    if is_ip:
        score += 30
        flags.append({"sev": "critical", "text": "Destination is a raw IP address rather than a domain name — legitimate advisory services don't do this."})

    if "@" in parsed.netloc:
        score += 25
        flags.append({"sev": "critical", "text": "URL contains an '@' before the host — a classic trick to disguise the real destination."})

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        score += 15
        flags.append({"sev": "warning", "text": f".{tld} is a low-cost TLD frequently abused for short-lived scam and phishing sites."})

    registrable = registrable_domain(host) if host else host
    if registrable in SHORTENERS:
        score += 18
        flags.append({"sev": "warning", "text": f"{registrable} is a link-shortening service — the real destination is hidden until visited."})

    subdomain_count = max(host.count(".") - 1, 0)
    if subdomain_count > 3:
        score += 10
        flags.append({"sev": "warning", "text": f"Unusually deep subdomain chain ({subdomain_count} levels) — often used to obscure the true domain."})

    brand_hit = False
    for kw in BRAND_KEYWORDS:
        if kw in host and registrable not in OFFICIAL_FINANCE_DOMAINS:
            score += 25
            flags.append({"sev": "critical", "text": f"Domain contains '{kw}' but is not an official {kw.upper()} domain ({registrable}) — likely impersonation."})
            brand_hit = True
            break
    if not brand_hit:
        normalized = normalize_confusables(host)
        for kw in BRAND_KEYWORDS:
            if kw in normalized and kw not in host and registrable not in OFFICIAL_FINANCE_DOMAINS:
                score += 28
                flags.append({"sev": "critical", "text": f"Domain uses look-alike characters that read as '{kw.upper()}' (e.g. digits swapped for letters) — a homoglyph trick to impersonate {kw.upper()}."})
                break

    is_idn, idn_decoded = decode_punycode_labels(host)
    if is_idn:
        score += 45
        flags.append({"sev": "critical", "text": f"Domain is internationalized (punycode: {host}) and renders in a browser as '{idn_decoded}' — a well-known technique for spoofing ASCII brand names with visually-identical Unicode characters. Legitimate Indian financial services never need this."})

    safe, safe_reason = is_safe_host(host) if host else (False, "No host in URL.")
    link_data = {
        "url": url, "domain": host, "tld": tld, "isIpLiteral": is_ip,
        "isShortener": registrable in SHORTENERS, "subdomainCount": subdomain_count,
        "isIdn": is_idn, "idnDecoded": idn_decoded if is_idn else None,
        "whois": None, "ssl": None, "page": None, "telegram": None, "instagram": None,
        "blocked": not safe, "blockedReason": safe_reason if not safe else None,
    }

    if safe:
        is_telegram = bool(re.search(r"t(?:elegram)?\.me/", url, re.I))
        is_instagram = bool(re.search(r"instagram\.com/", url, re.I))
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {
                "whois": pool.submit(whois_lookup, host),
                "ssl": pool.submit(check_ssl, host),
                "page": pool.submit(fetch_page, url),
            }
            if is_telegram:
                futures["telegram"] = pool.submit(analyze_telegram, url)
            if is_instagram:
                futures["instagram"] = pool.submit(analyze_instagram, url)
            results = {k: f.result() for k, f in futures.items()}

        whois = results["whois"]
        link_data["whois"] = whois
        if whois.get("domainAgeDays") is not None:
            age = whois["domainAgeDays"]
            if age < 14:
                score += 40
                flags.append({"sev": "critical", "text": f"Domain was registered only {age} day(s) ago — extremely fresh domains are the single strongest scam-site signal."})
            elif age < 60:
                score += 25
                flags.append({"sev": "warning", "text": f"Domain is only {age} days old."})
            elif age < 180:
                score += 12
                flags.append({"sev": "warning", "text": f"Domain is {age} days old — still relatively new."})
        else:
            flags.append({"sev": "info", "text": "Could not determine domain registration date from WHOIS."})
        if whois.get("whoisPrivacy"):
            score += 8
            flags.append({"sev": "info", "text": "WHOIS registrant identity is masked by a privacy service."})

        ssl_info = results["ssl"]
        link_data["ssl"] = ssl_info
        if ssl_info.get("error") and not ssl_info.get("verified"):
            score += 10
            flags.append({"sev": "warning", "text": "TLS certificate could not be fully verified from this network — issuer identity is unconfirmed."})

        page = results["page"]
        link_data["page"] = page
        if page.get("chain") and len(page["chain"]) > 2:
            hops = len(page["chain"]) - 1
            score += min(hops * 8, 24)
            flags.append({"sev": "warning", "text": f"URL redirects {hops} times before reaching its final destination."})
        if page.get("error") and page.get("statusCode") is None:
            flags.append({"sev": "info", "text": f"Could not reach the page directly: {page['error']}"})

        tg = results.get("telegram")
        if tg:
            link_data["telegram"] = tg
            if tg.get("available") and tg.get("messagesRiskAvg") is not None and tg["messagesRiskAvg"] >= 40:
                score += 15
                flags.append({"sev": "warning", "text": f"Recent messages in this Telegram channel score {tg['messagesRiskAvg']}/100 on average for scam-style language."})
            if tg.get("available") and tg.get("botNetworkSuspected"):
                score += 18
                flags.append({"sev": "warning", "text": f"Channel claims {tg['membersLabel']} but recent posts average only {tg['viewToSubscriberPct']}% views-to-subscribers — consistent with bought/bot subscribers rather than a real, engaged audience."})
        ig = results.get("instagram")
        if ig:
            link_data["instagram"] = ig
    else:
        flags.append({"sev": "info", "text": safe_reason})

    link_data["score"] = round(min(score, 100))
    link_data["flags"] = flags
    link_data["available"] = True
    return link_data


# --------------------------------------------------------------------------- image forensics (ELA)

def error_level_analysis(image_bytes, quality=90):
    """Real Error Level Analysis: resaves the image at a known JPEG quality and diffs it
    against the original. Regions edited after the original save (inserted/altered text,
    pasted numbers) were compressed at a different generation and light up with higher
    error residuals than the rest of the image. This is a real, well-known forensic
    technique — no trained model involved, just Pillow + numpy.

    Caveat shown honestly in the UI: images that have already been through multiple
    rounds of lossy recompression (e.g. forwarded many times over WhatsApp) can produce
    noisier ELA maps even when untampered, so this is a signal to investigate, not a
    standalone verdict."""
    orig = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    if orig.width * orig.height > 4000 * 4000:
        raise ValueError("Image too large to analyze (max ~16MP).")

    buf = io.BytesIO()
    orig.save(buf, "JPEG", quality=quality)
    buf.seek(0)
    resaved = Image.open(buf).convert("RGB")

    diff = ImageChops.difference(orig, resaved)
    arr = np.asarray(diff.convert("L"), dtype=float)

    p99 = float(np.percentile(arr, 99))
    p50 = float(np.percentile(arr, 50))
    tamper_score = round(min((p99 / (p50 + 1)) * 8, 100), 1)

    threshold = np.percentile(arr, 97)
    mask = arr > max(threshold, 12)
    ys, xs = np.where(mask)
    bbox = None
    if len(xs) > 20:
        bbox = [int(xs.min()), int(ys.min()), int(xs.max()), int(ys.max())]

    scale = 255.0 / (arr.max() if arr.max() > 0 else 1)
    ela_visual = diff.point(lambda p: min(255, p * scale))
    annotated = ela_visual.convert("RGB")
    if bbox:
        draw = ImageDraw.Draw(annotated)
        draw.rectangle(bbox, outline=(255, 40, 40), width=max(2, orig.width // 200))

    out_buf = io.BytesIO()
    annotated.save(out_buf, "PNG")
    ela_data_uri = "data:image/png;base64," + base64.b64encode(out_buf.getvalue()).decode()

    verdict = (
        "likely locally edited — a bounded region shows a much higher compression-error residual than the rest of the image"
        if tamper_score >= 55 and bbox else
        "inconclusive — mild variance, consistent with normal recompression noise (e.g. multiple WhatsApp forwards)"
        if tamper_score >= 25 else
        "no strong tamper signal detected"
    )
    return {
        "tamperScore": tamper_score,
        "bbox": bbox,
        "verdict": verdict,
        "elaPreview": ela_data_uri,
        "imageSize": [orig.width, orig.height],
    }


# --------------------------------------------------------------------------- fusion + routes

BUCKET_WEIGHTS = {
    "financial_claim": 0.24, "urgency_manipulation": 0.12, "credibility": 0.16,
    "social_signal": 0.14, "url_risk": 0.18, "visual_tampering": 0.16,
}
BUCKET_LABELS = {
    "financial_claim": "Financial Claim Risk", "urgency_manipulation": "Urgency / Manipulation Risk",
    "credibility": "Credibility Risk", "social_signal": "Social Signal Risk",
    "url_risk": "URL Risk", "visual_tampering": "Visual Tampering Risk",
}
SEV_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "SAFE": 3}


def fuse_all(buckets):
    """Weighted fusion over whichever risk buckets actually produced a signal for this
    submission — a text-only submission never gets a visual_tampering score pulling it
    down/up, an image-only submission still gets financial_claim/credibility scores from
    whatever OCR extracted. Weights are fixed and documented (see /api/analyze response
    methodology), not tuned per-request.

    Three ideas, combined transparently rather than one opaque formula:

    1. Weighted average across whichever buckets are available — the baseline.
    2. A single severe, well-evidenced bucket shouldn't get diluted by categories that
       are simply not applicable to this submission (e.g. a blatant guaranteed-return
       claim with no payment ask yet still reads near-zero on credibility/social). So the
       score is at least 85% of the single highest TEXT-evidence bucket (financial claim,
       urgency, credibility, social, url) — visual_tampering is excluded from this specific
       boost because ELA is a statistical heuristic that reads elevated on plenty of
       untampered images (sharp text edges, repeated recompression), unlike the text
       buckets which are direct evidence matches with a negation guard.
    3. Independent corroborating signals compound risk: real fraud attempts rarely trip
       only one wire. When two or more buckets are simultaneously elevated (>=10), a
       corroboration bonus (10 points per elevated bucket, capped at 35) is added — this
       is what pushes a message combining guaranteed-returns + urgency + a suspicious
       contact channel + a risky URL noticeably higher than any single signal alone,
       without requiring a black-box multiplicative formula."""
    parts = [(name, b["score"], BUCKET_WEIGHTS[name]) for name, b in buckets.items() if b.get("available")]
    if not parts:
        return 0, 30
    weighted = sum(s * w for _, s, w in parts) / sum(w for _, _, w in parts)

    elevated = [s for _, s, _ in parts if s >= 10]
    corroboration = min(len(elevated) * 10, 35) if len(elevated) >= 2 else 0

    peak_candidates = [s for name, s, _ in parts if name != "visual_tampering"]
    peak = max(peak_candidates) * 0.85 if peak_candidates else 0

    overall = max(weighted + corroboration, peak)
    confidence = min(48 + 8 * len(parts), 96)
    return round(min(overall, 100)), confidence


def verdict_for(score):
    if score >= 70:
        return "FRAUDULENT"
    if score >= 35:
        return "SUSPICIOUS"
    return "GENUINE"


def verdict_label_for(score):
    if score >= 80:
        return "HIGHLY SUSPICIOUS FINANCIAL FRAUD"
    if score >= 60:
        return "HIGH RISK — LIKELY INVESTMENT SCAM"
    if score >= 40:
        return "SUSPICIOUS INVESTMENT PROMOTION"
    if score >= 20:
        return "POTENTIALLY MISLEADING PROMOTION"
    return "LOW RISK — NO STRONG SCAM INDICATORS"


def extract_payment_handles(text, link):
    handles = set()
    if text:
        handles.update(UPI_RE.findall(text))
    page = (link or {}).get("page") or {}
    if page.get("textSample"):
        handles.update(UPI_RE.findall(page["textSample"]))
    return sorted(handles)


def compute_social_signal_risk(entities, telegram_module, has_payment_solicitation):
    score = 0
    findings = []
    handles = entities.get("socialHandles", [])
    wa_numbers = entities.get("whatsappNumbers", [])
    has_social_contact = bool(handles or wa_numbers)

    if has_social_contact and has_payment_solicitation:
        score += 45
        evidence = ", ".join([h["handle"] for h in handles[:3]] + wa_numbers[:2])
        findings.append({
            "signal": "Social-media-only contact", "severity": "HIGH", "evidence": evidence,
            "why": "Legitimate financial institutions provide verifiable, regulated contact channels. Routing payment-related contact only through Telegram/WhatsApp/Instagram, with no verifiable company behind it, is a common scam pattern.",
            "category": "social_signal", "status": "OBSERVED",
        })
    elif has_social_contact:
        score += 12
        evidence = ", ".join([h["handle"] for h in handles[:3]] + wa_numbers[:2])
        findings.append({
            "signal": "Social-media contact present", "severity": "LOW", "evidence": evidence,
            "why": "Not inherently suspicious on its own, but worth verifying independently rather than trusting contact details provided only inside the promotional material itself.",
            "category": "social_signal", "status": "OBSERVED",
        })

    if telegram_module and telegram_module.get("available") and telegram_module.get("botNetworkSuspected"):
        score += 35
        findings.append({
            "signal": "Bot-inflated subscriber count", "severity": "HIGH",
            "evidence": f"{telegram_module['membersLabel']} but only {telegram_module['viewToSubscriberPct']}% views-to-subscribers",
            "why": "A subscriber count far exceeding actual engagement is a known sign of purchased or bot-generated followers used to fake credibility.",
            "category": "social_signal", "status": "OBSERVED",
        })

    available = bool(has_social_contact or (telegram_module and telegram_module.get("available")))
    return {"score": round(min(score, 100)), "available": available, "findings": findings}


def link_flag_to_finding(flag):
    sev_map = {"critical": "HIGH", "warning": "MEDIUM", "info": "LOW", "safe": "SAFE"}
    return {"signal": "Link / domain signal", "severity": sev_map.get(flag["sev"], "MEDIUM"),
            "evidence": flag["text"], "why": None, "category": "url_risk", "status": "OBSERVED"}


def ela_to_finding(ela):
    sev = "HIGH" if ela["tamperScore"] >= 55 else "MEDIUM" if ela["tamperScore"] >= 25 else "LOW"
    return {
        "signal": "Visual tampering (Error Level Analysis)", "severity": sev, "evidence": ela["verdict"],
        "why": "Regions edited after the original save are recompressed at a different generation than the rest of the image, which produces a different error residual when the whole image is resaved at a known JPEG quality.",
        "category": "visual_tampering", "status": "INFERRED",
    }


def build_financial_claims(content):
    claims = []
    if not content or not content.get("available"):
        return claims
    for pct in content["entities"].get("pctClaims", []):
        claims.append({"type": "percentage_return", "raw": f"{pct}%", "value": pct})
    for f in content.get("findings", []):
        if f["category"] == "financial_claim" and f["signal"] == SIGNAL_LABELS["guaranteed_return"]:
            claims.append({"type": "guarantee_claim", "raw": f["evidence"], "value": None})
    return claims


def build_contact_info(entities):
    telegram = [h["handle"] for h in entities["socialHandles"] if h["platform"] == "telegram"]
    telegram += [f"@{u}" for u in entities["telegramUsernames"] if f"@{u}" not in telegram]
    instagram = [h["handle"] for h in entities["socialHandles"] if h["platform"] == "instagram"]
    instagram += [f"@{u}" for u in entities["instagramUsernames"] if f"@{u}" not in instagram]
    unspecified = [h["handle"] for h in entities["socialHandles"] if h["platform"] == "unspecified"]
    return {
        "telegram": telegram, "instagram": instagram, "whatsapp": entities["whatsappNumbers"],
        "unspecifiedSocial": unspecified, "phones": entities["phones"], "emails": entities["emails"],
    }


def build_narrative(score, label, confidence, findings, content, link, ela, entities, financial_claims, contact_info, llm=None):
    ranked = sorted(findings, key=lambda f: SEV_RANK.get(f["severity"], 1))

    why_flagged = []
    for f in ranked:
        if f["severity"] not in ("HIGH", "MEDIUM"):
            continue
        if f["evidence"]:
            why_flagged.append(f"{f['signal']} detected: {f['evidence']}.")
        elif f["why"]:
            why_flagged.append(f["why"])
        if len(why_flagged) >= 6:
            break

    evidence_facts = []
    if content and content.get("available"):
        for pct in content["entities"].get("pctClaims", []):
            evidence_facts.append(f"Promised return: {pct}%")
        if content.get("mathReality"):
            evidence_facts.append(f"Claimed basis: {content['mathReality']['basis']}")
        for utr in content["entities"].get("utrs", []):
            evidence_facts.append(f"Transaction ID (UTR) found: {utr}")
    for h in contact_info.get("telegram", [])[:2]:
        evidence_facts.append(f"Contact: Telegram {h}")
    for h in contact_info.get("instagram", [])[:2]:
        evidence_facts.append(f"Contact: Instagram {h}")
    for n in contact_info.get("whatsapp", [])[:2]:
        evidence_facts.append(f"Contact: WhatsApp {n}")
    if link and link.get("available") and not link.get("blocked"):
        evidence_facts.append(f"URL detected: {link['domain']}")
    if ela:
        evidence_facts.append(f"Visual tampering score: {ela['tamperScore']}/100")

    categories_present = {f["category"] for f in findings if f["severity"] in ("HIGH", "MEDIUM")}
    why_matters_map = {
        "financial_claim": "A legitimate investment cannot normally guarantee extraordinary returns over an extremely short period.",
        "urgency_manipulation": "Manufactured urgency is a manipulation tactic meant to prevent independent verification before acting.",
        "credibility": "Claims of authority or registration that don't check out remove the last reason to trust the message.",
        "social_signal": "Directing contact to an anonymous social-media handle instead of a verifiable institution removes accountability if something goes wrong.",
        "url_risk": "The linked destination shows structural signs commonly seen in short-lived scam infrastructure.",
        "visual_tampering": "The image shows signs of local editing, which is how fabricated profit screenshots are typically produced.",
    }
    why_matters = " ".join(why_matters_map[c] for c in ("financial_claim", "urgency_manipulation", "credibility", "social_signal", "url_risk", "visual_tampering") if c in categories_present)
    if not why_matters:
        why_matters = "No combination of high- or medium-severity risk signals was found in the available content, but independent verification is always worthwhile before acting on a financial promotion."

    if score >= 60:
        recommended = [
            "Do not send money.",
            "Do not share OTPs, passwords, or banking credentials.",
            "Verify the company or advisor independently through SEBI's official registry — not through contact details given inside this material.",
            "If you've already paid, see the \"If you already paid\" tab for time-sensitive next steps.",
        ]
    elif score >= 30:
        recommended = [
            "Independently verify any registration number, company name, or advisor identity before proceeding.",
            "Be skeptical of guaranteed or unusually high return claims.",
            "Avoid paying into personal UPI IDs or unfamiliar bank accounts.",
        ]
    else:
        recommended = [
            "No strong fraud indicators were found, but always verify independently before investing.",
            "Cross-check any registration numbers against SEBI's official registry.",
        ]

    return {
        "summary": f"{label} — risk score {score}/100 with {confidence}% confidence.",
        "whyFlagged": why_flagged or ["No significant scam-pattern language, financial claims, or link-risk signals were detected in the available content."],
        "evidence": evidence_facts,
        "whyItMatters": why_matters,
        "recommendedAction": recommended,
        "aiAssessment": (llm.get("summary") or None) if llm and llm.get("available") else None,
    }


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    text = (request.form.get("text") or "").strip()
    url = (request.form.get("url") or "").strip()
    image_file = request.files.get("image")
    if not text and not url and not image_file:
        body = request.get_json(silent=True) or {}
        text = (body.get("text") or "").strip()
        url = (body.get("url") or "").strip()

    image_bytes = None
    image_name = None
    if image_file and image_file.filename:
        image_bytes = image_file.read()
        image_name = image_file.filename
        if len(image_bytes) > 12 * 1024 * 1024:
            return jsonify({"error": "Image too large (max 12MB)."}), 400

    if not text and not url and not image_bytes:
        return jsonify({"error": "Provide text, a url, and/or an image to analyze."}), 400

    t0 = time.time()

    ocr = run_ocr(image_bytes) if image_bytes else None

    combined_parts = []
    if text:
        combined_parts.append(text)
    if ocr and ocr.get("available") and ocr.get("text"):
        combined_parts.append(ocr["text"])
    combined_text = "\n".join(combined_parts).strip()

    entities = extract_rich_entities(combined_text)

    effective_url = url
    auto_detected_url = False
    if not effective_url and entities["urls"]:
        effective_url = entities["urls"][0]
        auto_detected_url = True

    content = score_text(combined_text) if combined_text else {"available": False}

    with ThreadPoolExecutor(max_workers=2) as pool:
        link_future = pool.submit(analyze_link, effective_url) if effective_url else None
        llm_future = pool.submit(llm_analyze_text, combined_text) if combined_text else None
        link = link_future.result() if link_future else {"available": False}
        llm = llm_future.result() if llm_future else {"available": False, "reason": "No text to analyze."}

    try:
        ela = error_level_analysis(image_bytes) if image_bytes else None
        ela_error = None
    except Exception as e:
        ela = None
        ela_error = str(e)

    has_payment_solicitation = bool(content.get("available") and any(
        f["category"] == "credibility" and f["signal"] == SIGNAL_LABELS["payment_solicitation"] for f in content.get("findings", [])
    ))
    social = compute_social_signal_risk(entities, link.get("telegram") if link.get("available") else None, has_payment_solicitation)

    # The LLM is a semantic second opinion, not a second vote to add on top of the regex
    # score — each bucket takes the MAX of its rule-based score and the LLM's highest-
    # severity finding in that category, so a paraphrase the regex engine missed can still
    # surface the real risk, without double-counting when both systems agree.
    llm_bucket_peak = {b: 0 for b in LLM_BUCKETS}
    if llm.get("available"):
        for s in llm.get("signals", []):
            llm_bucket_peak[s["category"]] = max(llm_bucket_peak[s["category"]], LLM_SEVERITY_SCORE.get(s["severity"], 20))

    buckets = {
        "financial_claim": {"score": max(content.get("subScores", {}).get("financial_claim", 0), llm_bucket_peak["financial_claim"]), "available": content.get("available", False) or llm.get("available", False)},
        "urgency_manipulation": {"score": max(content.get("subScores", {}).get("urgency_manipulation", 0), llm_bucket_peak["urgency_manipulation"]), "available": content.get("available", False) or llm.get("available", False)},
        "credibility": {"score": max(content.get("subScores", {}).get("credibility", 0), llm_bucket_peak["credibility"]), "available": content.get("available", False) or llm.get("available", False)},
        "social_signal": {"score": max(social["score"], llm_bucket_peak["social_signal"]), "available": social["available"] or llm.get("available", False)},
        "url_risk": {"score": link.get("score", 0), "available": bool(link.get("available") and not link.get("blocked"))},
        "visual_tampering": {"score": ela["tamperScore"] if ela else 0, "available": ela is not None},
    }
    overall_score, confidence = fuse_all(buckets)
    if llm.get("available"):
        confidence = min(confidence + 4, 97)
    verdict = verdict_for(overall_score)
    v_label = verdict_label_for(overall_score)

    all_findings = []
    if content.get("available"):
        all_findings.extend(content["findings"])
    if link.get("available"):
        all_findings.extend(link_flag_to_finding(f) for f in link.get("flags", []))
    all_findings.extend(social["findings"])
    if ela:
        all_findings.append(ela_to_finding(ela))
    if llm.get("available"):
        all_findings.extend(llm.get("signals", []))
    all_findings.sort(key=lambda f: SEV_RANK.get(f["severity"], 1))

    financial_claims = build_financial_claims(content)
    contact_info = build_contact_info(entities)
    narrative = build_narrative(overall_score, v_label, confidence, all_findings, content, link, ela, entities, financial_claims, contact_info, llm)

    limitations = [
        "No live connection to SEBI's registry — registration-number and advisor-name checks are format/fuzzy-match against a small illustrative dataset, not the real ~1,300-entry registry.",
        "No vision-capable AI model is configured in this build — image understanding is real OCR text extraction plus rule-based and AI-assisted text analysis, not deep visual/contextual model reasoning.",
    ]
    if llm.get("available"):
        limitations.append(f"Text analysis is corroborated by an AI language model ({llm['model']} via Groq) alongside rule-based pattern matching — model reasoning is a second opinion, not an independently verified fact.")
    elif combined_text:
        limitations.append(f"AI-assisted semantic analysis was unavailable for this request ({llm.get('reason', 'unknown reason')}) — results rely on rule-based pattern matching only.")
    if image_bytes and not (ocr and ocr.get("available")):
        limitations.append(f"OCR could not run: {(ocr or {}).get('reason', 'unknown error')}.")
    if ocr and ocr.get("available") and ocr.get("lowConfidence"):
        limitations.append(f"OCR confidence was low ({ocr['confidence']}%) — extracted text may contain errors; verify against the original image.")
    if ela_error:
        limitations.append(f"Visual tampering analysis could not run: {ela_error}")
    elif ela:
        limitations.append("Visual tampering analysis (ELA) is a heuristic signal, not proof of editing — repeated recompression (e.g. many WhatsApp forwards) can also trigger it.")
    if link.get("available") and link.get("blocked"):
        limitations.append(f"Link could not be analyzed: {link.get('blockedReason')}")
    if link.get("available") and not link.get("blocked") and link.get("whois", {}).get("domainAgeDays") is None:
        limitations.append("Domain registration date could not be determined from WHOIS — shown as Not available rather than guessed.")

    result = {
        "id": str(uuid.uuid4())[:8],
        "submittedAt": datetime.now(timezone.utc).isoformat(),
        "elapsedMs": round((time.time() - t0) * 1000),
        "input": {"text": text or None, "url": url or None, "hasImage": bool(image_bytes), "imageName": image_name, "autoDetectedUrl": auto_detected_url},

        "overall_score": overall_score,
        "riskScore": overall_score,
        "confidence": confidence,
        "verdict": verdict,
        "verdict_label": v_label,

        "risk_breakdown": {name: {**b, "label": BUCKET_LABELS[name]} for name, b in buckets.items()},

        "summary": narrative["summary"],
        "key_findings": narrative["whyFlagged"],
        "narrative": narrative,
        "explanations": all_findings,
        "evidence": narrative["evidence"],

        "financial_claims": financial_claims,
        "extracted_text": combined_text or None,
        "ocr": ocr or {"available": False, "reason": "No image was submitted."},
        "extracted_entities": {**entities, **(content.get("entities", {}) if content.get("available") else {})},
        "urls": entities["urls"],
        "social_handles": entities["socialHandles"],
        "contact_information": contact_info,
        "urgency_signals": [f for f in (content.get("findings", []) if content.get("available") else []) if f["signal"] == SIGNAL_LABELS["urgency"]],
        "manipulation_signals": [f for f in (content.get("findings", []) if content.get("available") else []) if f["signal"] == SIGNAL_LABELS["fomo"]],
        "visual_tampering": ela or {"available": False, "reason": "No image was submitted." if not image_bytes else (ela_error or "Unavailable")},
        "url_analysis": link,
        "social_analysis": social,
        "ai_analysis": llm,

        "recommendations": narrative["recommendedAction"],
        "limitations": limitations,

        "modules": {
            "content": content,
            "link": link,
            "deepfake": {"available": False, "note": "No video/audio submitted, or a trained deepfake model isn't wired into this build."},
        },
        "reasons": all_findings,
        "domain": link.get("domain") if link.get("available") else None,
        "paymentHandles": extract_payment_handles(combined_text, link),
        "methodology": {
            "buckets": BUCKET_WEIGHTS,
            "content_weights": {c: w for c, w, _ in CONTENT_PATTERNS},
            "bands_3tier": {"GENUINE": "0–34", "SUSPICIOUS": "35–69", "FRAUDULENT": "70–100"},
            "bands_5tier": {"0-19": "Legitimate financial information", "20-39": "Potentially misleading promotion",
                            "40-59": "Suspicious investment promotion", "60-79": "Likely scam", "80-100": "Highly suspicious financial fraud"},
        },
    }
    HISTORY.append(result)
    return jsonify(result)


@app.route("/api/analyze/image", methods=["POST"])
def api_analyze_image_legacy():
    """Kept only for direct/standalone tamper-only checks; the main flow no longer needs a
    separate image step — /api/analyze now accepts an image alongside text/url in one call."""
    if "image" not in request.files:
        return jsonify({"error": "No image file uploaded (expected multipart field 'image')."}), 400
    file = request.files["image"]
    data = file.read()
    if len(data) > 12 * 1024 * 1024:
        return jsonify({"error": "Image too large (max 12MB)."}), 400
    try:
        result = error_level_analysis(data)
    except Exception as e:
        return jsonify({"error": f"Could not analyze image: {e}"}), 400
    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def api_history():
    nodes = []
    edges = []
    domain_index = {}
    handle_index = {}
    for h in HISTORY:
        nid = h["id"]
        label = (h["input"]["text"] or h["input"]["url"] or h["input"].get("imageName") or "submission")[:40]
        nodes.append({"id": nid, "type": "submission", "label": label, "risk": h["verdict"].lower(), "score": h["riskScore"]})
        dom = h.get("domain")
        if dom:
            key = f"domain:{dom}"
            if key not in domain_index:
                domain_index[key] = True
                nodes.append({"id": key, "type": "website", "label": dom, "risk": "info"})
            edges.append([nid, key])
        for handle in h.get("paymentHandles", []):
            key = f"upi:{handle}"
            if key not in handle_index:
                handle_index[key] = True
                nodes.append({"id": key, "type": "upi", "label": handle, "risk": "warning"})
            edges.append([nid, key])
    summary = [{"id": h["id"], "verdict": h["verdict"], "score": h["riskScore"],
                "submittedAt": h["submittedAt"],
                "label": (h["input"]["text"] or h["input"]["url"] or h["input"].get("imageName") or "")[:60]} for h in HISTORY]
    return jsonify({"history": summary, "network": {"nodes": nodes, "edges": edges}})


@app.after_request
def disable_caching(response):
    # A dev tool that gets iterated on quickly is exactly where a stale cached copy of
    # index.html silently keeps running old JS against a newer backend — turn caching
    # off entirely rather than relying on every client doing a hard refresh.
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
def root():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/favicon.ico")
def favicon():
    return "", 204


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)
