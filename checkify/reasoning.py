"""
Deterministic reasoning layer for Checkify: evidence polarity, protective-signal
detection, and structural content-type classification.

R1 (this whole module): negation/polarity is decided by dependency-parse rules with
zero LLM involvement, so the same input always yields the same polarity. This is the
fix for the reported false-positive bug: "We do not promise guaranteed returns" and
"guaranteed 10x profit" both contain the word "guaranteed", but only a syntactic
negation scope (not a keyword window) can tell them apart — and only a syntactic scope
correctly keeps "We do not promise guaranteed returns. Pay now for guaranteed 10x
profit." from having the first sentence's negation bleed into the second.

Nothing here is keyed to a specific screenshot, company, domain, or registration
number — the rules operate on grammatical structure (dependency labels, sentence
boundaries, subtrees), so they generalize to text this system has never seen.
"""

import re

try:
    import spacy
    _NLP = spacy.load("en_core_web_sm")
    SPACY_AVAILABLE = True
    SPACY_UNAVAILABLE_REASON = None
except Exception as e:  # pragma: no cover - exercised only if spaCy/model missing
    _NLP = None
    SPACY_AVAILABLE = False
    SPACY_UNAVAILABLE_REASON = f"spaCy unavailable ({e}); falling back to a fixed-window negation heuristic."

# --------------------------------------------------------------------------- polarity

POSITIVE_RISK = "POSITIVE_RISK"
NEGATED = "NEGATED"
CAUTIONARY = "CAUTIONARY"
NEUTRAL_MENTION = "NEUTRAL_MENTION"
PROTECTIVE = "PROTECTIVE"
REPORTED_THIRD_PARTY = "REPORTED_THIRD_PARTY"
UNKNOWN = "UNKNOWN"

NEGATING_VERB_LEMMAS = {"avoid", "refrain", "deny", "prevent", "stop", "prohibit", "ban"}
SELF_REFERENCE_LEMMAS = {"we", "i", "us", "our"}
WARNING_VERB_LEMMAS = {"beware", "warn", "flag", "watch"}
THIRD_PARTY_LEMMAS = {"anyone", "someone", "people", "scammer", "fraudster", "caller", "person", "scheme", "scam", "they"}
SAYING_VERB_LEMMAS = {"say", "tell", "claim", "state", "mention"}
RETROSPECTIVE_MARKERS = re.compile(r"\b(was|were|had\s+been|last\s+(year|quarter|month)|historically|in\s+FY\s?\d{2,4}|previously)\b", re.I)
PROMISSORY_MARKERS = re.compile(r"\b(will|guarantee[ds]?|assured|sure[- ]?shot|fixed|in\s+\d{1,3}\s+(days?|hours?|weeks?)|daily|monthly|by\s+tomorrow|within\s+\d)\b", re.I)


def _ancestor_chain(token):
    node = token
    seen = set()
    chain = []
    while node.i not in seen:
        seen.add(node.i)
        chain.append(node)
        if node.dep_ == "ROOT":
            break
        node = node.head
    return chain


def _has_neg_child(node):
    return any(child.dep_ == "neg" for child in node.children)


def _nsubj_of(node):
    return next((c for c in node.children if c.dep_ == "nsubj"), None)


def classify_polarity_spacy(doc, start, end):
    span = doc.char_span(start, end, alignment_mode="expand")
    if span is None:
        return UNKNOWN
    chain = _ancestor_chain(span.root)

    for node in chain:
        if _has_neg_child(node):
            return NEGATED
        if node.dep_ == "pcomp" and node.head.lemma_.lower() == "without":
            return NEGATED
        if node.lemma_.lower() in NEGATING_VERB_LEMMAS:
            subj = _nsubj_of(node)
            if subj is None or subj.lemma_.lower() in SELF_REFERENCE_LEMMAS:
                return NEGATED

    # Reported speech is checked before the generic cautionary check: "They said they
    # guarantee returns" has "they" as the subject of the claim verb itself (ccomp of a
    # saying verb), which is a different structure from "anyone" appearing as the
    # subject of a clause modifying/warned-about via an imperative or conditional
    # ("If anyone promises X, report them" — advcl, not ccomp of a saying verb). Checking
    # ccomp/xcomp-under-a-saying-verb first keeps the two from being conflated.
    for node in chain:
        if node.dep_ in ("ccomp", "xcomp"):
            head = node.head
            if head.lemma_.lower() in SAYING_VERB_LEMMAS:
                subj = _nsubj_of(head)
                if subj is not None and subj.lemma_.lower() not in SELF_REFERENCE_LEMMAS:
                    return REPORTED_THIRD_PARTY

    for node in chain:
        if node.lemma_.lower() in WARNING_VERB_LEMMAS:
            return CAUTIONARY
        subj = _nsubj_of(node)
        if subj is not None and subj.lemma_.lower() in THIRD_PARTY_LEMMAS:
            return CAUTIONARY
        if node.dep_ in ("acl", "relcl") and node.head.lemma_.lower() in THIRD_PARTY_LEMMAS:
            return CAUTIONARY

    return POSITIVE_RISK


# Fallback only used if spaCy/the model failed to load at all — a plain, honestly-
# labeled degraded mode (R1 still requires determinism, which a fixed window satisfies,
# just with less precision than a real dependency parse).
_FALLBACK_NEGATION_RE = re.compile(
    r"\b(not|no|never|without|do\s+not|does\s+not|don.?t|won.?t|cannot|can.?t|refrain|deny|denies)\b", re.I)
_FALLBACK_WARNING_RE = re.compile(r"\b(beware|warn(ing)?|watch\s+out|careful|report\s+(fake|fraudulent))\b", re.I)


def classify_polarity_fallback(text, start, end):
    sentence_start = text.rfind(".", 0, start)
    sentence_start = sentence_start + 1 if sentence_start != -1 else 0
    window = text[sentence_start:start]
    if _FALLBACK_WARNING_RE.search(window):
        return CAUTIONARY
    if _FALLBACK_NEGATION_RE.search(window):
        return NEGATED
    return POSITIVE_RISK


def classify_polarity(text, doc, start, end):
    if SPACY_AVAILABLE and doc is not None:
        return classify_polarity_spacy(doc, start, end)
    return classify_polarity_fallback(text, start, end)


def is_retrospective_pct_mention(window_text):
    """A bare 'returns were 8% last year' is a factual, backward-looking statement —
    not a claim structure — so it should not contribute risk even though it contains a
    percentage next to a profit word. Only promissory/forward-looking framing counts."""
    has_retro = bool(RETROSPECTIVE_MARKERS.search(window_text))
    has_promissory = bool(PROMISSORY_MARKERS.search(window_text))
    return has_retro and not has_promissory


def get_doc(text):
    if not SPACY_AVAILABLE or not text:
        return None
    try:
        return _NLP(text)
    except Exception:
        return None


# --------------------------------------------------------------------------- protective signals (Part F)
# Matched directly — these are the reader's/sender's own protective statements, not a
# negation of some other risk phrase, so they don't go through classify_polarity.

PROTECTIVE_PATTERNS = [
    ("no_guarantee_disclaimer", "No-guarantee disclaimer", [
        r"\bwe\s+do\s+not\s+(promise|guarantee)\b", r"\bno\s+guarantee\s+(of|is\s+made)\b",
        r"\bcannot\s+guarantee\b",
    ]),
    ("risk_disclosure", "Standard risk disclosure", [
        r"\bsubject\s+to\s+market\s+risks?\b", r"\bpast\s+performance\s+does\s+not\s+guarantee\b",
        r"\binvestments?\s+(involve|carry|are\s+subject\s+to)\s+risks?\b",
    ]),
    ("official_channel_instruction", "Official-channel instruction", [
        r"\b(official|verified)\s+(website|channel|app)\s+only\b",
        r"\bverify\s+(through|via|on)\s+(the\s+)?official\b",
    ]),
    ("no_personal_transfer_warning", "Warning against personal-account transfer", [
        r"\bnever\s+transfer\b[^.?!]{0,40}\bpersonal\b", r"\bdo\s+not\s+(pay|transfer|send)\b[^.?!]{0,40}\bpersonal\s+account\b",
        r"\bwe\s+will\s+never\s+ask\s+(you\s+)?for\s+(your\s+)?(otp|password|pin)\b",
    ]),
    ("educational_framing", "Educational framing", [
        r"\bfor\s+educational\s+(purposes?|discussion)\b", r"\bnot\s+(investment\s+)?advice\b",
        r"\bmarket\s+(note|commentary)\s+for\b",
    ]),
    ("impersonation_warning", "Impersonation warning", [
        r"\bbeware\s+of\s+(fake|fraudulent|impersonators?)\b", r"\bwe\s+do\s+not\s+(have|run)\s+(any\s+)?(telegram|whatsapp)\s+group\b",
        r"\breport\s+(fake|fraudulent)\s+(accounts?|profiles?|channels?)\b",
    ]),
]


def match_protective(text):
    """One protective *signal* (e.g. 'risk_disclosure') should count once per occurrence
    even if more than one of its own patterns matches overlapping text — otherwise the
    same sentence gets displayed and scored as if two disclaimers were present."""
    raw = []
    for pid, label, patterns in PROTECTIVE_PATTERNS:
        for pat in patterns:
            for m in re.finditer(pat, text, re.I):
                raw.append({"id": pid, "label": label, "evidence": text[m.start():m.end()], "start": m.start(), "end": m.end()})
    raw.sort(key=lambda f: (f["start"], -(f["end"] - f["start"])))
    findings = []
    last_end_by_id = {}
    for f in raw:
        if f["start"] >= last_end_by_id.get(f["id"], -1):
            findings.append(f)
            last_end_by_id[f["id"]] = f["end"]
    return findings


# --------------------------------------------------------------------------- content-type classification (Part C)

FINANCIAL_RESEARCH = "FINANCIAL_RESEARCH"
EDUCATIONAL_CONTENT = "EDUCATIONAL_CONTENT"
MARKET_COMMENTARY = "MARKET_COMMENTARY"
LEGITIMATE_FINANCIAL_COMMUNICATION = "LEGITIMATE_FINANCIAL_COMMUNICATION"
INVESTMENT_PROMOTION = "INVESTMENT_PROMOTION"
HIGH_PRESSURE_PROMOTION = "HIGH_PRESSURE_PROMOTION"
SOLICITATION_WITH_PAYMENT_REQUEST = "SOLICITATION_WITH_PAYMENT_REQUEST"
CONTENT_UNKNOWN = "UNKNOWN"

PAYMENT_REQUEST_RE = re.compile(
    r"\bpay\s+(now|immediately|to\s+join|to\s+start|rs\.?|₹|inr)\b|\b(send|transfer|deposit)\s+(money|funds|payment)\b|\bupi\b|[\w.\-]+@(?:ok\w{2,6}|ybl|paytm|apl|ibl)\b",
    re.I)
QUANTIFIED_PROMISE_RE = re.compile(r"\b\d{1,4}\s?(?:%|percent|per\s?cent|x)\b|\bdouble\b|\btriple\b", re.I)
URGENCY_RE = re.compile(r"\b(act\s+(now|fast)|limited\s+(time|slots?|seats?)|hurry|last\s+chance|today\s+only)\b", re.I)
TARGET_PRICE_RE = re.compile(r"\btarget\s+price\b|\bbuy\s+at\s+\d|\bstop\s?loss\b", re.I)
EDUCATIONAL_RE = re.compile(r"\bfor\s+educational\s+(purposes?|discussion)\b|\bnot\s+(investment\s+)?advice\b", re.I)


def classify_content_structural(text, has_payment_request, has_quantified_promise, has_urgency):
    """Fallback AND ceiling for the LLM refinement below — an LLM may relabel within
    what the structure allows, but per R2/Part C it can never override a payment
    request into something softer than SOLICITATION_WITH_PAYMENT_REQUEST."""
    if has_payment_request:
        return SOLICITATION_WITH_PAYMENT_REQUEST
    if has_quantified_promise and has_urgency:
        return HIGH_PRESSURE_PROMOTION
    if has_quantified_promise or TARGET_PRICE_RE.search(text):
        return INVESTMENT_PROMOTION
    if EDUCATIONAL_RE.search(text):
        return EDUCATIONAL_CONTENT
    if TARGET_PRICE_RE.search(text) or re.search(r"\bresearch\s+(note|report)\b", text, re.I):
        return FINANCIAL_RESEARCH
    if re.search(r"\bmarket\s+(view|outlook|commentary)\b", text, re.I):
        return MARKET_COMMENTARY
    if text.strip():
        return LEGITIMATE_FINANCIAL_COMMUNICATION
    return CONTENT_UNKNOWN
