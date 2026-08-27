# Checkify

A multimodal fraud-analysis tool for investment scams — paste a message, a link, upload a screenshot, or any combination, and get an explainable fraud-risk report. Built for the MarketShield project (SIH26_106).

Every signal is computed live: real WHOIS lookups, real TLS handshakes, real Telegram/Instagram scraping, real OCR (Tesseract) on uploaded screenshots, and a rule-based scoring engine with a negation guard (so "does not guarantee returns" isn't flagged the same as "guarantees returns"). Nothing is looked up from a table of pre-written cases, and no external data (WHOIS, SSL, follower counts, registry status) is ever fabricated — unavailable signals are shown as "Not available," not guessed.

## What it does

- **Text analysis** — detects guaranteed-return language, urgency/FOMO pressure, unverified authority claims, and payment solicitation, with matched phrases highlighted inline.
- **Link analysis** — WHOIS domain age, TLS certificate info, redirect chains, URL shorteners, raw-IP destinations, homoglyph/punycode domain spoofing, and SEBI/NSE/BSE brand impersonation.
- **Telegram/Instagram** — scrapes public channel previews for subscriber counts, recent messages, and bot-inflated-audience detection (subscribers vs. actual engagement).
- **Screenshot analysis** — upload a promotional image or scam banner and it's OCR'd automatically (Tesseract) — no need to retype the text. Extracts financial claims, contact handles, URLs, and runs Error Level Analysis (ELA) for visual tampering signs.
- **Explainable scoring** — six risk buckets (financial claim, urgency/manipulation, credibility, social signal, URL, visual tampering) fused into an overall score with a documented formula, not a black box.
- **Human-readable report** — a narrative "why this was flagged / what the evidence shows / why it matters / recommended action" summary generated from the actual findings, plus a ready-to-file cybercrime.gov.in complaint draft.

## Setup

### 1. Install Tesseract OCR (required for screenshot analysis)

Screenshot analysis needs the Tesseract OCR *engine* installed separately from the Python package — it's a system binary, not something `pip` can install.

- **Windows**: `winget install UB-Mannheim.TesseractOCR` (the server looks for it at the default install path automatically)
- **macOS**: `brew install tesseract`
- **Linux**: `sudo apt install tesseract-ocr` (Debian/Ubuntu) or your distro's equivalent

If Tesseract isn't installed, everything else still works — screenshot uploads will just report OCR as unavailable instead of failing.

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Run

```bash
cd checkify
python server.py
```

Open **http://localhost:5000** in your browser. It must be opened through this URL, not by double-clicking `index.html` directly — the page calls a live backend and a `file://` address can't reach it.

## Project structure

```
checkify/
  server.py           Flask backend — all analysis logic
  static/index.html   Frontend (vanilla HTML/JS, no build step)
checkify-dashboard.html   Standalone offline demo with 3 illustrative cases
                          (no backend needed — useful as a fallback if you
                          can't run the live server during a demo)
```

## Known limitations

- No live connection to SEBI's real intermediary registry — advisor/registration checks run against a small illustrative dataset (~5 names), not the real ~1,300-entry list.
- No vision-capable AI model is wired in — image understanding is real OCR text extraction plus rule-based analysis, not deep visual/contextual model reasoning.
- No threat-intelligence API (VirusTotal, Google Safe Browsing) is connected — link risk uses structural heuristics (domain age, TLDs, redirects, homoglyphs) instead.
- ELA (tamper detection) is a statistical heuristic — it can read elevated on some untampered images (e.g. images recompressed many times over WhatsApp), so it's weighted accordingly in the overall score rather than treated as proof.
- Session history and the correlation graph are in-memory only and reset when the server restarts.
