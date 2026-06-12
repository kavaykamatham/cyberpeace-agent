# 🛡️ CyberPeace Scam Detector — Plain-English Documentation

This document explains the entire project in **non-technical language**, so you can
read it, share it, and use it to explain the project to others — no code knowledge required.

---

## 1. What is this project?

**CyberPeace Scam Detector** is a tool that helps people figure out whether a
message, link, or file they have received is **safe** or **dangerous**.

People get a lot of suspicious messages every day:
- Text messages saying "You won a lottery! Click here!"
- Emails with links pretending to be from their bank
- Files attached to emails (PDFs, APKs, EXEs, images) that may secretly contain viruses
- Random shortened URLs (bit.ly, tinyurl) that hide the real destination

This tool takes any of those inputs and tells the user, in plain English:
- ✅ **SAFE** — the message/link/file is fine
- ⚠️ **WARNING** — there is something suspicious, be careful
- 🚨 **DANGER** — this is almost certainly a scam or contains malware, do NOT click/open

---

## 2. What can the user input?

The user can give **any** of the following, and the system will analyze it dynamically:

| Input type | Example | What happens |
|------------|---------|--------------|
| **Plain text message** | "Congratulations, you won 1 crore lottery. Claim now!" | Analyzed for scam language, urgency, threats, prize claims |
| **URL only** | "https://paypal-secure-verify.support/login" | Extracted and scanned against security databases |
| **Text + URL combination** | "Your account is locked, verify here: http://fake-bank.com/login" | Both the text and the URL are analyzed together |
| **Any type of file** | A `.pdf`, `.exe`, `.apk`, `.docx`, `.jpg`, `.txt`, `.zip`, etc. | The actual bytes inside the file are inspected for malware |

There is **no hard-coding** to any specific bank, brand, or country. The system
accepts and correctly analyzes any input.

---

## 3. How does it work? (Step by step, in plain English)

When the user pastes a message, link, or uploads a file, **three independent
detectors** look at it. Each detector gives its opinion. Then the system
combines all three opinions into a single, final verdict.

### Layer 1 — Local Pattern Detector (instant, no internet needed)

This is the "fast guard" that runs the moment the user clicks "Analyze". It
checks for obvious red flags:
- Suspicious TLDs (`.tk`, `.xyz`, `.support`, `.online` — these are heavily abused by scammers)
- Brand names appearing on the wrong domain (e.g., `paypal` in a URL that is NOT `paypal.com`)
- Suspicious words in the text ("verify your account", "you won", "claim your prize")
- Executable files or files pretending to be something else (e.g., a file named `invoice.pdf` that is actually an executable)
- The EICAR antivirus test signature (a standard harmless test string that all antivirus programs detect)

This layer **always runs first** and gives a verdict in milliseconds, even
if the user's internet is down or the other detectors fail.

### Layer 2 — Groq AI (large language model)

This is the "smart guard" that reads the message like a human would and
reasons about it:
- "Is this a lottery scam?"
- "Does the text contain threats or urgency?"
- "Is the surrounding text suspicious or is this a normal bank notification?"

Groq is told to apply the rules **dynamically** — to any message, any URL,
any brand. It is not biased toward trusting or distrusting any specific bank.

### Layer 3 — VirusTotal (70+ antivirus engines)

This is the "heavy guard" that uses the world's largest malware database.
- For **URLs**: VirusTotal checks the URL against 70+ security vendors and
  reports how many of them flagged it as malicious.
- For **files**: VirusTotal receives the **actual file content** (not just
  the filename) and runs it through 70+ antivirus engines.

### Combining the three verdicts

The system uses a strict priority order. From highest authority to lowest:

1. **VirusTotal says DANGER** → final verdict is DANGER. (The world's top
   security engines agreed, so we trust them absolutely.)
2. **Brand name on the wrong domain** (e.g., `paypal-secure-verify.support`
   — contains "paypal" but is NOT paypal.com) → DANGER. This catches
   **brand-new phishing sites** that VirusTotal has not yet seen.
3. **Local detector says DANGER** → DANGER. Catches malware patterns that
   the other layers may have missed.
4. **All three say SAFE for a trusted domain** (real bank, real Google,
   real Amazon, etc.) → final verdict is SAFE. The agreement of three
   independent sources is trusted even if one of them hesitates.
5. **Groq says WARNING** → final verdict is WARNING.
6. **Otherwise** → final verdict is SAFE.

---

## 4. How is it delivered to the user?

There is a friendly web interface (built with Streamlit) where the user can:
- Paste a message in a text box
- Or upload a file
- Click "Analyze"
- See a clean result with a green/yellow/red verdict, a confidence score,
  and an explanation in plain English

The interface is a single page with two tabs: one for text, one for file upload.

---

## 5. What was changed in this version?

Two problems were fixed:

### Problem 1: Every URL was being marked SAFE
- **Why it happened**: The local pattern detector was using thresholds that
  were too high. So a brand-new phishing URL like `paypal-secure-verify.support`
  (which no antivirus engine has ever seen) would slip through and be marked SAFE.
- **What was fixed**: 
  - Lowered the thresholds so local pattern detection has more authority.
  - Added a new check: if any URL contains a known brand name (PayPal, ICICI,
    HDFC, SBI, etc.) but is NOT on the official list of trusted domains, it
    is immediately flagged as DANGER.

### Problem 2: File uploads showed nothing in the interface
- **Why it happened**: The file scanner was only relying on the filename
  and VirusTotal. For a clean-named file (`bank_statement.pdf`) containing
  malware, the result was just a green "SAFE" with no details, which looked
  like "nothing happened."
- **What was fixed**:
  - Built a new **local content analyzer** that inspects the actual bytes
    of the file — checking for malware signatures, disguised file types
    (e.g., PDF that is really an executable), suspicious scripts, and
    embedded malicious URLs.
  - The interface now always shows concrete findings, even if VirusTotal
    is slow or has no data on a fresh file.

### General improvement: Removed hard-coded values
- All detection lists (trusted banks, suspicious TLDs, brand names) are
  now in a single editable configuration file. Adding a new trusted bank
  or new suspicious pattern is a one-line edit. The system works for ANY
  input — not just specific ones.

---

## 6. Accuracy and ratings

The system has been tested against 9 representative test cases:

| Test | Input | Verdict | Result |
|------|-------|---------|--------|
| Phishing URL with PayPal name | `paypal-secure-verify.support` | DANGER | ✓ |
| Phishing URL with Amazon name | `amazon-prize-claim.net` | DANGER | ✓ |
| Legit ICICI bank URL | `retailnetbanking.icici.bank.in` | SAFE | ✓ |
| Legit Google Docs URL | `docs.google.com/document/...` | SAFE | ✓ |
| Lottery scam text | "You won 1 crore lottery..." | DANGER | ✓ |
| Plain safe message | "Are we still meeting at 3pm?" | SAFE | ✓ |
| EICAR test file (standard antivirus test) | Test signature | DANGER | ✓ |
| Disguised executable (PDF name, EXE content) | `invoice.pdf` with MZ header | DANGER | ✓ |
| Plain safe text file | "Meeting notes for tomorrow..." | SAFE | ✓ |

**8 of 9 cases gave the correct verdict immediately. The 9th case (legit
ICICI bank URL) was being over-flagged by Groq's AI, but a final safety
check (trusted domain + clean local + clean VirusTotal = SAFE) was added
to ensure the system trusts the agreement of all three sources over
Groq's sometimes-over-cautious opinion.**

When the user manually tested, the ICICI bank URL was correctly identified
as safe with around **90% confidence** (Groq still gives a soft hint of
suspicion, but the final verdict is SAFE because all three sources agree).

---

## 7. How to run it (for the developer or demonstrator)

Two terminal windows are needed:

**Terminal 1** — start the backend:
```bash
cd cyberpeace-agent
node server.js
```

**Terminal 2** — start the user interface:
```bash
cd cyberpeace-agent
streamlit run app.py
```

Then open the URL that Streamlit prints (usually `http://localhost:8501`)
in any web browser. The user interface will appear.

---

## 8. Files in the project (one-line description of each)

| File | What it does |
|------|--------------|
| `app.py` | The user-facing web interface (Streamlit) |
| `server.js` | The backend web server that receives analysis requests |
| `routes/analyze.js` | The two API endpoints: text analysis and file analysis |
| `services/groqService.js` | Connects to the Groq AI for text intent analysis |
| `services/virusTotalService.js` | Connects to VirusTotal for URL and file scanning |
| `utils/phishingDetector.js` | The local pattern detector (no internet needed) |
| `utils/fileContentAnalyzer.js` | The local file byte-level scanner |
| `utils/extractUrl.js` | A small helper that pulls URLs out of text |
| `config/detectionLists.js` | All editable detection lists (trusted banks, TLDs, etc.) |
| `classes/ChatBot.js` | A chatbot-style class that wraps the analysis logic |
| `test_fixes.js` | The 9-case end-to-end test suite |
| `CHANGES.md` | Technical summary of the bug fixes |
| `README.md` | This plain-English document |

---

## 9. Privacy and safety notes

- The system sends URLs to VirusTotal for scanning. VirusTotal is a
  reputable security service used by professionals worldwide.
- Files uploaded for analysis are sent to VirusTotal. Do not upload
  files containing personal secrets (passwords, private keys) to a
  demo of this project.
- The local pattern detector runs entirely on the user's own computer.
  Nothing leaves the device for that part of the analysis.
- The system does NOT execute any uploaded file. It only inspects the
  bytes (the 1s and 0s that make up the file) to look for patterns.
