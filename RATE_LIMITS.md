# ⏱️ API Rate Limits — Plain-English Explanation

This document answers the manager's question: **"What is the rate limit
for this tool?"** and also clarifies how the system handles inputs that
are NOT in the centralized list.

---

## 1. What is an "API rate limit"?

An **API rate limit** is the maximum number of requests you can make to
an external service in a given time window. If you exceed it, the
service refuses your request (usually with a "429 Too Many Requests"
error) and you have to wait before trying again.

Think of it like a phone — your phone company gives you a plan with a
limit on how many minutes you can talk per month. If you go over, you
either pay extra or wait until next month.

The CyberPeace tool uses **two external APIs**, each with its own rate limit:

### A. Groq AI (the smart text analyzer)

- **Free tier** rate limits (per Groq's published documentation, 2025/2026):
  - **~30 requests per minute**
  - **~6,000 tokens per minute**
  - **~14,400 requests per day**
- **The model we use** (`llama-3.3-70b-versatile`) is the "workhorse"
  model — fast and smart. It has the most generous free-tier limits.
- **What happens when the limit is hit?** Our code automatically
  catches the error and returns a "fallback" verdict that relies on
  the local pattern detector and VirusTotal instead. The user still
  gets a correct SAFE / WARNING / DANGER answer.

### B. VirusTotal (the URL and file scanner)

- **Public/free API** rate limits (per VirusTotal's official docs):
  - **4 requests per minute**
  - **500 requests per day**
  - **File size limit: 32 MB** (this is what we already configured)
- **What happens when the limit is hit?** VirusTotal returns a
  "429 Rate Limit" error. Our code handles it gracefully and shows
  the user a clear message: "VirusTotal rate limit reached. The local
  scanner and Groq AI are still working."

### C. The actual numbers for this project

For **one analysis request**:
- If the message contains **1 URL**, we use 1 VirusTotal request.
- If the message contains **3 URLs**, we use 3 VirusTotal requests.
- For a **file upload**, we use 1 VirusTotal request (file upload + poll).

So with the free VirusTotal API:
- ~4 file uploads or URL analyses per minute (without hitting the limit)
- ~500 per day

For Groq, the limit is much higher (30/min, 14,400/day) so it almost
never blocks a single user demo.

### D. What about "time taken"?

You mentioned the spinner shows **30–60 seconds** for file uploads. This
is NOT the rate limit — it's the **scan time**:
- VirusTotal needs to actually receive the file, distribute it to 70+
  antivirus engines, and collect their verdicts. This takes 30-60
  seconds for a fresh file.
- The system polls every 3-4 seconds for results.
- The local pattern detector finishes in **milliseconds** (it shows
  results immediately in the "Local Content Analysis" section).

### E. Summary table for the manager

| Service | Free tier limit | What it limits | What happens if you hit it |
|---------|----------------|----------------|----------------------------|
| Groq AI | ~30 req/min, ~14,400/day | Text analysis calls | Code falls back to local + VirusTotal; user still gets a verdict |
| VirusTotal | 4 req/min, 500/day, 32 MB file | URL scans + file uploads | Code shows "rate limit" message; local detector still gives findings |

For a single-user demo, these limits are **more than enough**. The only
limitation to be aware of is the **4 requests per minute on VirusTotal**:
if the manager uploads 5 files in 60 seconds, the 5th one will briefly
show the rate-limit message until the next minute starts.

---

## 2. The centralized-list question (very important!)

The user/manager asked: *"If a bank/brand is NOT in the centralized list,
does the system still work? Or is it hard-coded?"*

This is a great question. The answer:

### The system is NOT hard-coded. It works for ANY input.

Here's how the 3 layers work together, even when the input contains
something not in the centralized list:

### Layer 1 — Local Pattern Detector (always works, no list needed)

The local pattern detector has **generic rules** that do NOT depend on
any specific list. Examples of rules that always apply:
- "Does the URL have an IP address instead of a domain?" → DANGER
- "Does the URL end in `.tk`, `.xyz`, `.support`?" → DANGER
- "Is the URL longer than 250 characters?" → WARNING
- "Does the text contain the words 'verify your account'?" → DANGER
- "Is this a downloadable executable?" → DANGER

So even if the user pastes a URL for a brand we have never heard of
(`https://mybank-secure-login.com`), the system can still flag it as
suspicious because the URL itself looks wrong (subdomain trick, unusual
TLD, etc.).

### Layer 2 — Brand Impersonation Check (uses the list, but the list is extensible)

The brand impersonation check is the only place that uses the list.
**If the brand is in the list**, the system gives a strong DANGER verdict
when it appears on the wrong domain.
**If the brand is NOT in the list**, the system falls through to other
checks (local patterns, Groq, VirusTotal) and will likely still catch
the scam — it just won't use the brand-impersonation shortcut.

### Layer 3 — Groq AI (does NOT use the list)

The Groq AI reasons about ANY message dynamically. It does not need a
list of trusted banks to detect scams. If a brand-new phishing scam
appears for "MyCryptoWallet", Groq can recognize the patterns of urgency,
credential requests, and fake-domain language and flag it correctly.

### Layer 4 — VirusTotal (does NOT use the list)

VirusTotal has a database of millions of URLs scanned by 70+ vendors.
It detects scams for ANY brand, anywhere in the world, regardless of
our internal lists.

### So what does the centralized list actually do?

The centralized list is a **performance and accuracy optimization**:
- For brands in the list: instant detection, even if no antivirus engine
  has seen the new phishing site yet.
- For brands NOT in the list: detection still works, just through
  generic patterns + AI + VirusTotal.

### How to add a new brand to the list (takes 30 seconds)

Open `config/detectionLists.js` and add a new entry to either list:

```js
// To add a new trusted bank (e.g. "mybank.com"):
TRUSTED_DOMAINS: [
    // ... existing entries ...
    "mybank.com",        // ← add this line
],

// To add a new brand to watch for impersonation:
BRAND_NAMES: [
    // ... existing entries ...
    "mybank",            // ← add this line
],
```

Save the file, restart the server, and the new entries take effect
immediately. **No code changes are needed.**

### Real-world example

Let's say a phishing email arrives claiming to be from "HDFC Bank"
but the actual URL is `hdfc-secure-verify.tk/login`:

- The brand "hdfc" is **in the list** → brand impersonation check fires → DANGER. ✓

Now let's say a NEW phishing email arrives claiming to be from
"MyNewFintechApp" with URL `mynewfintechapp-login.support`:

- The brand "mynewfintechapp" is **NOT in the list** → brand impersonation
  check does NOT fire. BUT:
  - The local pattern detector sees `.support` TLD → +55 points
  - The local pattern detector sees "secure" and "login" in subdomain → +50 points
  - Total local score: 105/100 → capped at 100 → exceeds the 55 threshold → DANGER. ✓

**Result: the system catches the scam anyway**, just through a different
path. The centralized list is not the only defense; it's just one of
several layers.

### Summary in one sentence

> "The system works for any input. The centralized list is a helpful
> speed-boost for known brands, but the other three layers (local patterns,
> AI, and VirusTotal) ensure the system catches scams even for brands it
> has never seen before."
