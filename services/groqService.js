const Groq = require("groq-sdk");
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// ─── FALLBACK — fired when Groq API is down/rate-limited ───────────────────
// CRITICAL: fallback = true so analyze.js knows to rely more heavily on
// local pattern checks and VirusTotal instead of Groq's opinion.
const FALLBACK_SCAM = {
    isScamQuery: false,
    scamTypes: [],
    confidence: 0,
    riskLevel: "unknown",
    reason: "AI analysis temporarily unavailable. VirusTotal and local pattern checks are still running.",
    fallback: true   // ← analyze.js uses this flag to lower the verdict threshold
};

const FALLBACK_FILE = {
    verdict: "WARNING",
    risk_score: 50,
    reasons: ["AI file analysis temporarily unavailable."],
    recommendations: ["Scan this file with your local antivirus before opening."],
    fallback: true
};

const FALLBACK_EXPLAIN = (finalVerdict) => {
    if (finalVerdict === "DANGER")
        return "⚠️ This message or URL was flagged as dangerous by our security scanners. Do NOT click any links or provide any personal information.";
    if (finalVerdict === "WARNING")
        return "⚠️ This content raised some security concerns. Proceed with caution and verify the source before clicking anything.";
    return "This content appears safe based on automated checks. AI explanation is temporarily unavailable.";
};

function safeParseJSON(raw) {
    if (!raw) return null;
    try { return JSON.parse(raw); } catch {}
    const match = raw.match(/\{[\s\S]*\}/);
    if (match) { try { return JSON.parse(match[0]); } catch {} }
    return null;
}

function logGroqError(err, fn) {
    const s = err?.status || err?.response?.status;
    if (s === 429) console.error(`[Groq/${fn}] Rate limit hit (429) — using fallback`);
    else if (s === 401) console.error(`[Groq/${fn}] Bad API key (401) — check GROQ_API_KEY in .env`);
    else console.error(`[Groq/${fn}] Error:`, err.message);
}

// ─── analyzeScamIntent ──────────────────────────────────────────────────────
// Reads the MESSAGE TEXT for scam language, urgency, threats, prize claims.
// Does NOT decide URL safety — that is VirusTotal's job.
async function analyzeScamIntent(message) {
    try {
        const res = await groq.chat.completions.create({
            model: "llama-3.3-70b-versatile",
            temperature: 0,
            messages: [
                {
                    role: "system",
                    content: `You are a cybersecurity expert who detects scam messages.

YOUR JOB: Analyze the MESSAGE TEXT for scam indicators — urgency, threats, prize claims, fake domain names, requests for credentials.
VirusTotal handles URL scanning separately. Your job is text intent analysis.
Be DYNAMIC — apply these rules to ANY message, ANY URL, ANY brand, ANY bank. Do not assume any specific domain is safe or unsafe by name; reason about the structure of the message.

══════════════════════════════════════════════
GENERAL RULE: a message is SAFE only if it has NO scam indicators
══════════════════════════════════════════════
• Pure neutral messages (meeting reminders, hello, etc.) with no link or a link to a well-known platform
• A bare URL with no urgency, no prize claim, no threat, no credential request, and no suspicious language around it
  → isScamQuery: false (low confidence, e.g. 0-20)
• DO NOT auto-trust any specific bank domain. Banks can be impersonated. If the surrounding text is suspicious, flag it.

══════════════════════════════════════════════
ALWAYS MARK SCAM — isScamQuery: true
══════════════════════════════════════════════
1. LOTTERY / PRIZE SCAM (confidence: 90+)
   "You won", "Congratulations you are selected", "Claim your reward", "You have been chosen"

2. URGENT THREAT + LINK (confidence: 85+)
   "Your account is suspended, verify now", "Click immediately or lose access"

3. OTP / CREDENTIAL REQUEST (confidence: 95+)
   "Enter your OTP here", "Share your PIN", "Give your CVV/password"

4. FAKE DOMAIN impersonating real brand (confidence: 85+)
   paypal-secure-verify.support      ← NOT paypal.com
   icici-netbanking-login.xyz         ← NOT icici.bank.in
   hdfc-secure-banking.online         ← NOT hdfcbank.com
   sbi-kyc-update.tk                  ← NOT sbi.co.in
   amazon-prize-claim.net             ← NOT amazon.com

5. IP ADDRESS links (confidence: 80+)
   http://192.168.1.1/login, http://45.33.32.156/verify

6. URL shorteners + prize/urgency language (confidence: 75+)
   "You won! Claim: bit.ly/xxxxx"

══════════════════════════════════════════════
SCAM TYPE VALUES
══════════════════════════════════════════════
Use exactly these strings (or empty array if none):
"lottery_scam" | "phishing" | "banking_fraud" | "urgency_tactics" |
"impersonation" | "credential_harvesting" | "suspicious_link"

Return ONLY valid JSON. No markdown. No extra text:
{
  "isScamQuery": true or false,
  "scamTypes": [],
  "confidence": 0-100,
  "reason": "one specific sentence explaining exactly what triggered this verdict",
  "riskLevel": "high" | "medium" | "low" | "none"
}`
                },
                { role: "user", content: message }
            ]
        });

        const raw = res.choices[0]?.message?.content || "";
        const parsed = safeParseJSON(raw);
        if (!parsed || typeof parsed.isScamQuery !== "boolean") {
            console.error("[Groq/analyzeScamIntent] Bad response:", raw.substring(0, 200));
            return FALLBACK_SCAM;
        }
        return parsed;

    } catch (err) {
        logGroqError(err, "analyzeScamIntent");
        return FALLBACK_SCAM;
    }
}

// ─── analyzeFileContent ─────────────────────────────────────────────────────
async function analyzeFileContent(filename, fileMetadata) {
    try {
        const res = await groq.chat.completions.create({
            model: "llama-3.3-70b-versatile",
            temperature: 0,
            messages: [
                {
                    role: "system",
                    content: `You are a cybersecurity expert analyzing uploaded files for threats.

Apply these rules DYNAMICALLY based on the actual file metadata, regardless of brand, language, or user.
Do NOT trust any specific extension or filename just because it looks "common" — reason about what the file actually is.

HIGH RISK file extensions — almost always DANGER (executable code):
.exe .bat .cmd .scr .vbs .ps1 .msi .dll .pif .com .jar

MEDIUM RISK — WARNING (could contain hidden malware or be a malicious app):
.apk (Android app — malicious unless from official store)
.zip .rar .7z .tar .gz (archives that may hide executables)
Double extension: photo.jpg.exe, invoice.pdf.bat (disguised malware — DANGER)
Shortcut/script files: .lnk, .iso, .img

SUSPICIOUS filenames regardless of extension (DANGER):
Contains any of: virus, malware, trojan, ransomware, hack, crack, keygen, phish, scam, free_prize, warez, exploit, payload, backdoor, stealer, rat_

USUALLY SAFE (but still verify — never auto-trust):
.pdf .docx .xlsx .pptx .odt .jpg .jpeg .png .gif .bmp .webp
.mp4 .mkv .mov .avi .mp3 .wav .flac
.txt .csv .json .log .md

Return ONLY valid JSON, no markdown:
{
  "verdict": "SAFE" or "WARNING" or "DANGER",
  "risk_score": 0-100,
  "reasons": ["one specific finding"],
  "recommendations": ["what the user should do next"]
}`
                },
                {
                    role: "user",
                    content: `Filename: ${filename}\nMetadata: ${JSON.stringify(fileMetadata)}`
                }
            ]
        });

        const parsed = safeParseJSON(res.choices[0]?.message?.content || "");
        return parsed || FALLBACK_FILE;

    } catch (err) {
        logGroqError(err, "analyzeFileContent");
        return FALLBACK_FILE;
    }
}

// ─── explainRisk ────────────────────────────────────────────────────────────
async function explainRisk(userMessage, urlChecks, finalVerdict, isFileSharingLink = false) {
    // File-sharing links: hardcoded clear warning, no need to call Groq
    if (isFileSharingLink) {
        return "⚠️ This is a file-sharing link. The platform itself is not flagged as malicious by any security engine. However, the actual FILE behind this link cannot be scanned without downloading it. Windows Defender and other antivirus tools will warn you when you try to download if the file is dangerous — trust that warning and do not override it. Only download if you personally know and trust who sent you this link.";
    }

    try {
        const vtSummary = urlChecks.map(c => {
            const vt = c.virusTotalData || {};
            return `URL: ${c.url} | Malicious: ${vt.malicious || 0} | Suspicious: ${vt.suspicious || 0} | Total engines: ${vt.total || 0}`;
        }).join("\n");

        const res = await groq.chat.completions.create({
            model: "llama-3.3-70b-versatile",
            messages: [
                {
                    role: "system",
                    content: `You are a cybersecurity assistant writing a plain-English explanation for a non-technical user.
Write 2-3 sentences maximum. Be direct and specific. Always end with ONE concrete action.

Rules:
- DANGER verdict → clearly warn, tell them do NOT click/open/download
- WARNING verdict → explain the specific concern, advise caution
- SAFE verdict with real bank domain + 0 VT flags → explicitly confirm it is safe
- SAFE verdict with 0 VT flags → confirm safe, briefly mention what was checked
- Never be vague. Be specific about what was found or not found.`
                },
                {
                    role: "user",
                    content: `Message: "${userMessage}"\nFinal verdict: ${finalVerdict}\nVirusTotal data:\n${vtSummary || "No URLs scanned"}`
                }
            ]
        });

        return res.choices[0]?.message?.content || FALLBACK_EXPLAIN(finalVerdict);

    } catch (err) {
        logGroqError(err, "explainRisk");
        return FALLBACK_EXPLAIN(finalVerdict);
    }
}

module.exports = { analyzeScamIntent, analyzeFileContent, explainRisk };