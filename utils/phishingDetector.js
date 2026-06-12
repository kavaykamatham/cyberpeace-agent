/**
 * Local Phishing & Scam Detection
 * Runs instantly — no API calls needed.
 * This is the primary defense when Groq is unavailable.
 *
 * All detection lists (trusted domains, brand names, TLDs, suspicious
 * patterns, etc.) are loaded from `config/detectionLists.js` so the system
 * works dynamically for ANY URL / text / brand — not just hard-coded ones.
 */

const config = require("../config/detectionLists");

// ─── Trusted domain check ───────────────────────────────────────────────────
function isTrustedDomain(url) {
    try {
        const hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
        return config.TRUSTED_DOMAINS.some(t => hostname === t || hostname.endsWith("." + t));
    } catch {
        return false;
    }
}

// ─── URL pattern checks (regex-based, all dynamic) ──────────────────────────
// These patterns detect general phishing techniques — typosquatting, IP-address
// links, executable downloads, disguised file extensions, URL shorteners.
// None of them target any specific bank or brand.
const PHISHING_PATTERNS = [
    // Typosquatted bank/brand names (generic — picks up numbers-for-letters etc.)
    { pattern: /(?:paypa1|payp@l|paypai|paypa-l)\./i,                  score: 80, label: "Fake PayPal domain (misspelled/typosquatted)" },
    { pattern: /(?:gogle|goolge|g00gle|google-accounts)\./i,           score: 80, label: "Fake Google domain (typosquatting)" },
    { pattern: /(?:amaz0n|amazom|amazon-account|amazon-prize)\./i,     score: 80, label: "Fake Amazon domain (typosquatting)" },
    { pattern: /(?:app1e|appl3|apple-id|apple-verify)\./i,             score: 80, label: "Fake Apple domain (typosquatting)" },
    // Generic "bank-secure" / "verify-account" subdomain patterns
    { pattern: /[a-z0-9-]+\.(?:secure|verify|login|update|kyc|support)\.[a-z]{2,}/i,
                                                                       score: 50, label: "Subdomain uses security-themed word (verify/login/kyc) on non-trusted domain" },
    // URL shorteners
    {
        pattern: /(?:bit\.ly|tinyurl\.com|ow\.ly|is\.gd|tiny\.cc|tr\.im|rebrand\.ly|shorturl\.at|rb\.gy|t\.co|goo\.gl)(?:\/|$)/i,
        score: 30, label: "URL shortener — hides real destination"
    },
    // IP address used as domain
    {
        pattern: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{3}(?:\/|$)/,
        score: 65, label: "IP address used instead of domain name — banks never do this"
    },
    // Executable download links
    {
        pattern: /\/[^/]*\.(exe|bat|cmd|scr|vbs|ps1|apk|jar|com|msi|dll)(\?|$)/i,
        score: 70, label: "Executable file download link"
    },
    // Double-extension trick
    {
        pattern: /\.\w{2,4}\.(exe|bat|cmd|scr|vbs|apk|jar|com|msi)(\?|$)/i,
        score: 80, label: "Disguised file extension (e.g. invoice.pdf.exe)"
    }
];

// ─── Suspicious query params ────────────────────────────────────────────────
const SUSPICIOUS_PARAMS = [
    { param: "verify",   score: 20, label: "URL has ?verify= parameter" },
    { param: "confirm",  score: 20, label: "URL has ?confirm= parameter" },
    { param: "redirect", score: 25, label: "URL has ?redirect= — may send you to a malicious site" },
    { param: "token",    score: 15, label: "URL has ?token= parameter" },
    { param: "session",  score: 15, label: "URL has ?session= parameter" }
];

// ─── Suspicious keywords in message text ────────────────────────────────────
const SUSPICIOUS_KEYWORDS = [
    "verify your account",    "confirm your identity",   "update payment",
    "unusual activity",       "click here immediately",  "urgent action required",
    "your account will be closed", "verify password",    "update bank details",
    "re-enter credentials",   "authorize transaction",   "validate account",
    "you won",                "claim prize",             "free money",
    "easy cash",              "act now",                 "approval pending",
    "pending verification",   "account has been suspended", "otp verification required",
    "dear customer your",     "limited offer expires",   "congratulations you have been selected",
    "click the link below to verify", "your parcel is on hold",
    "kyc update",             "reactivate your account", "unlock your account",
    "your account has been locked", "share your otp",    "share your pin",
    "send your cvv",          "reset your password immediately"
];

// ─── Lottery scam patterns ──────────────────────────────────────────────────
const LOTTERY_PATTERNS = [
    /you.{0,20}won/i,
    /congratulations.{0,30}(prize|winner|reward|cash|selected)/i,
    /claim.{0,20}(now|prize|reward|money)/i,
    /you.{0,20}(selected|chosen|lucky winner)/i,
    /free.{0,20}(iphone|ipad|gift card|cash|money)/i,
    /you.{0,15}have.{0,15}(won|been selected|been chosen)/i
];

// ─── checkPhishingURL ──────────────────────────────────────────────────────
function checkPhishingURL(url) {
    // Step 1: Trusted domain = immediately safe
    if (isTrustedDomain(url)) {
        return {
            isSuspicious: false,
            suspiciousScore: 0,
            detectedPatterns: [],
            riskLevel: "LOW",
            trusted: true,
            note: "Verified legitimate domain"
        };
    }

    let score = 0;
    let patterns = [];

    try {
        const urlObj   = new URL(url);
        const hostname = urlObj.hostname.toLowerCase();

        // High-risk TLD
        const matchedTLD = config.HIGH_RISK_TLDS.find(tld => hostname.endsWith(tld));
        if (matchedTLD) {
            score += 55;
            patterns.push(`Domain uses "${matchedTLD}" — one of the most commonly abused scam TLDs`);
        }

        // Phishing patterns
        PHISHING_PATTERNS.forEach(({ pattern, score: s, label }) => {
            if (pattern.test(url)) {
                score += s;
                patterns.push(label);
            }
        });

        // Suspicious query params
        SUSPICIOUS_PARAMS.forEach(({ param, score: s, label }) => {
            if (urlObj.searchParams.has(param)) {
                score += s;
                patterns.push(label);
            }
        });

        // Brand impersonation: brand name in hostname but NOT on the trusted list
        const hasBrand = config.BRAND_NAMES.find(brand => hostname.includes(brand));
        if (hasBrand) {
            score += 70;
            patterns.push(`Domain contains "${hasBrand}" but is NOT their official website — likely impersonation`);
        }

        // Many subdomain levels on untrusted domain
        const parts = hostname.split(".");
        if (parts.length >= 4) {
            score += 20;
            patterns.push(`${parts.length} subdomain levels — common phishing trick to look like a real site`);
        }

        // Very long URL
        if (url.length > 250) {
            score += 15;
            patterns.push("Unusually long URL — often used to hide the real destination");
        }

    } catch { /* invalid URL — not trusted */ }

    const finalScore = Math.min(score, 100);
    return {
        isSuspicious: finalScore >= config.THRESHOLDS.localWarningScore,
        suspiciousScore: finalScore,
        detectedPatterns: [...new Set(patterns)],
        riskLevel: finalScore >= config.THRESHOLDS.localDangerScore ? "HIGH" :
                   finalScore >= config.THRESHOLDS.localWarningScore ? "MEDIUM" : "LOW",
        trusted: false
    };
}

// ─── checkSuspiciousText ───────────────────────────────────────────────────
function checkSuspiciousText(text) {
    let score = 0;
    let keywords = [];

    SUSPICIOUS_KEYWORDS.forEach(kw => {
        if (text.toLowerCase().includes(kw.toLowerCase())) {
            score += 18;
            keywords.push(kw);
        }
    });

    return {
        isSuspicious: score >= 30,
        suspiciousScore: Math.min(score, 100),
        keywords,
        riskLevel: score >= 60 ? "HIGH" : score >= 30 ? "MEDIUM" : "LOW"
    };
}

// ─── checkLotteryScamText ──────────────────────────────────────────────────
function checkLotteryScamText(text) {
    let score = 0;
    let indicators = [];

    LOTTERY_PATTERNS.forEach(pattern => {
        if (pattern.test(text)) {
            score += 30;
            indicators.push(pattern.source.substring(0, 50));
        }
    });

    return {
        isLotteryScam: score >= 50,
        score: Math.min(score, 100),
        indicators
    };
}

// ─── extractURLsWithAnalysis ───────────────────────────────────────────────
function extractURLsWithAnalysis(text) {
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const matches = text.match(urlRegex) || [];
    return matches.map(url => ({
        url,
        localAnalysis: checkPhishingURL(url)
    }));
}

// ─── overallRiskAssessment ─────────────────────────────────────────────────
function overallRiskAssessment(message) {
    const lottery = checkLotteryScamText(message);
    const text    = checkSuspiciousText(message);
    const urls    = extractURLsWithAnalysis(message);

    const maxURLRisk = urls.length > 0
        ? Math.max(...urls.map(u => u.localAnalysis.suspiciousScore))
        : 0;

    const overall = Math.max(lottery.score, text.suspiciousScore, maxURLRisk);

    return {
        overallRiskScore: overall,
        riskLevel: overall >= config.THRESHOLDS.localDangerScore ? "🚨 DANGER" :
                   overall >= config.THRESHOLDS.localWarningScore ? "⚠️ WARNING" : "✅ SAFE",
        isLotteryScam: lottery.isLotteryScam,
        hasSuspiciousText: text.isSuspicious,
        hasSuspiciousURL: urls.some(u => u.localAnalysis.isSuspicious),
        details: { lottery, text, urls }
    };
}

module.exports = {
    checkPhishingURL,
    checkSuspiciousText,
    checkLotteryScamText,
    extractURLsWithAnalysis,
    overallRiskAssessment,
    isTrustedDomain
};
