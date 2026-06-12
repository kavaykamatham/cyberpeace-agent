/**
 * Centralized configuration for all detection lists.
 *
 * WHY THIS FILE EXISTS:
 * Earlier the brand names, trusted domains, and TLDs were hard-coded inside
 * `routes/analyze.js`. This made it look like the system only worked for
 * specific banks (ICICI, HDFC, etc.) and not for any URL.
 *
 * By centralizing them here:
 *   1. The same lists are used by both the message analyzer and the file analyzer.
 *   2. You can edit one file to add a new bank, brand, or TLD — no code changes needed.
 *   3. None of these lists are tied to any specific input. The system dynamically
 *      checks EVERY URL/text/file against them.
 *
 * If you want to add a new trusted domain (e.g. your own company's domain),
 * just add it to TRUSTED_DOMAINS below and restart the server.
 *
 * If you want to add a new brand to watch for impersonation, add it to BRAND_NAMES.
 *
 * Everything here is "domain knowledge" — known-bad patterns, known-trusted
 * platforms, common phishing TLDs. It is NOT specific to any one user's input.
 */

module.exports = {
    // ─── Trusted domains (never flagged as brand impersonation) ───────────
    // Banks, big tech, file-sharing platforms, common services.
    // The system uses substring matching with `.` prefix, so adding
    // "mybank.com" automatically trusts "login.mybank.com" too.
    TRUSTED_DOMAINS: [
        // ICICI Bank
        "icici.bank.in", "icicibank.com",
        "retailnetbanking.icici.bank.in", "infinitynxt.icicibank.com",
        // HDFC
        "hdfcbank.com", "hdfc.bank.in", "netbanking.hdfcbank.com",
        // SBI
        "sbi.co.in", "onlinesbi.sbi", "sbi.bank.in",
        // Other Indian banks
        "axisbank.com", "axis.bank.in", "kotak.com", "netbanking.kotak.com",
        "yesbank.in", "pnbindia.in", "bankofbaroda.in", "canarabank.com",
        "unionbankofindia.co.in", "indianbank.in", "idfcfirstbank.com",
        // International / global
        "paypal.com", "paypal.me",
        "google.com", "accounts.google.com", "docs.google.com",
        "drive.google.com", "mail.google.com", "youtube.com",
        "microsoft.com", "live.com", "outlook.com", "office.com",
        "amazon.com", "amazon.in",
        "apple.com", "icloud.com",
        // Common safe platforms
        "github.com", "linkedin.com", "twitter.com", "x.com",
        "facebook.com", "instagram.com", "wikipedia.org",
        "stackoverflow.com", "reddit.com",
        // File sharing (legitimate platforms, file content is not scanned)
        "limewire.com", "wetransfer.com", "mega.nz", "mediafire.com",
        "dropbox.com", "onedrive.com"
    ],

    // ─── Brand names to watch for impersonation on UNTRUSTED domains ──────
    // If a URL contains any of these words but is NOT in TRUSTED_DOMAINS, it
    // is almost certainly phishing. The system checks the URL dynamically
    // against this list — adding a new brand here extends detection to it.
    BRAND_NAMES: [
        "paypal", "icici", "hdfc", "sbi", "axis", "kotak", "yesbank", "pnb",
        "google", "amazon", "apple", "microsoft", "netflix",
        "facebook", "instagram", "twitter", "whatsapp", "linkedin",
        "dhl", "fedex", "ups", "usps", "irs", "aadhaar", "pan",
        "coinbase", "binance", "metamask"
    ],

    // ─── High-risk TLDs (free/cheap and heavily abused for scams) ─────────
    HIGH_RISK_TLDS: [
        ".tk", ".ml", ".ga", ".cf", ".pw",        // Freenom freebies
        ".click", ".download", ".review",          // Action-oriented scam TLDs
        ".zip", ".mov",                            // File-extension TLDs
        ".support", ".online", ".site", ".win",    // Common in fake "support" scams
        ".gq", ".xyz"                              // Heavily abused free TLDs
    ],

    // ─── File-sharing platforms (platform is fine, file content unknown) ──
    FILE_SHARING_DOMAINS: [
        "limewire.com", "wetransfer.com", "mega.nz", "mediafire.com",
        "sendspace.com", "zippyshare.com", "4shared.com", "rapidshare.com",
        "uploaded.net", "depositfiles.com", "openload.co", "anonfiles.com",
        "gofile.io", "transfer.sh"
    ],

    // ─── Verdict thresholds (tunable, not hard-coded to any input) ────────
    THRESHOLDS: {
        localDangerScore:   55,   // local pattern score >= this → DANGER
        localWarningScore:  25,   // local pattern score >= this → WARNING
        groqHighConfidence: 70,   // Groq confidence >= this counts as DANGER
        groqMedConfidence:  40,   // Groq confidence >= this counts as WARNING
        filenameDanger:     70,   // filename risk score >= this → DANGER
        filenameWarning:    35,   // filename risk score >= this → WARNING
        vtMaliciousForDanger: 3,  // VT malicious count >= this → DANGER
        vtSuspiciousForWarn:  2   // VT suspicious count >= this → WARNING
    }
};
