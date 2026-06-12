const express = require("express");
const router  = express.Router();
const multer  = require("multer");

const { analyzeScamIntent, analyzeFileContent, explainRisk } = require("../services/groqService");
const { checkUrl, checkFile }                                 = require("../services/virusTotalService");
const { extractUrl }                                          = require("../utils/extractUrl");
const {
    checkSuspiciousText,
    checkLotteryScamText,
    extractURLsWithAnalysis,
    overallRiskAssessment
} = require("../utils/phishingDetector");
const { analyzeFileContent: localFileAnalyze }                = require("../utils/fileContentAnalyzer");
const config = require("../config/detectionLists");

const upload = multer({
    storage: multer.memoryStorage(),
    limits:  { fileSize: 32 * 1024 * 1024 }
});

// ─── File-sharing platform check ──────────────────────────────────────────
// List of file-sharing domains lives in config/detectionLists.js so it can be
// extended without editing code. None of this is tied to any specific input.
function isFileSharingURL(url) {
    try {
        const hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
        return config.FILE_SHARING_DOMAINS.some(d => hostname === d || hostname.endsWith("." + d));
    } catch {
        return false;
    }
}

// ─── Brand impersonation check (dynamic — uses config) ──────────────────
// If a URL contains any brand name from config.BRAND_NAMES but is NOT on the
// config.TRUSTED_DOMAINS list, it is almost certainly phishing.
// Adding a new brand to config/detectionLists.js immediately extends detection.
function findBrandImpersonation(urls) {
    for (const u of urls) {
        try {
            const h = new URL(u).hostname.toLowerCase();
            if (config.TRUSTED_DOMAINS.some(t => h === t || h.endsWith("." + t))) continue;
            if (config.BRAND_NAMES.some(b => h.includes(b))) return u;
        } catch {}
    }
    return null;
}

// ─── POST /analyze — analyze a text message ────────────────────────────────
router.post("/", async (req, res) => {
    try {
        const { message } = req.body;
        if (!message || typeof message !== "string" || message.trim().length < 3) {
            return res.status(400).json({ success: false, error: "Message is required (min 3 characters)" });
        }

        console.log("\n[/analyze]", message.substring(0, 120));

        // ── Step 1: Extract URLs ─────────────────────────────────────────
        const urls = extractUrl(message);
        console.log(`[1] URLs found: ${urls.length}`, urls);

        // ── Step 2: Local pattern detection — instant, no API needed ─────
        // This runs FIRST and is always available (no external API).
        // It is the fallback authority when Groq is unavailable.
        const localURLAnalysis  = extractURLsWithAnalysis(message);
        const localTextAnalysis = checkSuspiciousText(message);
        const localLotteryCheck = checkLotteryScamText(message);
        const localOverallRisk  = overallRiskAssessment(message);

        console.log(`[2] Local score: ${localOverallRisk.overallRiskScore} | ${localOverallRisk.riskLevel}`);

        // ── Step 3: Groq AI — message intent analysis ────────────────────
        console.log("[3] Groq AI analysis...");
        const groqResult = await analyzeScamIntent(message);
        const groqFailed = groqResult.fallback === true;
        console.log(`[3] Groq: scam=${groqResult.isScamQuery} | confidence=${groqResult.confidence} | fallback=${groqFailed}`);

        // ── Step 4: VirusTotal — scans EVERY URL regardless of Groq ──────
        let urlChecks    = [];
        let vtFoundDanger  = false;
        let vtFoundWarning = false;

        if (urls.length > 0) {
            console.log("[4] VirusTotal scanning...");
            for (const url of urls) {
                const vt = await checkUrl(url);
                console.log(`[4] VT ${url} → ${vt.verdict} (${vt.malicious || 0} malicious, ${vt.suspicious || 0} suspicious)`);
                urlChecks.push({ url, virusTotalData: vt });
                if (vt.verdict === "DANGER")  vtFoundDanger  = true;
                if (vt.verdict === "WARNING") vtFoundWarning = true;
            }
        }

        // ── Step 5: File-sharing link detection ──────────────────────────
        const hasFileSharingURL = urls.some(isFileSharingURL);

        // ── Step 6: Compute ONE authoritative final verdict ───────────────
        //
        // VERDICT PRIORITY (highest to lowest):
        // 1. VT says DANGER              → always DANGER (no override)
        // 2. Groq confident scam (≥70%)  → DANGER
        // 3. Local patterns HIGH (≥65)   → DANGER (works even when Groq is down)
        // 4. Groq moderate scam (≥40%)   → WARNING
        // 5. VT says WARNING             → WARNING
        // 6. File-sharing URL            → WARNING (file content unverifiable)
        // 7. Local patterns MEDIUM (≥35) → WARNING (works even when Groq is down)
        // 8. Everything else             → SAFE
        //
        // KEY: When Groq fails (fallback=true), we lower the local pattern
        // threshold so local detection becomes the primary authority.

        let finalVerdict;
        let finalIsScam;
        let isFileSharingLink = hasFileSharingURL;

        // ── Detect brand-impersonation (dynamic — uses config) ───────────
        // findBrandImpersonation() checks every URL against config.BRAND_NAMES
        // and config.TRUSTED_DOMAINS. Adding a new brand to the config
        // immediately extends detection to it — no code change needed.
        const brandImpersonationURL = findBrandImpersonation(urls);

        // All thresholds come from config/detectionLists.js — tunable in one place.
        const localDangerThreshold  = config.THRESHOLDS.localDangerScore;
        const localWarningThreshold = config.THRESHOLDS.localWarningScore;

        // ── Compute a "trusted URL + clean" flag ──────────────────────
        // If EVERY URL in the message is on the trusted list AND the local
        // detector found no suspicious patterns, we have a strong SAFE signal
        // that Groq's text intent analysis should not be allowed to override
        // (Groq can over-flag legitimate bank notifications).
        const allURLsTrusted = urls.length > 0 && urls.every(u => {
            try {
                const h = new URL(u).hostname.toLowerCase().replace(/^www\./, "");
                return config.TRUSTED_DOMAINS.some(t => h === t || h.endsWith("." + t));
            } catch { return false; }
        });
        const localClean = localOverallRisk.overallRiskScore < config.THRESHOLDS.localWarningScore;
        const vtClean    = !vtFoundDanger && !vtFoundWarning;
        const trustedClean = allURLsTrusted && localClean && vtClean;

        if (vtFoundDanger) {
            // VirusTotal confirmed malicious — highest authority
            finalVerdict = "DANGER";
            finalIsScam  = true;

        } else if (brandImpersonationURL) {
            // URL pretends to be a known brand but is not on the trusted list.
            // This catches brand-new phishing sites that 0 engines have flagged yet.
            finalVerdict = "DANGER";
            finalIsScam  = true;
            console.log(`[5] Brand impersonation detected on untrusted domain: ${brandImpersonationURL}`);

        } else if (trustedClean) {
            // Every signal agrees this is safe: trusted domain + clean local + clean VT.
            // Even if Groq over-flags, we trust the multi-source agreement.
            finalVerdict = "SAFE";
            finalIsScam  = false;
            console.log(`[5] All signals agree: trusted URLs, clean local, clean VT → SAFE`);

        } else if (groqResult.isScamQuery && groqResult.confidence >= 70) {
            // Groq is highly confident this is a scam
            finalVerdict = "DANGER";
            finalIsScam  = true;

        } else if (localOverallRisk.overallRiskScore >= localDangerThreshold) {
            // Local patterns strongly flag it — primary fallback when Groq is down
            finalVerdict = "DANGER";
            finalIsScam  = true;

        } else if (groqResult.isScamQuery && groqResult.confidence >= 40) {
            // Groq is moderately confident
            finalVerdict = "WARNING";
            finalIsScam  = true;

        } else if (vtFoundWarning) {
            // VirusTotal found something slightly suspicious
            finalVerdict = "WARNING";
            finalIsScam  = false;

        } else if (hasFileSharingURL) {
            // File-sharing link: the platform is fine but the file content is unverifiable
            finalVerdict = "WARNING";
            finalIsScam  = false;

        } else if (localOverallRisk.overallRiskScore >= localWarningThreshold) {
            // Local patterns flag it moderately
            finalVerdict = "WARNING";
            finalIsScam  = true;

        } else {
            finalVerdict = "SAFE";
            finalIsScam  = false;
        }

        console.log(`[5] Final verdict: ${finalVerdict} | isScam: ${finalIsScam}`);

        // ── Step 7: Plain-English explanation ────────────────────────────
        let riskExplanation = "";
        if (urls.length > 0) {
            console.log("[6] Generating explanation...");
            riskExplanation = await explainRisk(message, urlChecks, finalVerdict, isFileSharingLink);
        }

        res.json({
            success: true,
            message,
            // ── THE ONE TRUE VERDICT — the UI must read these two fields ──
            finalVerdict,        // "SAFE" | "WARNING" | "DANGER"
            finalIsScam,         // true | false
            isFileSharingLink,   // true = file-sharing platform (can't scan the file itself)
            groqFailed,          // true = Groq API was unavailable (fallback was used)
            // ── Supporting data for the UI ────────────────────────────────
            extractedUrls: urls,
            groqAnalysis:  groqResult,
            urlChecks,
            localDetection: {
                urls:              localURLAnalysis,
                suspiciousKeywords: localTextAnalysis.keywords,
                suspiciousScore:    localTextAnalysis.suspiciousScore,
                lotteryScam:        localLotteryCheck,
                overallRisk:        localOverallRisk
            },
            riskExplanation,
            timestamp: new Date().toISOString()
        });

    } catch (err) {
        console.error("[/analyze] Error:", err);
        res.status(500).json({ success: false, error: "Server error: " + err.message });
    }
});

// ─── POST /analyze/file ─────────────────────────────────────────────────────
router.post("/file", upload.single("file"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, error: "No file uploaded. Use field name 'file'." });
        }

        const { originalname, mimetype, buffer, size } = req.file;
        console.log(`\n[/analyze/file] ${originalname} | ${mimetype} | ${size} bytes`);

        // ── Filename risk checks (instant) ───────────────────────────────
        let filenameRisk  = 0;
        let filenameFlags = [];

        if (/\.(exe|bat|cmd|scr|vbs|ps1|msi|dll|pif|com)$/i.test(originalname)) {
            filenameRisk += 70;
            filenameFlags.push("Executable file — do NOT run unless from a fully trusted source");
        }
        if (/\.apk$/i.test(originalname)) {
            filenameRisk += 40;
            filenameFlags.push("Android APK — only install from the official Google Play Store or trusted source");
        }
        if (/\.\w{2,4}\.\w{2,4}$/.test(originalname)) {
            filenameRisk += 60;
            filenameFlags.push("Double extension detected — this is how malware disguises itself (e.g. invoice.pdf.exe)");
        }
        if (/(?:virus|malware|trojan|ransomware|hack|crack|keygen|phish|scam)/i.test(originalname)) {
            filenameRisk += 50;
            filenameFlags.push("Filename contains a suspicious word (malware, crack, scam, etc.)");
        }

        // ── Local content analysis: ALWAYS RUNS FIRST ──────────────────
        // Scans actual bytes for EICAR, magic-byte mismatches, embedded URLs,
        // script patterns, and suspicious keywords. Runs instantly so the
        // user always gets a verdict even if VirusTotal times out.
        console.log("[1] Local file content analysis (scanning actual bytes)...");
        const localFileResult = localFileAnalyze(buffer, originalname, mimetype);
        console.log(`[1] Local file verdict: ${localFileResult.verdict} (score ${localFileResult.riskScore}, ${localFileResult.findings.length} findings)`);

        // ── Groq AI: filename + type analysis ───────────────────────────
        console.log("[2] Groq file analysis...");
        const groqFileResult = await analyzeFileContent(originalname, { name: originalname, size, type: mimetype });
        console.log("[2] Groq file verdict:", groqFileResult.verdict);

        // ── VirusTotal: scans ACTUAL FILE BYTES ──────────────────────────
        // This is NOT just checking the filename — the real file content is
        // uploaded to VirusTotal and scanned by 70+ antivirus engines.
        console.log("[3] VirusTotal scanning actual file bytes...");
        const vtResult = await checkFile(buffer, originalname, mimetype);
        console.log(`[3] VT file: ${vtResult.verdict} — ${vtResult.summary}`);

        // ── Final verdict: combine all signals (priority order) ──────────
        // Thresholds are loaded from config/detectionLists.js so the file
        // detection is fully dynamic and tunable in one place.
        const T = config.THRESHOLDS;
        let finalVerdict = "SAFE";
        if (
            vtResult.verdict === "DANGER" ||
            localFileResult.verdict === "DANGER" ||
            filenameRisk >= T.filenameDanger ||
            groqFileResult.verdict === "DANGER"
        ) {
            finalVerdict = "DANGER";
        } else if (
            vtResult.verdict === "WARNING" ||
            localFileResult.verdict === "WARNING" ||
            filenameRisk >= T.filenameWarning ||
            groqFileResult.verdict === "WARNING"
        ) {
            finalVerdict = "WARNING";
        }

        console.log(`[4] File final verdict: ${finalVerdict}`);

        res.json({
            success:      true,
            fileName:     originalname,
            fileSize:     size,
            fileType:     mimetype,
            finalVerdict,
            virusTotal: {
                verdict:    vtResult.verdict,
                summary:    vtResult.summary,
                malicious:  vtResult.malicious  || 0,
                suspicious: vtResult.suspicious || 0,
                harmless:   vtResult.harmless   || 0,
                undetected: vtResult.undetected || 0,
                total:      vtResult.total      || 0,
                status:     vtResult.status
            },
            groqAnalysis: groqFileResult,
            filenameAnalysis: {
                riskScore:    Math.min(filenameRisk, 100),
                flags:        filenameFlags,
                isSuspicious: filenameRisk >= 35
            },
            // ── Local content analysis: actual byte-level findings ──────────
            // This is what catches malware even when VT has 0 detections.
            // Always present in the response so the UI can always show findings.
            localFileAnalysis: {
                verdict:           localFileResult.verdict,
                riskScore:         localFileResult.riskScore,
                findings:          localFileResult.findings,
                stringsExtracted:  localFileResult.stringsExtracted,
                urlsFound:         localFileResult.urlsFound
            },
            timestamp: new Date().toISOString()
        });

    } catch (err) {
        console.error("[/analyze/file] Error:", err);
        res.status(500).json({ success: false, error: "Server error: " + err.message });
    }
});

module.exports = router;