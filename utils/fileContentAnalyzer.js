/**
 * File Content Analyzer
 * Scans the actual BYTES of an uploaded file for malicious indicators.
 * This runs in ADDITION to VirusTotal so we always have a local verdict,
 * even when VT times out or has 0 detections on a fresh hash.
 *
 * Detects:
 *   - Embedded URLs (and checks them against the phishing detector)
 *   - Suspicious strings (URLs, IPs, executable headers, scripts)
 *   - EICAR test signature (the standard antivirus test string)
 *   - Suspicious keywords in any extracted text
 *   - Executable markers (MZ, PE, ELF, Mach-O)
 *   - Script/payload indicators (powershell, base64 blobs, etc.)
 */

const { checkPhishingURL, checkSuspiciousText } = require("./phishingDetector");

// ─── EICAR test signature (standard AV test, harmless but detected) ─────────
const EICAR_SIGNATURE = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

// ─── Executable file signatures ────────────────────────────────────────────
const EXECUTABLE_MARKERS = [
    { sig: Buffer.from([0x4D, 0x5A]), label: "Windows PE executable (MZ header)" },     // MZ
    { sig: Buffer.from([0x7F, 0x45, 0x4C, 0x46]), label: "Linux ELF executable" },     // ELF
    { sig: Buffer.from([0xFE, 0xED, 0xFA, 0xCE]), label: "Mach-O executable (32-bit)" }, // Mach-O
    { sig: Buffer.from([0xFE, 0xED, 0xFA, 0xCF]), label: "Mach-O executable (64-bit)" },
    { sig: Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]), label: "Mach-O universal binary" },
    { sig: Buffer.from([0x50, 0x4B, 0x03, 0x04]), label: "ZIP / Office document (OOXML)" }, // PK.. — also Office
    { sig: Buffer.from([0x25, 0x50, 0x44, 0x46]), label: "PDF document" },
    { sig: Buffer.from([0xFF, 0xD8, 0xFF]),     label: "JPEG image" },
    { sig: Buffer.from([0x89, 0x50, 0x4E, 0x47]), label: "PNG image" }
];

// ─── Suspicious script / payload indicators ─────────────────────────────────
const SUSPICIOUS_SCRIPT_PATTERNS = [
    { pattern: /powershell(?:\.exe)?\s+-e(?:ncodedCommand|nc)\s+/i, label: "Encoded PowerShell command (common malware technique)" },
    { pattern: /IEX\s*\(\s*New-Object\s+Net\.WebClient/i,            label: "PowerShell download cradle (downloads and runs remote code)" },
    { pattern: /cmd\.exe\s*\/c\s+[a-z]/i,                            label: "cmd.exe execution with arguments" },
    { pattern: /<script[^>]*src\s*=\s*["']https?:\/\/(?!(?:www\.)?(?:google|bing|yahoo|microsoft|apple|github)\.)/i, label: "External script tag pointing to untrusted source" },
    { pattern: /eval\s*\(\s*(?:atob|base64_decode|Buffer\.from\()/i,   label: "eval() of base64-decoded content (obfuscated payload)" },
    { pattern: /document\.write\s*\(\s*unescape\s*\(/i,               label: "document.write(unescape(...)) — classic obfuscation" },
    { pattern: /\b(?:nc|netcat|ncat)\s+-[a-z]*e\b/i,                  label: "Netcat reverse shell command" }
];

// ─── Extract printable strings from binary data (length >= 4) ───────────────
function extractStrings(buffer, minLength = 4) {
    const strings = [];
    let current = [];
    for (let i = 0; i < buffer.length; i++) {
        const byte = buffer[i];
        // printable ASCII range
        if (byte >= 0x20 && byte < 0x7F) {
            current.push(String.fromCharCode(byte));
        } else {
            if (current.length >= minLength) {
                strings.push(current.join(""));
            }
            current = [];
        }
    }
    if (current.length >= minLength) strings.push(current.join(""));
    return strings;
}

// ─── Extract URLs from arbitrary text/strings ──────────────────────────────
const URL_REGEX = /https?:\/\/[^\s<>"']+/gi;
function extractUrlsFromText(text) {
    return text.match(URL_REGEX) || [];
}

// ─── Main file analysis function ────────────────────────────────────────────
function analyzeFileContent(buffer, fileName, mimeType) {
    const findings = [];
    let riskScore   = 0;

    // ── 1. EICAR test signature (instant 100% detection, harmless) ───────
    if (buffer.includes(EICAR_SIGNATURE)) {
        findings.push("⚠️ EICAR test signature detected — this is the standard antivirus test string, used to verify AV works");
        riskScore += 100;
    }

    // ── 2. File-type marker check ─────────────────────────────────────────
    const head = buffer.subarray(0, 16);
    for (const { sig, label } of EXECUTABLE_MARKERS) {
        if (head.subarray(0, sig.length).equals(sig)) {
            findings.push(`File starts with magic bytes: ${label}`);
            // Executable types are inherently higher risk
            if (label.includes("executable") || label.includes("PE")) {
                riskScore += 30;
            }
            break; // only report the first marker
        }
    }

    // ── 3. Filename + MIME mismatch check ─────────────────────────────────
    if (fileName && mimeType) {
        const ext = (fileName.split(".").pop() || "").toLowerCase();
        const mime = (mimeType || "").toLowerCase();

        // Filename says .pdf but content starts with MZ? Classic malware trick.
        if (ext === "pdf" && head.subarray(0, 2).equals(Buffer.from([0x4D, 0x5A]))) {
            findings.push("🚨 Filename extension is .pdf but content is a Windows executable — this is a classic malware disguise technique");
            riskScore += 80;
        }
        if ((ext === "jpg" || ext === "png") && head.subarray(0, 2).equals(Buffer.from([0x4D, 0x5A]))) {
            findings.push("🚨 Image file extension but content is a Windows executable — malware disguise");
            riskScore += 80;
        }
        if (ext === "docx" && !head.subarray(0, 4).equals(Buffer.from([0x50, 0x4B, 0x03, 0x04]))) {
            findings.push("Filename says .docx but content is not a valid Office document");
            riskScore += 25;
        }
    }

    // ── 4. Extract strings and look for suspicious patterns ───────────────
    // Only do this for files up to 2 MB to keep things fast.
    let strings = [];
    if (buffer.length <= 2 * 1024 * 1024) {
        strings = extractStrings(buffer, 6);
    } else {
        findings.push(`File is large (${(buffer.length / 1024 / 1024).toFixed(1)} MB) — only magic bytes and URL scan performed`);
    }

    // ── 5. Scan for suspicious script patterns ────────────────────────────
    const allText = strings.join("\n");
    for (const { pattern, label } of SUSPICIOUS_SCRIPT_PATTERNS) {
        if (pattern.test(allText)) {
            findings.push(`🚨 ${label}`);
            riskScore += 50;
        }
    }

    // ── 6. Extract and analyze any embedded URLs ──────────────────────────
    const embeddedUrls = extractUrlsFromText(allText);
    if (embeddedUrls.length > 0) {
        findings.push(`Found ${embeddedUrls.length} URL(s) inside the file content`);
        for (const u of embeddedUrls.slice(0, 10)) {  // cap at 10
            const urlCheck = checkPhishingURL(u);
            if (urlCheck.isSuspicious) {
                findings.push(`🚨 Suspicious URL embedded in file: ${u} (score ${urlCheck.suspiciousScore})`);
                riskScore += Math.min(urlCheck.suspiciousScore, 60);
            }
        }
    }

    // ── 7. Suspicious keywords in extracted text ──────────────────────────
    if (allText.length > 0) {
        const textCheck = checkSuspiciousText(allText);
        if (textCheck.isSuspicious) {
            findings.push(`Suspicious keywords found in file content: ${textCheck.keywords.slice(0, 5).join(", ")}`);
            riskScore += textCheck.suspiciousScore;
        }
    }

    // ── 8. Cap the score ──────────────────────────────────────────────────
    riskScore = Math.min(riskScore, 100);

    return {
        riskScore,
        findings,
        verdict:   riskScore >= 65 ? "DANGER" : riskScore >= 30 ? "WARNING" : "SAFE",
        stringsExtracted: strings.length,
        urlsFound: embeddedUrls.length,
        fileSize: buffer.length
    };
}

module.exports = { analyzeFileContent, extractStrings, extractUrlsFromText };
