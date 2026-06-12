const axios = require("axios");
const FormData = require("form-data");

const VT_BASE = "https://www.virustotal.com/api/v3";
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// ─── Poll until VT says "completed" ────────────────────────────────────────
async function pollForResult(analysisId, maxRetries = 8, intervalMs = 3000) {
    for (let i = 0; i < maxRetries; i++) {
        await wait(intervalMs);
        try {
            const res = await axios.get(
                `${VT_BASE}/analyses/${analysisId}`,
                {
                    headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY },
                    timeout: 10000
                }
            );
            const attrs = res.data.data.attributes;
            console.log(`[VT] Poll ${i + 1}/${maxRetries} — status: ${attrs.status}`);
            if (attrs.status === "completed") {
                return { status: "completed", stats: attrs.stats, results: attrs.results || {} };
            }
        } catch (pollError) {
            console.error(`[VT] Poll error attempt ${i + 1}:`, pollError.message);
        }
    }
    // Return timeout — still usable
    return { status: "timeout", stats: {}, results: {}, note: "VirusTotal took too long. Try again in a minute." };
}

// ─── Build clean verdict from stats ────────────────────────────────────────
function buildVerdict(stats, target) {
    const malicious  = stats?.malicious  || 0;
    const suspicious = stats?.suspicious || 0;
    const harmless   = stats?.harmless   || 0;
    const undetected = stats?.undetected || 0;
    const total = malicious + suspicious + harmless + undetected;

    let verdict = "SAFE";
    if (malicious >= 3)                         verdict = "DANGER";
    else if (malicious >= 1 || suspicious >= 2) verdict = "WARNING";

    return {
        verdict,
        malicious,
        suspicious,
        harmless,
        undetected,
        total,
        summary: total > 0
            ? `${malicious} of ${total} security engines flagged this as malicious`
            : "No scan data available",
        target
    };
}

// ─── Handle API errors cleanly ──────────────────────────────────────────────
function handleVTError(error, target) {
    const status = error?.response?.status;
    if (status === 429) {
        console.error("[VT] Rate limit (429)");
        return { verdict: "UNKNOWN", summary: "VirusTotal rate limit reached. Try again in 1 minute.", stats: {}, target };
    }
    if (status === 401) {
        console.error("[VT] Invalid API key (401)");
        return { verdict: "UNKNOWN", summary: "VirusTotal API key is invalid. Check your .env file.", stats: {}, target };
    }
    console.error("[VT] Error:", error.message);
    return { verdict: "UNKNOWN", summary: `VirusTotal scan failed: ${error.message}`, stats: {}, target };
}

// ─── Scan a URL ─────────────────────────────────────────────────────────────
async function checkUrl(url) {
    if (!process.env.VIRUSTOTAL_API_KEY) {
        return { url, status: "error", verdict: "UNKNOWN", summary: "VirusTotal API key not configured", stats: {} };
    }
    try {
        const submitRes = await axios.post(
            `${VT_BASE}/urls`,
            new URLSearchParams({ url }),
            {
                headers: {
                    "x-apikey": process.env.VIRUSTOTAL_API_KEY,
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                timeout: 15000
            }
        );
        const analysisId = submitRes.data?.data?.id;
        if (!analysisId) throw new Error("No analysis ID returned");
        console.log(`[VT] URL submitted. ID: ${analysisId}`);

        const result = await pollForResult(analysisId);
        return { url, status: result.status, ...buildVerdict(result.stats, url), stats: result.stats, note: result.note || null };

    } catch (error) {
        return { url, status: "error", ...handleVTError(error, url) };
    }
}

// ─── Scan a FILE by uploading actual bytes ──────────────────────────────────
// This is the key fix: sends real file content, not just the filename
async function checkFile(fileBuffer, fileName, mimeType) {
    if (!process.env.VIRUSTOTAL_API_KEY) {
        return { fileName, status: "error", verdict: "UNKNOWN", summary: "VirusTotal API key not configured", stats: {} };
    }
    try {
        // Step 1: Upload actual file bytes to VirusTotal
        const form = new FormData();
        form.append("file", fileBuffer, {
            filename: fileName,
            contentType: mimeType || "application/octet-stream"
        });

        console.log(`[VT] Uploading file: ${fileName} (${fileBuffer.length} bytes)`);

        const uploadRes = await axios.post(
            `${VT_BASE}/files`,
            form,
            {
                headers: {
                    "x-apikey": process.env.VIRUSTOTAL_API_KEY,
                    ...form.getHeaders()
                },
                timeout: 60000,           // files take longer to upload
                maxBodyLength: 32 * 1024 * 1024  // 32 MB max
            }
        );

        const analysisId = uploadRes.data?.data?.id;
        if (!analysisId) throw new Error("No analysis ID returned for file");
        console.log(`[VT] File uploaded. Analysis ID: ${analysisId}`);

        // Step 2: Poll until completed (files take longer than URLs)
        const result = await pollForResult(analysisId, 10, 4000);

        return {
            fileName,
            status: result.status,
            ...buildVerdict(result.stats, fileName),
            stats: result.stats,
            note: result.note || null
        };

    } catch (error) {
        return { fileName, status: "error", ...handleVTError(error, fileName) };
    }
}

module.exports = { checkUrl, checkFile };