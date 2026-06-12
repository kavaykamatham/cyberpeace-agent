require("dotenv").config();
const express = require("express");
const cors    = require("cors");

const analyzeRoute = require("./routes/analyze");

// Import services directly so /analyze/whatsapp can call them
// without making a slow internal HTTP round-trip
const { analyzeScamIntent, explainRisk } = require("./services/groqService");
const { checkUrl }                        = require("./services/virusTotalService");
const { extractUrl }                      = require("./utils/extractUrl");
const {
    checkSuspiciousText,
    checkLotteryScamText,
    overallRiskAssessment
} = require("./utils/phishingDetector");
const config = require("./config/detectionLists");

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
    res.send("CyberPeace Scam Detection API Running ✅");
});

app.get("/health", (req, res) => {
    res.json({
        status:    "ok",
        service:   "CyberPeace Scam Detection",
        version:   "1.0.0",
        timestamp: new Date()
    });
});

// ── Keep-alive: self-ping every 14 minutes to prevent Render free-tier sleep
// This keeps the server always warm so Turn.io never gets a cold-start timeout
setInterval(async () => {
    try {
        const http = require("http");
        http.get(`http://localhost:${PORT}/health`, () => {
            console.log("[keep-alive] ping sent");
        });
    } catch (e) { /* ignore */ }
}, 14 * 60 * 1000); // every 14 minutes

// ── Main analysis routes ───────────────────────────────────────────────────
app.use("/analyze", analyzeRoute);

// ── /analyze/whatsapp — Turn.io endpoint ──────────────────────────────────
// Calls services directly (no internal HTTP) so it responds within 20 seconds
app.post("/analyze/whatsapp", async (req, res) => {
    try {
        const message = (req.body?.message || "").trim();

        if (message.length < 2) {
            return res.json({
                whatsappMessage: "Please send a message, URL, or suspicious text to check."
            });
        }

        // Step 1: Extract URLs
        const urls = extractUrl(message);

        // Step 2: Local pattern check (instant — no API)
        const localRisk = overallRiskAssessment(message);

        // Step 3: Groq AI (fast — usually 1-2 seconds)
        const groqResult  = await analyzeScamIntent(message);
        const groqFailed  = groqResult.fallback === true;

        // Step 4: VirusTotal — only scan first URL to stay within 20s limit
        let vtVerdict  = null;
        let urlChecks  = [];
        if (urls.length > 0) {
            const vt = await checkUrl(urls[0]);
            vtVerdict = vt.verdict;
            urlChecks.push({ url: urls[0], virusTotalData: vt });
        }

        // Step 5: Brand impersonation check
        let brandImpersonation = false;
        for (const u of urls) {
            try {
                const h = new URL(u).hostname.toLowerCase();
                const trusted = config.TRUSTED_DOMAINS.some(t => h === t || h.endsWith("." + t));
                if (!trusted && config.BRAND_NAMES.some(b => h.includes(b))) {
                    brandImpersonation = true;
                    break;
                }
            } catch {}
        }

        // Step 6: Final verdict
        let finalVerdict = "SAFE";

        if (vtVerdict === "DANGER" || brandImpersonation) {
            finalVerdict = "DANGER";
        } else if (!groqFailed && groqResult.isScamQuery && groqResult.confidence >= 70) {
            finalVerdict = "DANGER";
        } else if (localRisk.overallRiskScore >= config.THRESHOLDS.localDangerScore) {
            finalVerdict = "DANGER";
        } else if (!groqFailed && groqResult.isScamQuery && groqResult.confidence >= 40) {
            finalVerdict = "WARNING";
        } else if (vtVerdict === "WARNING") {
            finalVerdict = "WARNING";
        } else if (localRisk.overallRiskScore >= config.THRESHOLDS.localWarningScore) {
            finalVerdict = "WARNING";
        }

        // Trusted domain override
        const allTrusted = urls.length > 0 && urls.every(u => {
            try {
                const h = new URL(u).hostname.toLowerCase().replace(/^www\./, "");
                return config.TRUSTED_DOMAINS.some(t => h === t || h.endsWith("." + t));
            } catch { return false; }
        });
        if (allTrusted && vtVerdict !== "DANGER" && localRisk.overallRiskScore < 25) {
            finalVerdict = "SAFE";
        }

        // Step 7: Build explanation
        let explanation = groqResult.reason || "";
        try {
            if (urls.length > 0) {
                explanation = await explainRisk(message, urlChecks, finalVerdict, false);
            }
        } catch (e) { /* use groq reason */ }

        // Step 8: Format WhatsApp message
        const scamTypes = groqResult.scamTypes || [];
        const typesLine = scamTypes.length > 0
            ? `\nType: ${scamTypes.map(t => t.replace(/_/g, " ")).join(", ")}`
            : "";

        let whatsappMessage;
        if (finalVerdict === "DANGER") {
            whatsappMessage =
                `DANGER - This is a SCAM!${typesLine}\n\n` +
                `${explanation}\n\n` +
                `Do NOT click any links or share personal information.\n\n` +
                `- CyberPeace Scam Detector`;
        } else if (finalVerdict === "WARNING") {
            whatsappMessage =
                `WARNING - Be careful!${typesLine}\n\n` +
                `${explanation}\n\n` +
                `Verify with the official source before clicking anything.\n\n` +
                `- CyberPeace Scam Detector`;
        } else {
            whatsappMessage =
                `SAFE - No threats detected.\n\n` +
                `${explanation || "This message appears to be legitimate."}\n\n` +
                `- CyberPeace Scam Detector`;
        }

        console.log(`[/analyze/whatsapp] verdict=${finalVerdict} | groq=${groqResult.isScamQuery} | vt=${vtVerdict}`);
        res.json({ whatsappMessage, verdict: finalVerdict });

    } catch (err) {
        console.error("[/analyze/whatsapp] Error:", err.message);
        res.json({
            whatsappMessage: "Analysis failed. Please try again in a moment.\n\n- CyberPeace Scam Detector"
        });
    }
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ success: false, error: "Endpoint not found. Use POST /analyze" });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`- POST /analyze          — Streamlit / API`);
    console.log(`- POST /analyze/whatsapp — Turn.io WhatsApp`);
    console.log(`- GET  /health           — health check`);
});
