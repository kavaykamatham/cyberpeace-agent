require("dotenv").config();
const express = require("express");
const cors    = require("cors");
const http    = require("http");

const analyzeRoute = require("./routes/analyze");
const { analyzeScamIntent, explainRisk } = require("./services/groqService");
const { checkUrl }                        = require("./services/virusTotalService");
const { extractUrl }                      = require("./utils/extractUrl");
const { checkSuspiciousText, checkLotteryScamText, overallRiskAssessment } = require("./utils/phishingDetector");
const config = require("./config/detectionLists");

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ── Health check ──────────────────────────────────────────────────────────
app.get("/", (req, res) => res.send("CyberPeace Scam Detection API Running ✅"));

app.get("/health", (req, res) => res.json({
    status:    "ok",
    service:   "CyberPeace Scam Detection",
    version:   "2.0.0",
    timestamp: new Date()
}));

// ── Keep-alive: ping own /health every 14 minutes ─────────────────────────
// Prevents Render free tier from sleeping — keeps server warm for Turn.io
function selfPing() {
    http.get(`http://localhost:${PORT}/health`, (res) => {
        console.log(`[keep-alive] ping OK — ${new Date().toISOString()}`);
    }).on("error", (e) => {
        console.log(`[keep-alive] ping failed: ${e.message}`);
    });
}
// Start pinging 2 minutes after boot, then every 14 minutes
setTimeout(() => {
    selfPing();
    setInterval(selfPing, 14 * 60 * 1000);
}, 2 * 60 * 1000);

// ── Main routes ───────────────────────────────────────────────────────────
app.use("/analyze", analyzeRoute);

// ── /analyze/whatsapp — Turn.io endpoint ─────────────────────────────────
// Must respond within 20 seconds (Turn.io hard limit)
// Calls services directly — no internal HTTP round-trip
app.post("/analyze/whatsapp", async (req, res) => {
    const start = Date.now();
    try {
        const message = (req.body?.message || "").trim();
        console.log("[/analyze/whatsapp] Received message:", message);
        console.log(`\n[whatsapp] "${message.substring(0, 80)}"`);

        if (message.length < 2) {
            return res.json({
                whatsappMessage: "Please send a message, URL, or suspicious text to check."
            });
        }

        // Step 1: Extract URLs
        const urls = extractUrl(message);

        // Step 2: Local pattern check — instant
        const localRisk = overallRiskAssessment(message);

        // Step 3: Groq AI — ~1-2 seconds
        const groqResult = await analyzeScamIntent(message);
        const groqFailed = groqResult.fallback === true;
        console.log(`[whatsapp] Groq: ${groqResult.isScamQuery} (${groqResult.confidence}%) @ ${Date.now()-start}ms`);

        // Step 4: VirusTotal — scan first URL only (to stay within 20s)
        let vtVerdict = null;
        let urlChecks = [];
        if (urls.length > 0) {
            const vt = await checkUrl(urls[0]);
            vtVerdict = vt.verdict;
            urlChecks.push({ url: urls[0], virusTotalData: vt });
            console.log(`[whatsapp] VT: ${vtVerdict} @ ${Date.now()-start}ms`);
        }

        // Step 5: Brand impersonation check
        let brandImpersonation = false;
        for (const u of urls) {
            try {
                const h = new URL(u).hostname.toLowerCase();
                const trusted = (config.TRUSTED_DOMAINS || []).some(t => h === t || h.endsWith("." + t));
                if (!trusted && (config.BRAND_NAMES || []).some(b => h.includes(b.toLowerCase()))) {
                    brandImpersonation = true;
                    break;
                }
            } catch {}
        }

        // Step 6: Final verdict
        let finalVerdict = "SAFE";
        const localScore = localRisk.overallRiskScore || 0;
        const dangerThreshold  = groqFailed ? 55 : 65;
        const warningThreshold = groqFailed ? 30 : 35;

        if (vtVerdict === "DANGER" || brandImpersonation) {
            finalVerdict = "DANGER";
        } else if (!groqFailed && groqResult.isScamQuery && groqResult.confidence >= 70) {
            finalVerdict = "DANGER";
        } else if (localScore >= dangerThreshold) {
            finalVerdict = "DANGER";
        } else if (!groqFailed && groqResult.isScamQuery && groqResult.confidence >= 40) {
            finalVerdict = "WARNING";
        } else if (vtVerdict === "WARNING") {
            finalVerdict = "WARNING";
        } else if (localScore >= warningThreshold) {
            finalVerdict = "WARNING";
        }

        // Trusted domain override — never flag verified real domains
        const allTrusted = urls.length > 0 && urls.every(u => {
            try {
                const h = new URL(u).hostname.toLowerCase().replace(/^www\./, "");
                return (config.TRUSTED_DOMAINS || []).some(t => h === t || h.endsWith("." + t));
            } catch { return false; }
        });
        if (allTrusted && vtVerdict !== "DANGER" && localScore < 25) {
            finalVerdict = "SAFE";
        }

        // Step 7: Explanation
        let explanation = groqResult.reason || "";
        try {
            if (urls.length > 0) {
                explanation = await explainRisk(message, urlChecks, finalVerdict, false);
            }
        } catch {}

        // Step 8: Format reply
        const scamTypes = (groqResult.scamTypes || []).map(t => t.replace(/_/g, " ")).join(", ");
        const typeLine  = scamTypes ? `Type: ${scamTypes}\n\n` : "";

        let whatsappMessage;
        if (finalVerdict === "DANGER") {
            whatsappMessage = `DANGER - This is a SCAM!\n\n${typeLine}${explanation}\n\nDo NOT click any links or share personal details.\n\n- CyberPeace Scam Detector`;
        } else if (finalVerdict === "WARNING") {
            whatsappMessage = `WARNING - Be careful!\n\n${typeLine}${explanation}\n\nVerify with the official source before clicking anything.\n\n- CyberPeace Scam Detector`;
        } else {
            whatsappMessage = `SAFE - No threats detected.\n\n${explanation || "This message appears to be legitimate."}\n\n- CyberPeace Scam Detector`;
        }

        console.log(`[whatsapp] Done: ${finalVerdict} @ ${Date.now()-start}ms`);
        res.json({ whatsappMessage, verdict: finalVerdict });

    } catch (err) {
        console.error(`[whatsapp] Error @ ${Date.now()-start}ms:`, err.message);
        res.json({
            whatsappMessage: "Analysis failed. Please try again.\n\n- CyberPeace Scam Detector"
        });
    }
});

// 404 handler
app.use((req, res) => res.status(404).json({ success: false, error: "Endpoint not found" }));

app.listen(PORT, () => {
    console.log(`\nServer running on port ${PORT}`);
    console.log(`- POST /analyze          — full analysis`);
    console.log(`- POST /analyze/whatsapp — Turn.io (fast, <20s)`);
    console.log(`- GET  /health           — health check`);
    console.log(`Keep-alive ping starts in 2 minutes\n`);
});
