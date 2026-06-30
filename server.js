require("dotenv").config();
const express = require("express");
const cors    = require("cors");
const http    = require("http");

const analyzeRoute = require("./routes/analyze");
const { analyzeScamIntent, explainRisk }         = require("./services/groqService");
const { checkUrl }                                = require("./services/virusTotalService");
const { extractUrl }                              = require("./utils/extractUrl");
const { checkSuspiciousText, checkLotteryScamText, overallRiskAssessment } = require("./utils/phishingDetector");
const config    = require("./config/detectionLists");
const bhashini  = require("./services/bhashiniService");

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: "10mb" }));

app.get("/", (req, res) => res.send("CyberPeace Scam Detection API Running ✅"));

app.get("/health", (req, res) => res.json({
    status:             "ok",
    service:            "CyberPeace Scam Detection",
    version:            "3.1.0",
    bhashiniConfigured: bhashini.isConfigured(),
    timestamp:          new Date()
}));

function selfPing() {
    http.get(`http://localhost:${PORT}/health`, () => {
        console.log(`[keep-alive] ping OK — ${new Date().toISOString()}`);
    }).on("error", (e) => {
        console.log(`[keep-alive] ping failed: ${e.message}`);
    });
}
setTimeout(() => {
    selfPing();
    setInterval(selfPing, 14 * 60 * 1000);
}, 2 * 60 * 1000);

app.use("/analyze", analyzeRoute);

// ── /analyze/whatsapp — Turn.io endpoint ─────────────────────────────────────
// IMPORTANT: Bhashini's pipeline API does NOT support automatic language
// detection (txt_lang_detection is not a valid taskType — confirmed by testing,
// error was "TaskType is not valid !"). Only asr, translation, tts are valid.
//
// FIX: We use the language the user already selected in the Turn.io journey
// (sent here as `language` field, e.g. "hi", "te", "ta") instead of trying
// to auto-detect it. This is reliable since the user picks their language
// during onboarding and it's saved to their profile field.
app.post("/analyze/whatsapp", async (req, res) => {
    const start = Date.now();
    try {
        const body        = req.body || {};
        const rawMessage  = (body.message || "").trim();
        const userLang    = body.language || null;     // from Turn.io profile field
        const audioBase64 = body.audio   || null;
        const audioLang   = userLang || "hi";

        console.log(`\n[whatsapp] message="${rawMessage.substring(0,80)}" | lang=${userLang} | hasAudio=${!!audioBase64}`);

        if (!rawMessage && !audioBase64) {
            return res.json({
                whatsappMessage: "Please send a message, URL, or suspicious text to check."
            });
        }

        let inputText = rawMessage;
        let sourceLang = "en";

        // Step 1: Voice to text if audio provided
        if (audioBase64) {
            try {
                console.log(`[1] Converting voice to text (lang: ${audioLang})...`);
                inputText  = await bhashini.speechToText(audioBase64, audioLang);
                sourceLang = audioLang;
                console.log(`[1] Transcript: "${inputText.substring(0, 80)}" @ ${Date.now()-start}ms`);
            } catch (asrErr) {
                console.error("[1] ASR failed:", asrErr.message);
                return res.json({
                    whatsappMessage: "Sorry, I could not understand the voice message. Please try sending as text."
                });
            }
        }

        if (!inputText || inputText.length < 2) {
            return res.json({
                whatsappMessage: "Message is too short to analyze. Please send more details."
            });
        }

        // Step 2: Use selected language (NOT auto-detected) and translate to English
        let englishText = inputText;
        if (!audioBase64) {
            console.log("[2] Using selected language, translating to English...");
            const result = await bhashini.toEnglish(inputText, userLang);
            englishText  = result.englishText;
            sourceLang   = result.sourceLang;
            console.log(`[2] Source lang: ${sourceLang} | English: "${englishText.substring(0,80)}" @ ${Date.now()-start}ms`);
        } else {
            if (sourceLang !== "en") {
                englishText = await bhashini.translateText(inputText, sourceLang, "en");
                console.log(`[2] Translated voice: "${englishText.substring(0,80)}" @ ${Date.now()-start}ms`);
            }
        }

        // Step 3: Extract URLs
        const urls = extractUrl(englishText);
        console.log(`[3] URLs found: ${urls.length}`, urls);

        // Step 4: Local pattern check
        const localRisk = overallRiskAssessment(englishText);

        // Step 5: Groq AI
        const groqResult = await analyzeScamIntent(englishText);
        const groqFailed = groqResult.fallback === true;
        console.log(`[5] Groq: ${groqResult.isScamQuery} (${groqResult.confidence}%) @ ${Date.now()-start}ms`);

        // Step 6: VirusTotal
        let vtVerdict = null;
        let urlChecks = [];
        if (urls.length > 0) {
            const vt = await checkUrl(urls[0]);
            vtVerdict = vt.verdict;
            urlChecks.push({ url: urls[0], virusTotalData: vt });
            console.log(`[6] VT: ${vtVerdict} @ ${Date.now()-start}ms`);
        }

        // Step 7: Brand impersonation
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

        // Step 8: Final verdict
        let finalVerdict = "SAFE";
        const localScore       = localRisk.overallRiskScore || 0;
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

        const allTrusted = urls.length > 0 && urls.every(u => {
            try {
                const h = new URL(u).hostname.toLowerCase().replace(/^www\./, "");
                return (config.TRUSTED_DOMAINS || []).some(t => h === t || h.endsWith("." + t));
            } catch { return false; }
        });
        if (allTrusted && vtVerdict !== "DANGER" && localScore < 25) {
            finalVerdict = "SAFE";
        }

        // Step 9: Explanation
        let explanation = groqResult.reason || "";
        try {
            if (urls.length > 0) {
                explanation = await explainRisk(englishText, urlChecks, finalVerdict, false);
            }
        } catch {}

        // Step 10: Format English reply
        const scamTypes = (groqResult.scamTypes || []).map(t => t.replace(/_/g, " ")).join(", ");
        const typeLine  = scamTypes ? `Type: ${scamTypes}\n\n` : "";

        let englishReply;
        if (finalVerdict === "DANGER") {
            englishReply = `DANGER - This is a SCAM!\n\n${typeLine}${explanation}\n\nDo NOT click any links or share personal details.\n\n- CyberPeace Scam Detector`;
        } else if (finalVerdict === "WARNING") {
            englishReply = `WARNING - Be careful!\n\n${typeLine}${explanation}\n\nVerify with the official source before clicking anything.\n\n- CyberPeace Scam Detector`;
        } else {
            englishReply = `SAFE - No threats detected.\n\n${explanation || "This message appears to be legitimate."}\n\n- CyberPeace Scam Detector`;
        }

        // Step 11: Translate reply back to user's language
        let whatsappMessage = englishReply;
        if (sourceLang && sourceLang !== "en") {
            console.log(`[11] Translating reply to ${sourceLang}...`);
            try {
                whatsappMessage = await bhashini.fromEnglish(englishReply, sourceLang);
                console.log(`[11] Translated reply @ ${Date.now()-start}ms`);
            } catch (transErr) {
                console.error("[11] Translation failed, sending English:", transErr.message);
                whatsappMessage = englishReply;
            }
        }

        console.log(`[whatsapp] Done: ${finalVerdict} | lang: ${sourceLang} @ ${Date.now()-start}ms`);
        res.json({ whatsappMessage, verdict: finalVerdict, detectedLanguage: sourceLang });

    } catch (err) {
        console.error(`[whatsapp] Error @ ${Date.now()-start}ms:`, err.message);
        res.json({
            whatsappMessage: "Analysis failed. Please try again.\n\n- CyberPeace Scam Detector"
        });
    }
});

app.use((req, res) => res.status(404).json({ success: false, error: "Endpoint not found" }));

app.listen(PORT, () => {
    console.log(`\nServer running on port ${PORT}`);
    console.log(`- POST /analyze          — full analysis`);
    console.log(`- POST /analyze/whatsapp — Turn.io (multilingual, voice + text)`);
    console.log(`- GET  /health           — health check`);
    console.log(`Bhashini configured: ${bhashini.isConfigured()}`);
    console.log(`Keep-alive ping starts in 2 minutes\n`);
});