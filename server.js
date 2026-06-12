require("dotenv").config();
const express = require("express");
const cors    = require("cors");

const analyzeRoute = require("./routes/analyze");

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

// ── Main analysis routes (Streamlit, direct API calls) ────────────────────
app.use("/analyze", analyzeRoute);

// ── /analyze/whatsapp  — Turn.io WhatsApp integration endpoint ────────────
// Returns a single plain-text "whatsappMessage" field.
// Turn.io just calls this and prints the string — no JSON parsing needed.
app.post("/analyze/whatsapp", async (req, res) => {
    try {
        const message = req.body?.message || "";

        if (!message || message.trim().length < 2) {
            return res.json({
                whatsappMessage:
                    "Please send a message, URL, or suspicious text you want me to check."
            });
        }

        // Call the same analysis logic — reuse the existing route handler
        // by making an internal HTTP call to /analyze
        const axios    = require("axios");
        const baseUrl  = `http://localhost:${PORT}`;

        let analysis;
        try {
            const r = await axios.post(
                `${baseUrl}/analyze`,
                { message },
                { headers: { "Content-Type": "application/json" }, timeout: 55000 }
            );
            analysis = r.data;
        } catch (innerErr) {
            return res.json({
                whatsappMessage:
                    "⏳ The scanner is waking up. Please send your message again in 20 seconds."
            });
        }

        const verdict     = analysis.finalVerdict   || "UNKNOWN";
        const explanation = analysis.riskExplanation || analysis.groqAnalysis?.reason || "";
        const scamTypes   = analysis.groqAnalysis?.scamTypes || [];
        const typesLine   = scamTypes.length > 0
            ? `\nType: ${scamTypes.map(t => t.replace(/_/g, " ")).join(", ")}`
            : "";

        let whatsappMessage;

        if (verdict === "DANGER") {
            whatsappMessage =
                `🚨 *DANGER — This is a SCAM!*${typesLine}\n\n` +
                `${explanation}\n\n` +
                `*Do NOT click any links or share personal information.*`;
        } else if (verdict === "WARNING") {
            whatsappMessage =
                `⚠️ *WARNING — Be careful!*${typesLine}\n\n` +
                `${explanation}\n\n` +
                `*Verify with the official source before clicking anything.*`;
        } else if (verdict === "SAFE") {
            whatsappMessage =
                `✅ *SAFE — No threats detected.*\n\n` +
                `${explanation || "This message appears to be legitimate."}`;
        } else {
            whatsappMessage =
                `⚠️ Could not complete analysis. Please try again.\n\n` +
                `If this keeps happening, the scanning service may be busy.`;
        }

        // Append CyberPeace credit
        whatsappMessage += "\n\n_— CyberPeace Scam Detector_";

        res.json({ whatsappMessage, verdict });

    } catch (err) {
        console.error("[/analyze/whatsapp] Error:", err.message);
        res.json({
            whatsappMessage:
                "⚠️ Analysis failed. Please try again in a moment."
        });
    }
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error:   "Endpoint not found. Use POST /analyze"
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT} 🚀`);
    console.log(`- POST http://localhost:${PORT}/analyze          — Streamlit / API`);
    console.log(`- POST http://localhost:${PORT}/analyze/whatsapp — Turn.io WhatsApp`);
    console.log(`- GET  http://localhost:${PORT}/health           — health check`);
});