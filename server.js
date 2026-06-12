require("dotenv").config();
const express = require("express");
const cors = require("cors");

const analyzeRoute = require("./routes/analyze");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
    res.send("CyberPeace Scam Detection API Running ✅");
});

app.get("/health", (req, res) => {
    res.json({
        status: "ok",
        service: "CyberPeace Scam Detection",
        version: "1.0.0",
        timestamp: new Date()
    });
});

app.use("/analyze", analyzeRoute);

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: "Endpoint not found. Use POST /analyze"
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT} 🚀`);
    console.log(`- POST http://localhost:${PORT}/analyze - Analyze message for scams`);
    console.log(`- GET http://localhost:${PORT}/health - Server health check`);
});