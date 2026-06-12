const { analyzeScamIntent, explainRisk } = require("../services/groqService");
const { checkUrl } = require("../services/virusTotalService");
const { extractUrl } = require("../utils/extractUrl");

class ChatBot {
    constructor(name = "CyberPeace Bot") {
        this.name = name;
        this.conversationHistory = [];
    }

    /**
     * Analyze a user message for scam/spam content
     * @param {string} userMessage - The message to analyze
     * @returns {Promise<Object>} Analysis result
     */
    async analyzeMessage(userMessage) {
        try {
            this.conversationHistory.push({
                role: "user",
                message: userMessage,
                timestamp: new Date()
            });

            // Step 1: Extract URLs
            const urls = extractUrl(userMessage);

            // Step 2: Groq AI analyzes language and intent
            const analysisData = await analyzeScamIntent(userMessage);

            let result = {
                success: true,
                userMessage,
                extractedUrls: urls,
                isScamQuery: analysisData.isScamQuery,
                scamTypes: analysisData.scamTypes || [],
                confidence: analysisData.confidence || 0,
                reason: analysisData.reason || "",
                timestamp: new Date()
            };

            // Step 3: VirusTotal scans EVERY URL found — not just when Groq flags it
            // This is critical: Groq can miss things; VT always checks the actual URL
            if (urls && urls.length > 0) {
                result.urlChecks = [];

                for (const url of urls) {
                    try {
                        const vtResult = await checkUrl(url);
                        result.urlChecks.push({
                            url,
                            verdict: vtResult.verdict,
                            malicious: vtResult.malicious || 0,
                            suspicious: vtResult.suspicious || 0,
                            summary: vtResult.summary,
                            stats: vtResult.stats
                        });

                        // VT overrides Groq: if VT finds danger, mark as scam
                        if (vtResult.verdict === "DANGER") {
                            result.isScamQuery = true;
                            if (!result.scamTypes.includes("malicious_url")) {
                                result.scamTypes.push("malicious_url");
                            }
                        }
                    } catch (error) {
                        result.urlChecks.push({
                            url,
                            error: "Could not scan URL: " + error.message
                        });
                    }
                }

                // Step 4: Plain-English explanation
                result.riskExplanation = await explainRisk(userMessage, result.urlChecks);
            }

            this.conversationHistory.push({
                role: "bot",
                response: result,
                timestamp: new Date()
            });

            return result;

        } catch (error) {
            const errorResponse = {
                success: false,
                error: error.message,
                timestamp: new Date()
            };
            this.conversationHistory.push({
                role: "bot",
                response: errorResponse,
                timestamp: new Date()
            });
            throw error;
        }
    }

    getHistory() { return this.conversationHistory; }
    clearHistory() { this.conversationHistory = []; }

    getVerdict(analysisResult) {
        if (!analysisResult.success) return "ERROR: Could not analyze message";
        if (!analysisResult.isScamQuery) return "✅ SAFE - This doesn't appear to be a scam";

        if (analysisResult.urlChecks && analysisResult.urlChecks.length > 0) {
            const hasDanger = analysisResult.urlChecks.some(c => c.verdict === "DANGER" || c.malicious > 0);
            if (hasDanger) return "🚨 DANGER - Scam detected with malicious URLs. DO NOT CLICK!";
            return "⚠️ WARNING - Possible scam. URLs appear safe but be careful.";
        }

        return "⚠️ WARNING - This looks like a potential scam. Be careful!";
    }
}

module.exports = ChatBot;