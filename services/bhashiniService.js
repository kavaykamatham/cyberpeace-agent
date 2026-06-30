// ─────────────────────────────────────────────────────────────────────────────
// services/bhashiniService.js
// DEBUG VERSION — logs the full error response from Bhashini for diagnosis
// ─────────────────────────────────────────────────────────────────────────────

const axios = require("axios");

const BHASHINI_CONFIG_URL  = "https://meity-auth.ulcacontrib.org/ulca/apis/v0/model/getModelsPipeline";
const BHASHINI_COMPUTE_URL = "https://dhruva-api.bhashini.gov.in/services/inference/pipeline";

const USER_ID      = process.env.BHASHINI_USER_ID;
const ULCA_API_KEY = process.env.BHASHINI_ULCA_API_KEY;
const INFER_KEY    = process.env.BHASHINI_INFERENCE_API_KEY;

const LANG_CODES = {
    "hi": "Hindi", "ta": "Tamil", "te": "Telugu", "bn": "Bengali",
    "mr": "Marathi", "gu": "Gujarati", "kn": "Kannada", "ml": "Malayalam",
    "pa": "Punjabi", "or": "Odia", "as": "Assamese", "ur": "Urdu", "en": "English"
};

function isConfigured() {
    return !!(USER_ID && ULCA_API_KEY && INFER_KEY);
}

async function getPipelineConfig(taskType, sourceLanguage, targetLanguage = null) {
    const task = { taskType };
    if (sourceLanguage) task.sourceLanguage = sourceLanguage;
    if (targetLanguage) task.targetLanguage = targetLanguage;

    try {
        const response = await axios.post(
            BHASHINI_CONFIG_URL,
            {
                pipelineTasks:        [task],
                pipelineRequestConfig: { pipelineId: "64392f96daac500b55c543cd" }
            },
            {
                headers: {
                    "userID":     USER_ID,
                    "ulcaApiKey": ULCA_API_KEY,
                    "Content-Type": "application/json"
                },
                timeout: 10000
            }
        );

        const pipelineConfig = response.data?.pipelineResponseConfig?.[0];
        if (!pipelineConfig) throw new Error("No pipeline config returned from Bhashini");

        const serviceId       = pipelineConfig.config?.[0]?.serviceId;
        const callbackUrl     = response.data?.pipelineInferenceAPIEndPoint?.callbackUrl;
        const inferenceApiKey = response.data?.pipelineInferenceAPIEndPoint?.inferenceApiKey?.value;

        if (!serviceId) throw new Error("No serviceId in Bhashini pipeline config");

        return { serviceId, callbackUrl, inferenceApiKey };

    } catch (err) {
        // ── DEBUG: print the FULL error response from Bhashini ──────────────
        console.error("\n========== BHASHINI ERROR DETAIL ==========");
        console.error("Status code:", err.response?.status);
        console.error("Response body:", JSON.stringify(err.response?.data, null, 2));
        console.error("Request body sent:", JSON.stringify({
            pipelineTasks: [task],
            pipelineRequestConfig: { pipelineId: "64392f96daac500b55c543cd" }
        }, null, 2));
        console.error("Headers sent (keys masked):", {
            userID:     USER_ID ? USER_ID.substring(0, 6) + "..." : "MISSING",
            ulcaApiKey: ULCA_API_KEY ? ULCA_API_KEY.substring(0, 6) + "..." : "MISSING"
        });
        console.error("=============================================\n");
        throw err;
    }
}

async function runPipeline(callbackUrl, inferenceApiKey, pipelineTasks) {
    try {
        const response = await axios.post(
            callbackUrl || BHASHINI_COMPUTE_URL,
            { pipelineTasks, inputData: pipelineTasks[0].input },
            {
                headers: {
                    "Authorization": inferenceApiKey || INFER_KEY,
                    "Content-Type":  "application/json"
                },
                timeout: 15000
            }
        );
        return response.data;
    } catch (err) {
        console.error("\n========== BHASHINI COMPUTE ERROR ==========");
        console.error("Status code:", err.response?.status);
        console.error("Response body:", JSON.stringify(err.response?.data, null, 2));
        console.error("==============================================\n");
        throw err;
    }
}

async function detectLanguage(text) {
    if (!isConfigured()) {
        console.log("[Bhashini] Keys not configured — assuming English");
        return "en";
    }

    try {
        const { serviceId, callbackUrl, inferenceApiKey } = await getPipelineConfig("txt_lang_detection", "");

        const result = await runPipeline(callbackUrl, inferenceApiKey, [{
            taskType:  "txt_lang_detection",
            config:    { serviceId },
            input:     [{ source: text }]
        }]);

        const langCode = result?.pipelineResponse?.[0]?.output?.[0]?.langPrediction?.[0]?.langCode || "en";
        console.log(`[Bhashini] Detected language: ${langCode} (${LANG_CODES[langCode] || langCode})`);
        return langCode;

    } catch (err) {
        console.error("[Bhashini/detectLanguage] Error:", err.message, "— assuming English");
        return "en";
    }
}

async function translateText(text, sourceLanguage, targetLanguage) {
    if (sourceLanguage === targetLanguage) return text;
    if (!isConfigured()) {
        console.log("[Bhashini] Keys not configured — returning original text");
        return text;
    }

    try {
        const { serviceId, callbackUrl, inferenceApiKey } = await getPipelineConfig(
            "translation", sourceLanguage, targetLanguage
        );

        const result = await runPipeline(callbackUrl, inferenceApiKey, [{
            taskType:  "translation",
            config:    { serviceId, language: { sourceLanguage, targetLanguage } },
            input:     [{ source: text }]
        }]);

        const translated = result?.pipelineResponse?.[0]?.output?.[0]?.target;
        if (!translated) throw new Error("No translation output received");

        console.log(`[Bhashini] Translated ${sourceLanguage}→${targetLanguage}: "${translated.substring(0, 60)}..."`);
        return translated;

    } catch (err) {
        console.error("[Bhashini/translateText] Error:", err.message, "— returning original");
        return text;
    }
}

async function speechToText(audioBase64, language = "hi") {
    if (!isConfigured()) {
        throw new Error("Bhashini keys not configured. Cannot process voice messages.");
    }
    const { serviceId, callbackUrl, inferenceApiKey } = await getPipelineConfig("asr", language);
    const result = await runPipeline(callbackUrl, inferenceApiKey, [{
        taskType:  "asr",
        config:    { serviceId, language: { sourceLanguage: language } },
        audio:     [{ audioContent: audioBase64 }]
    }]);
    const transcript = result?.pipelineResponse?.[0]?.output?.[0]?.source;
    if (!transcript) throw new Error("No transcript returned from Bhashini ASR");
    console.log(`[Bhashini] ASR (${language}): "${transcript.substring(0, 80)}"`);
    return transcript;
}

async function toEnglish(text) {
    const sourceLang = await detectLanguage(text);
    if (sourceLang === "en") return { englishText: text, sourceLang: "en" };
    const englishText = await translateText(text, sourceLang, "en");
    return { englishText, sourceLang };
}

async function fromEnglish(englishText, targetLang) {
    if (!targetLang || targetLang === "en") return englishText;
    return await translateText(englishText, "en", targetLang);
}

module.exports = {
    isConfigured, detectLanguage, translateText, speechToText,
    toEnglish, fromEnglish, LANG_CODES
};