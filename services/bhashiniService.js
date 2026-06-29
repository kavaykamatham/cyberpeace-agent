// ─────────────────────────────────────────────────────────────────────────────
// services/bhashiniService.js
// Bhashini API integration for:
//   1. Language detection (what language is the user writing in?)
//   2. Text translation (any Indian language ↔ English)
//   3. Voice/Audio to text (ASR — speech recognition)
//
// Bhashini works in 2 steps:
//   Step A — Pipeline Config Call: get the serviceId for the task + language pair
//   Step B — Pipeline Compute Call: actually run the task (translate / transcribe)
//
// Keys needed in .env:
//   BHASHINI_USER_ID=...
//   BHASHINI_ULCA_API_KEY=...
//   BHASHINI_INFERENCE_API_KEY=...
// ─────────────────────────────────────────────────────────────────────────────

const axios = require("axios");

const BHASHINI_CONFIG_URL  = "https://meity-auth.ulcacontrib.org/ulca/apis/v0/model/getModelsPipeline";
const BHASHINI_COMPUTE_URL = "https://dhruva-api.bhashini.gov.in/services/inference/pipeline";

const USER_ID      = process.env.BHASHINI_USER_ID;
const ULCA_API_KEY = process.env.BHASHINI_ULCA_API_KEY;
const INFER_KEY    = process.env.BHASHINI_INFERENCE_API_KEY;

// Bhashini language codes (ISO-639)
const LANG_CODES = {
    "hi": "Hindi",
    "ta": "Tamil",
    "te": "Telugu",
    "bn": "Bengali",
    "mr": "Marathi",
    "gu": "Gujarati",
    "kn": "Kannada",
    "ml": "Malayalam",
    "pa": "Punjabi",
    "or": "Odia",
    "as": "Assamese",
    "ur": "Urdu",
    "en": "English"
};

// ── Check if Bhashini keys are configured ────────────────────────────────────
function isConfigured() {
    return !!(USER_ID && ULCA_API_KEY && INFER_KEY);
}

// ── Step A: Get pipeline config (serviceId) for a task ───────────────────────
async function getPipelineConfig(taskType, sourceLanguage, targetLanguage = null) {
    const task = { taskType, sourceLanguage };
    if (targetLanguage) task.targetLanguage = targetLanguage;

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
}

// ── Step B: Run the pipeline compute call ────────────────────────────────────
async function runPipeline(callbackUrl, inferenceApiKey, pipelineTasks) {
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
}

// ── 1. Detect language of text ────────────────────────────────────────────────
// Returns language code like "hi", "ta", "te", "en" etc.
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

// ── 2. Translate text ─────────────────────────────────────────────────────────
// sourceLanguage: "hi", "ta", "te" etc.
// targetLanguage: "en" for English, or any other language code
async function translateText(text, sourceLanguage, targetLanguage) {
    // No translation needed if same language
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
        return text; // fallback: return original text
    }
}

// ── 3. Voice/Audio to text (ASR) ──────────────────────────────────────────────
// audioBase64: base64-encoded audio (wav format preferred)
// language: "hi", "ta", "te" etc. (the language being spoken)
async function speechToText(audioBase64, language = "hi") {
    if (!isConfigured()) {
        throw new Error("Bhashini keys not configured. Cannot process voice messages.");
    }

    try {
        const { serviceId, callbackUrl, inferenceApiKey } = await getPipelineConfig(
            "asr", language
        );

        const result = await runPipeline(callbackUrl, inferenceApiKey, [{
            taskType:  "asr",
            config:    { serviceId, language: { sourceLanguage: language } },
            audio:     [{ audioContent: audioBase64 }]
        }]);

        const transcript = result?.pipelineResponse?.[0]?.output?.[0]?.source;
        if (!transcript) throw new Error("No transcript returned from Bhashini ASR");

        console.log(`[Bhashini] ASR (${language}): "${transcript.substring(0, 80)}"`);
        return transcript;

    } catch (err) {
        console.error("[Bhashini/speechToText] Error:", err.message);
        throw err;
    }
}

// ── 4. Full pipeline: detect language + translate to English ──────────────────
// Use this for incoming messages before scam detection
async function toEnglish(text) {
    const sourceLang = await detectLanguage(text);
    if (sourceLang === "en") return { englishText: text, sourceLang: "en" };

    const englishText = await translateText(text, sourceLang, "en");
    return { englishText, sourceLang };
}

// ── 5. Translate English verdict back to user's language ──────────────────────
// Use this after scam detection to reply in the user's language
async function fromEnglish(englishText, targetLang) {
    if (!targetLang || targetLang === "en") return englishText;
    return await translateText(englishText, "en", targetLang);
}

module.exports = {
    isConfigured,
    detectLanguage,
    translateText,
    speechToText,
    toEnglish,
    fromEnglish,
    LANG_CODES
};