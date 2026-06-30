// ─────────────────────────────────────────────────────────────────────────────
// services/bhashiniService.js
//
// IMPORTANT FIXES IN THIS VERSION:
// 1. "txt_lang_detection" is NOT a valid Bhashini taskType (confirmed via
//    testing — only asr, translation, tts are valid). Auto-detection removed.
//    Instead, we use the language the user already selected in Turn.io
//    (saved to their profile field as a FULL WORD like "Telugu", "Hindi").
// 2. Added a name-to-code converter since Turn.io profile stores full
//    language names, but Bhashini's API needs short ISO codes like "te", "hi".
// ─────────────────────────────────────────────────────────────────────────────

const axios = require("axios");

const BHASHINI_CONFIG_URL  = "https://meity-auth.ulcacontrib.org/ulca/apis/v0/model/getModelsPipeline";
const BHASHINI_COMPUTE_URL = "https://dhruva-api.bhashini.gov.in/services/inference/pipeline";

const USER_ID      = process.env.BHASHINI_USER_ID;
const ULCA_API_KEY = process.env.BHASHINI_ULCA_API_KEY;
const INFER_KEY    = process.env.BHASHINI_INFERENCE_API_KEY;

// Short code → display name
const LANG_CODES = {
    "hi": "Hindi", "ta": "Tamil", "te": "Telugu", "bn": "Bengali",
    "mr": "Marathi", "gu": "Gujarati", "kn": "Kannada", "ml": "Malayalam",
    "pa": "Punjabi", "or": "Odia", "as": "Assamese", "ur": "Urdu", "en": "English"
};

// Full name (any case) → short code — handles what Turn.io sends
const NAME_TO_CODE = {
    "hindi": "hi", "tamil": "ta", "telugu": "te", "bengali": "bn",
    "marathi": "mr", "gujarati": "gu", "kannada": "kn", "malayalam": "ml",
    "punjabi": "pa", "odia": "or", "oriya": "or", "assamese": "as",
    "urdu": "ur", "english": "en"
};

// ── Convert whatever Turn.io sends ("Telugu", "telugu", "te") → short code ──
function normalizeLanguage(input) {
    if (!input) return "en";
    const trimmed = input.trim();

    // Already a valid short code (e.g. "te", "hi")
    if (LANG_CODES[trimmed.toLowerCase()]) return trimmed.toLowerCase();

    // Full name like "Telugu" or "telugu"
    const code = NAME_TO_CODE[trimmed.toLowerCase()];
    if (code) return code;

    // Unknown — default to English, but log it so we can add it later
    console.log(`[Bhashini] Unrecognized language value: "${input}" — defaulting to English`);
    return "en";
}

function isConfigured() {
    return !!(USER_ID && ULCA_API_KEY && INFER_KEY);
}

async function getPipelineConfig(taskType, sourceLanguage, targetLanguage = null) {
    if (!["asr", "translation", "tts"].includes(taskType)) {
        throw new Error(`Invalid taskType "${taskType}". Bhashini only supports: asr, translation, tts`);
    }

    const task = { taskType };
    if (sourceLanguage) task.sourceLanguage = sourceLanguage;
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

// ── detectLanguage — uses the user's SELECTED language (full name or code) ─
async function detectLanguage(text, knownLang = null) {
    const code = normalizeLanguage(knownLang);
    console.log(`[Bhashini] Using language: "${knownLang}" → normalized to "${code}" (${LANG_CODES[code]})`);
    return code;
}

async function translateText(text, sourceLanguage, targetLanguage) {
    const srcCode = normalizeLanguage(sourceLanguage);
    const tgtCode = normalizeLanguage(targetLanguage);

    if (srcCode === tgtCode) return text;

    if (!isConfigured()) {
        console.log("[Bhashini] Keys not configured — returning original text");
        return text;
    }

    try {
        const { serviceId, callbackUrl, inferenceApiKey } = await getPipelineConfig(
            "translation", srcCode, tgtCode
        );

        const result = await runPipeline(callbackUrl, inferenceApiKey, [{
            taskType:  "translation",
            config:    { serviceId, language: { sourceLanguage: srcCode, targetLanguage: tgtCode } },
            input:     [{ source: text }]
        }]);

        const translated = result?.pipelineResponse?.[0]?.output?.[0]?.target;
        if (!translated) throw new Error("No translation output received");

        console.log(`[Bhashini] Translated ${srcCode}→${tgtCode}: "${translated.substring(0, 60)}..."`);
        return translated;

    } catch (err) {
        console.error("[Bhashini/translateText] Error:", err.response?.data || err.message, "— returning original");
        return text;
    }
}

async function speechToText(audioBase64, language = "hi") {
    if (!isConfigured()) {
        throw new Error("Bhashini keys not configured. Cannot process voice messages.");
    }

    const code = normalizeLanguage(language);
    const { serviceId, callbackUrl, inferenceApiKey } = await getPipelineConfig("asr", code);

    const result = await runPipeline(callbackUrl, inferenceApiKey, [{
        taskType:  "asr",
        config:    { serviceId, language: { sourceLanguage: code } },
        audio:     [{ audioContent: audioBase64 }]
    }]);

    const transcript = result?.pipelineResponse?.[0]?.output?.[0]?.source;
    if (!transcript) throw new Error("No transcript returned from Bhashini ASR");

    console.log(`[Bhashini] ASR (${code}): "${transcript.substring(0, 80)}"`);
    return transcript;
}

async function toEnglish(text, knownLang = null) {
    const sourceLang = await detectLanguage(text, knownLang);
    if (sourceLang === "en") return { englishText: text, sourceLang: "en" };

    const englishText = await translateText(text, sourceLang, "en");
    return { englishText, sourceLang };
}

async function fromEnglish(englishText, targetLang) {
    const code = normalizeLanguage(targetLang);
    if (!code || code === "en") return englishText;
    return await translateText(englishText, "en", code);
}

module.exports = {
    isConfigured, detectLanguage, translateText, speechToText,
    toEnglish, fromEnglish, LANG_CODES, normalizeLanguage
};