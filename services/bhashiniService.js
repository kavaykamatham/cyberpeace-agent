// ─────────────────────────────────────────────────────────────────────────────
// services/bhashiniService.js
// FIXED VERSION
//
// Root cause found: "txt_lang_detection" is NOT a valid taskType in Bhashini's
// pipeline config/compute API. The only valid taskTypes are: asr, translation, tts.
// Language detection is a separate, different service — not available through
// this pipeline with our current credentials.
//
// FIX: Since the WhatsApp journey already lets the user pick their language
// (via Turn.io's language selector / profile field), we use THAT language
// directly instead of trying to auto-detect it with Bhashini.
// This removes the broken detectLanguage() dependency entirely from the
// main flow, while keeping translation (which uses valid "translation" taskType).
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

// ── Get pipeline config — ONLY for valid taskTypes: asr, translation, tts ───
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

// ── detectLanguage — REMOVED dependency on broken txt_lang_detection ────────
// This taskType does not exist in Bhashini's pipeline API.
// We now rely on the language the USER SELECTED in the Turn.io journey
// (passed in as `knownLang` parameter) instead of auto-detecting it.
// If no language is provided, we default to English (safe fallback).
async function detectLanguage(text, knownLang = null) {
    if (knownLang && LANG_CODES[knownLang]) {
        console.log(`[Bhashini] Using user-selected language: ${knownLang} (${LANG_CODES[knownLang]})`);
        return knownLang;
    }
    console.log("[Bhashini] No language provided — defaulting to English");
    return "en";
}

// ── Translate text — uses VALID taskType "translation" ─────────────────────
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
        console.error("[Bhashini/translateText] Error:", err.response?.data || err.message, "— returning original");
        return text;
    }
}

// ── Voice/Audio to text (ASR) — uses VALID taskType "asr" ───────────────────
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

// ── Full pipeline: get language (from profile) + translate to English ──────
// knownLang: the language the user already selected in Turn.io (profile field)
async function toEnglish(text, knownLang = null) {
    const sourceLang = await detectLanguage(text, knownLang);
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