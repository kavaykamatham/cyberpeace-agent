// ─────────────────────────────────────────────────────────────────────────────
// services/bhashiniService.js
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

const NAME_TO_CODE = {
    "hindi": "hi", "tamil": "ta", "telugu": "te", "bengali": "bn",
    "marathi": "mr", "gujarati": "gu", "kannada": "kn", "malayalam": "ml",
    "punjabi": "pa", "odia": "or", "oriya": "or", "assamese": "as",
    "urdu": "ur", "english": "en",
    "hin": "hi", "tam": "ta", "tel": "te", "ben": "bn",
    "mar": "mr", "guj": "gu", "kan": "kn", "mal": "ml",
    "pan": "pa", "ori": "or", "asm": "as", "urd": "ur", "eng": "en"
};

function normalizeLanguage(input) {
    if (!input) return "en";
    const trimmed = input.trim();
    if (LANG_CODES[trimmed.toLowerCase()]) return trimmed.toLowerCase();
    const code = NAME_TO_CODE[trimmed.toLowerCase()];
    if (code) return code;
    console.log(`[Bhashini] Unrecognized language value: "${input}" — defaulting to English`);
    return "en";
}

function isConfigured() {
    return !!(USER_ID && ULCA_API_KEY && INFER_KEY);
}

// ── Pipeline Config Call ────────────────────────────────────────────────────
// Per official Bhashini docs, language goes inside config.language — NOT
// at the task root level. Wrong structure causes "something went wrong" on
// the compute call even though config call appears to succeed.
async function getPipelineConfig(taskType, sourceLanguage, targetLanguage = null) {
    if (!["asr", "translation", "tts"].includes(taskType)) {
        throw new Error(`Invalid taskType "${taskType}". Bhashini only supports: asr, translation, tts`);
    }

    // Correct structure per docs:
    // { "taskType": "translation", "config": { "language": { "sourceLanguage": "te", "targetLanguage": "en" } } }
    const task = { taskType };
    const langConfig = {};
    if (sourceLanguage) langConfig.sourceLanguage = sourceLanguage;
    if (targetLanguage) langConfig.targetLanguage = targetLanguage;
    if (Object.keys(langConfig).length > 0) {
        task.config = { language: langConfig };
    }

    console.log(`[Bhashini] Config call task:`, JSON.stringify(task));

    const response = await axios.post(
        BHASHINI_CONFIG_URL,
        {
            pipelineTasks:         [task],
            pipelineRequestConfig: { pipelineId: "64392f96daac500b55c543cd" }
        },
        {
            headers: {
                "userID":       USER_ID,
                "ulcaApiKey":   ULCA_API_KEY,
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

    console.log(`[Bhashini] Config OK — serviceId: ${serviceId}`);
    return { serviceId, callbackUrl, inferenceApiKey };
}

// ── Pipeline Compute Call ───────────────────────────────────────────────────
// pipelineTasks: ONLY taskType + config — no input field inside tasks
// Text goes ONLY in top-level inputData.input
async function runPipeline(callbackUrl, inferenceApiKey, pipelineTasks, inputText) {
    const cleanTasks = pipelineTasks.map(({ taskType, config }) => ({ taskType, config }));

    const requestBody = {
        pipelineTasks: cleanTasks,
        inputData: {
            input: [{ source: inputText }]
        }
    };

    console.log(`[Bhashini] Compute call body:`, JSON.stringify(requestBody).substring(0, 200));

    const response = await axios.post(
        callbackUrl || BHASHINI_COMPUTE_URL,
        requestBody,
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

async function detectLanguage(text, knownLang = null) {
    const code = normalizeLanguage(knownLang);
    console.log(`[Bhashini] Using language: "${knownLang}" → normalized to "${code}" (${LANG_CODES[code] || "English"})`);
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

        const result = await runPipeline(
            callbackUrl, inferenceApiKey,
            [{
                taskType: "translation",
                config:   { serviceId, language: { sourceLanguage: srcCode, targetLanguage: tgtCode } }
            }],
            text
        );

        const translated = result?.pipelineResponse?.[0]?.output?.[0]?.target;
        if (!translated) throw new Error("No translation output in response");

        console.log(`[Bhashini] Translated ${srcCode}→${tgtCode}: "${translated.substring(0, 60)}..."`);
        return translated;

    } catch (err) {
        console.error("[Bhashini/translateText] Error:", err.response?.data || err.message, "— returning original");
        return text;
    }
}

async function speechToText(audioBase64, language = "hi") {
    if (!isConfigured()) throw new Error("Bhashini keys not configured.");

    const code = normalizeLanguage(language);
    const { serviceId, callbackUrl, inferenceApiKey } = await getPipelineConfig("asr", code);

    const asrRequestBody = {
        pipelineTasks: [{
            taskType: "asr",
            config:   { serviceId, language: { sourceLanguage: code } }
        }],
        inputData: {
            audio: [{ audioContent: audioBase64 }]
        }
    };

    const asrResponse = await axios.post(
        callbackUrl || BHASHINI_COMPUTE_URL,
        asrRequestBody,
        {
            headers: {
                "Authorization": inferenceApiKey || INFER_KEY,
                "Content-Type":  "application/json"
            },
            timeout: 15000
        }
    );

    const transcript = asrResponse.data?.pipelineResponse?.[0]?.output?.[0]?.source;
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