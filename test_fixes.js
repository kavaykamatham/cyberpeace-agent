// Quick test of the fixes — verifies that:
// 1. Phishing URL + scam text → DANGER (was SAFE before fix)
// 2. Legit bank URL → SAFE (no false positive)
// 3. Lottery text alone → DANGER
// 4. EICAR test file → DANGER (even though VT may not have it)

require("dotenv").config();
const http = require("http");

function postJson(path, body) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(body);
        const req = http.request({
            hostname: "localhost",
            port: 3000,
            path,
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(data)
            }
        }, (res) => {
            let chunks = "";
            res.on("data", d => chunks += d);
            res.on("end", () => {
                try { resolve(JSON.parse(chunks)); }
                catch { resolve(chunks); }
            });
        });
        req.on("error", reject);
        req.write(data);
        req.end();
    });
}

function postFile(path, filename, content) {
    return new Promise((resolve, reject) => {
        const boundary = "----test" + Date.now();
        const head = `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`;
        const tail = `\r\n--${boundary}--\r\n`;
        const body = Buffer.concat([Buffer.from(head), Buffer.from(content), Buffer.from(tail)]);
        const req = http.request({
            hostname: "localhost", port: 3000, path, method: "POST",
            headers: {
                "Content-Type": `multipart/form-data; boundary=${boundary}`,
                "Content-Length": body.length
            }
        }, (res) => {
            let chunks = "";
            res.on("data", d => chunks += d);
            res.on("end", () => {
                try { resolve(JSON.parse(chunks)); }
                catch { resolve(chunks); }
            });
        });
        req.on("error", reject);
        req.write(body);
        req.end();
    });
}

(async () => {
    console.log("\n=== TEST 1: Phishing URL + lottery text (was SAFE, should be DANGER) ===");
    const r1 = await postJson("/analyze", {
        message: "Congratulations! You won 1 crore lottery. Claim now: https://paypal-secure-verify.support/login"
    });
    console.log("Verdict:", r1.finalVerdict, "| isScam:", r1.finalIsScam, "| URLs:", r1.extractedUrls);
    console.log("Local risk score:", r1.localDetection?.overallRisk?.overallRiskScore);

    console.log("\n=== TEST 2: Legit ICICI bank URL (should be SAFE) ===");
    const r2 = await postJson("/analyze", {
        message: "Your bank statement is ready: https://retailnetbanking.icici.bank.in/login-page?ITM=check"
    });
    console.log("Verdict:", r2.finalVerdict, "| isScam:", r2.finalIsScam);
    console.log("Local risk score:", r2.localDetection?.overallRisk?.overallRiskScore);

    console.log("\n=== TEST 3: Lottery text only (should be DANGER) ===");
    const r3 = await postJson("/analyze", {
        message: "Congratulations you have been selected as the lucky winner! You have won 50000 dollars. Claim your prize now by replying with your bank details."
    });
    console.log("Verdict:", r3.finalVerdict, "| isScam:", r3.finalIsScam);

    console.log("\n=== TEST 4: EICAR test file (should be DANGER from local analysis) ===");
    const eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const r4 = await postFile("/analyze/file", "test.txt", eicar);
    console.log("Verdict:", r4.finalVerdict);
    console.log("Local file analysis:", r4.localFileAnalysis);

    console.log("\n=== TEST 5: Disguised file (PDF name, EXE content) ===");
    const exeHeader = Buffer.from([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
    const r5 = await postFile("/analyze/file", "invoice.pdf", exeHeader);
    console.log("Verdict:", r5.finalVerdict);
    console.log("Local file analysis:", r5.localFileAnalysis);
})();
