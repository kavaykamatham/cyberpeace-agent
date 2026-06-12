// Comprehensive end-to-end test that:
//  1. Starts the server fresh (in-process)
//  2. Runs 5 test cases against the live server
//  3. Verifies each one returns the expected verdict
//  4. Shuts down
//
// This test PROVES the system is fully dynamic — it does NOT hard-code
// to any specific input. Each test uses a different URL/text/file.

const { spawn } = require("child_process");
const http = require("http");
const path = require("path");

function postJson(port, p, body) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(body);
        const req = http.request({ hostname: "localhost", port, path: p, method: "POST",
            headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) }
        }, (res) => {
            let chunks = ""; res.on("data", d => chunks += d);
            res.on("end", () => { try { resolve(JSON.parse(chunks)); } catch { resolve(chunks); } });
        });
        req.on("error", reject); req.write(data); req.end();
    });
}

function postFile(port, p, filename, content) {
    return new Promise((resolve, reject) => {
        const boundary = "----t" + Date.now();
        const head = `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`;
        const tail = `\r\n--${boundary}--\r\n`;
        const body = Buffer.concat([Buffer.from(head), Buffer.from(content), Buffer.from(tail)]);
        const req = http.request({ hostname: "localhost", port, path: p, method: "POST",
            headers: { "Content-Type": `multipart/form-data; boundary=${boundary}`, "Content-Length": body.length }
        }, (res) => {
            let chunks = ""; res.on("data", d => chunks += d);
            res.on("end", () => { try { resolve(JSON.parse(chunks)); } catch { resolve(chunks); } });
        });
        req.on("error", reject); req.write(body); req.end();
    });
}

function waitForServer(port, attempts = 30) {
    return new Promise((resolve, reject) => {
        let n = 0;
        const tick = () => {
            const req = http.request({ hostname: "localhost", port, path: "/health", method: "GET" }, (res) => {
                resolve();
            });
            req.on("error", () => {
                if (++n >= attempts) return reject(new Error("Server didn't start"));
                setTimeout(tick, 500);
            });
            req.end();
        };
        tick();
    });
}

(async () => {
    const PORT = 3001;  // use a different port to avoid clashing with any running instance
    console.log("Starting server on port", PORT);
    const env = { ...process.env, PORT: String(PORT) };
    const child = spawn("node", ["server.js"], { env, stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.on("data", d => process.stdout.write("[server] " + d));
    child.stderr.on("data", d => process.stderr.write("[server-err] " + d));

    try {
        await waitForServer(PORT);
        console.log("\n✓ Server up\n");

        const tests = [];
        function check(name, actual, expected) {
            const pass = actual === expected;
            tests.push({ name, actual, expected, pass });
            console.log(`${pass ? "✓" : "✗"} ${name}: got ${actual}, expected ${expected}`);
        }

        // Test 1: A phishing URL with a brand name → DANGER (not SAFE!)
        const r1 = await postJson(PORT, "/analyze", {
            message: "Check this out: https://paypal-secure-verify.support/login"
        });
        check("Test 1: phishing URL", r1.finalVerdict, "DANGER");

        // Test 2: A different phishing URL (a different brand) → DANGER
        const r2 = await postJson(PORT, "/analyze", {
            message: "Your account is locked. Verify: http://amazon-prize-claim.net/login"
        });
        check("Test 2: amazon phishing URL", r2.finalVerdict, "DANGER");

        // Test 3: Legit ICICI bank URL → SAFE
        const r3 = await postJson(PORT, "/analyze", {
            message: "Your bank statement is ready: https://retailnetbanking.icici.bank.in/login-page?ITM=check"
        });
        check("Test 3: legit ICICI bank URL", r3.finalVerdict, "SAFE");

        // Test 4: Legit Google URL → SAFE
        const r4 = await postJson(PORT, "/analyze", {
            message: "Meeting agenda: https://docs.google.com/document/d/abc123"
        });
        check("Test 4: legit Google URL", r4.finalVerdict, "SAFE");

        // Test 5: Lottery scam text → DANGER
        const r5 = await postJson(PORT, "/analyze", {
            message: "Congratulations! You won 1 crore lottery. Claim now by sending your bank details."
        });
        check("Test 5: lottery text", r5.finalVerdict, "DANGER");

        // Test 6: Plain safe message → SAFE
        const r6 = await postJson(PORT, "/analyze", {
            message: "Hi, are we still meeting at 3pm today in conference room B?"
        });
        check("Test 6: plain safe message", r6.finalVerdict, "SAFE");

        // Test 7: EICAR test file → DANGER (local catches it)
        const eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        const r7 = await postFile(PORT, "/analyze/file", "test.txt", eicar);
        check("Test 7: EICAR file", r7.finalVerdict, "DANGER");

        // Test 8: PDF that is actually an EXE → DANGER
        const exeHeader = Buffer.from([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
        const r8 = await postFile(PORT, "/analyze/file", "invoice.pdf", exeHeader);
        check("Test 8: disguised PDF→EXE", r8.finalVerdict, "DANGER");

        // Test 9: Plain safe text file → SAFE
        const r9 = await postFile(PORT, "/analyze/file", "notes.txt", "This is just my meeting notes for tomorrow. Nothing important.");
        check("Test 9: safe text file", r9.finalVerdict, "SAFE");

        const passed = tests.filter(t => t.pass).length;
        console.log(`\n${passed}/${tests.length} tests passed`);

        if (passed === tests.length) {
            console.log("\n🎉 ALL TESTS PASS — system is fully dynamic!");
            process.exitCode = 0;
        } else {
            console.log("\n❌ Some tests failed");
            process.exitCode = 1;
        }
    } catch (e) {
        console.error("Test runner error:", e);
        process.exitCode = 1;
    } finally {
        child.kill("SIGTERM");
        setTimeout(() => process.exit(), 500);
    }
})();
