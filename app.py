import streamlit as st
import requests

st.set_page_config(
    page_title="CyberPeace - Scam Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
    .main { padding: 20px; }
    .stTabs [data-baseweb="tab-list"] { gap: 20px; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ CyberPeace Scam Detector")
st.markdown("**Detect scams, phishing, and spam messages in real-time**")
st.markdown("---")

with st.sidebar:
    st.header("⚙️ Settings")
    api_url = st.text_input(
        "API Server URL",
        value="http://localhost:3000",
        help="Enter the CyberPeace API server URL"
    )
    st.markdown("---")
    st.info("""
    **Make sure your server is running:**
    ```bash
    node server.js
    ```
    """)

# ── API calls ────────────────────────────────────────────────────────────────
def analyze_message(message):
    try:
        r = requests.post(f"{api_url}/analyze", json={"message": message}, timeout=90)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": f"Cannot connect to server at {api_url}. Is it running?"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Request timed out. VirusTotal scan took too long. Try again."}
    except Exception as e:
        return {"success": False, "error": str(e)}

def analyze_file_bytes(file_bytes, file_name, mime_type):
    try:
        r = requests.post(
            f"{api_url}/analyze/file",
            files={"file": (file_name, file_bytes, mime_type or "application/octet-stream")},
            timeout=120
        )
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": f"Cannot connect to server at {api_url}. Is it running?"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "File scan timed out. Try again."}
    except Exception as e:
        return {"success": False, "error": str(e)}

# ── Display: text message results ────────────────────────────────────────────
def display_results(result):
    if not result.get("success"):
        st.error(f"❌ Error: {result.get('error', 'Unknown error')}")
        return

    # ── Use the single authoritative finalVerdict from the server ────────
    # This is computed by the server combining Groq + VirusTotal + local checks.
    # Never read analysis.isScamQuery directly — that is only Groq's raw output.
    final_verdict      = result.get("finalVerdict", "SAFE")
    final_is_scam      = result.get("finalIsScam", False)
    is_file_sharing    = result.get("isFileSharingLink", False)

    groq_result      = result.get("groqAnalysis", {})
    confidence       = groq_result.get("confidence", 0)
    scam_types       = groq_result.get("scamTypes", [])
    reason           = groq_result.get("reason", "")
    urls             = result.get("extractedUrls", [])
    risk_explanation = result.get("riskExplanation", "")
    url_checks       = result.get("urlChecks", [])

    # ── Top verdict banner ───────────────────────────────────────────────
    col1, col2 = st.columns([3, 1])
    with col1:
        if final_verdict == "DANGER":
            st.error("🚨 DANGER — This is likely a scam or contains malicious content. Do NOT click any links.")
        elif final_verdict == "WARNING" and is_file_sharing:
            st.warning("⚠️ WARNING — This is a file-sharing link. The platform is not flagged as malicious, but the FILE behind the link cannot be scanned without downloading it. Your antivirus will warn you — trust that warning.")
        elif final_verdict == "WARNING":
            st.warning("⚠️ WARNING — This looks suspicious. Proceed with caution.")
        else:
            st.success("✅ SAFE — This message appears to be legitimate.")
    with col2:
        st.metric("Confidence", f"{confidence}%")

    # ── Analysis details ─────────────────────────────────────────────────
    st.markdown("### 📊 Analysis Details")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Scam Detected", "🔴 Yes" if final_is_scam else "🟢 No")
    with c2:
        st.metric("Scam Types", len(scam_types) if scam_types else 0)
    with c3:
        st.metric("URLs Found", len(urls))

    if final_is_scam and scam_types:
        st.markdown("### 🎯 Detected Scam Types")
        for t in scam_types:
            st.info(f"• {t.replace('_', ' ').title()}")

    if reason:
        st.markdown("### 💡 Why?")
        st.write(reason)

    if urls:
        st.markdown("### 🔗 URLs Detected")
        for url in urls:
            st.code(url, language=None)

    # ── VirusTotal URL scan results ──────────────────────────────────────
    if url_checks:
        st.markdown("### 🔍 URL Security Scan (VirusTotal — 91 engines)")
        for check in url_checks:
            url = check.get("url", "Unknown")
            vt  = check.get("virusTotalData", {})
            status = vt.get("status", "unknown")
            mal    = vt.get("malicious",  0)
            sus    = vt.get("suspicious", 0)
            harm   = vt.get("harmless",   0)
            undet  = vt.get("undetected", 0)
            total  = vt.get("total",      0)

            with st.expander(f"📋 {url}"):
                if status == "completed":
                    st.success("✅ Scan completed")
                elif status in ("timeout", "queued"):
                    st.warning("⏳ VirusTotal still analyzing — results may be partial")
                elif vt.get("summary"):
                    st.warning(f"⚠️ {vt.get('summary')}")

                c1, c2, c3, c4 = st.columns(4)
                with c1:
                    if mal > 0:
                        st.error(f"🚨 Malicious\n**{mal}**")
                    else:
                        st.metric("Malicious", mal)
                with c2:
                    if sus > 0:
                        st.warning(f"⚠️ Suspicious\n**{sus}**")
                    else:
                        st.metric("Suspicious", sus)
                with c3:
                    st.metric("Undetected", undet)
                with c4:
                    st.metric("Harmless", harm)

                st.caption(f"Total engines checked: {total} | Summary: {vt.get('summary', 'N/A')}")

                if mal > 0:
                    st.error(f"🚨 {mal} engine(s) confirmed this URL is malicious. Do NOT click it.")
                elif sus > 0:
                    st.warning(f"⚠️ {sus} engine(s) flagged this URL as suspicious.")
                elif status == "completed":
                    st.success("✅ No engines flagged this URL as dangerous.")

    # ── Local phishing pattern results ───────────────────────────────────
    local = result.get("localDetection", {})
    local_urls = local.get("urls", [])
    suspicious_local = [u for u in local_urls if u.get("localAnalysis", {}).get("isSuspicious")]

    if suspicious_local:
        st.markdown("### 🛡️ Local Pattern Detection")
        st.caption("Instant check — no API needed")
        for u in suspicious_local:
            with st.expander(f"📌 {u.get('url')}"):
                la = u.get("localAnalysis", {})
                st.metric("Suspicious Score", f"{la.get('suspiciousScore', 0)}%")
                for p in la.get("detectedPatterns", []):
                    st.warning(f"• {p}")

    if local.get("suspiciousKeywords"):
        st.markdown("### ⚠️ Suspicious Keywords Found")
        for kw in local.get("suspiciousKeywords", []):
            st.warning(f"• {kw}")

    st.markdown("---")
    if risk_explanation:
        st.markdown("### ⚠️ Risk Assessment")
        st.info(risk_explanation)

    if result.get("timestamp"):
        st.caption(f"Analyzed at: {result.get('timestamp')}")

# ── Display: file scan results ───────────────────────────────────────────────
def display_file_results(data):
    if not data.get("success"):
        st.error(f"❌ Error: {data.get('error', 'Unknown error')}")
        return

    final_verdict = data.get("finalVerdict", "SAFE")
    vt      = data.get("virusTotal", {})
    groq_a  = data.get("groqAnalysis", {})
    fname_a = data.get("filenameAnalysis", {})

    if final_verdict == "DANGER":
        st.error("🚨 DANGER — This file is flagged as dangerous! Do NOT open it.")
    elif final_verdict == "WARNING":
        st.warning("⚠️ WARNING — This file may be risky. Scan with antivirus before opening.")
    else:
        st.success("✅ SAFE — No threats detected in this file.")

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Verdict", final_verdict)
    with c2:
        st.metric("File Type", data.get("fileType", "unknown"))
    with c3:
        st.metric("File Size", f"{data.get('fileSize', 0):,} bytes")

    # VirusTotal result
    st.markdown("### 🔍 VirusTotal File Scan (actual content scanned)")
    vt_status = vt.get("status", "unknown")
    vt_mal    = vt.get("malicious",  0)
    vt_sus    = vt.get("suspicious", 0)
    vt_harm   = vt.get("harmless",   0)
    vt_undet  = vt.get("undetected", 0)
    vt_total  = vt.get("total",      0)

    if vt_status == "completed":
        st.success("✅ Full scan completed")
    elif vt_status in ("timeout", "queued"):
        st.warning("⏳ VirusTotal still analyzing — results may be partial")
    elif vt.get("summary"):
        st.warning(f"⚠️ {vt.get('summary')}")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        if vt_mal > 0:
            st.error(f"🚨 Malicious\n**{vt_mal}**")
        else:
            st.metric("Malicious", vt_mal)
    with c2:
        if vt_sus > 0:
            st.warning(f"⚠️ Suspicious\n**{vt_sus}**")
        else:
            st.metric("Suspicious", vt_sus)
    with c3:
        st.metric("Undetected", vt_undet)
    with c4:
        st.metric("Harmless", vt_harm)

    st.caption(f"Total engines: {vt_total} | {vt.get('summary', 'N/A')}")

    if vt_mal > 0:
        st.error(f"🚨 {vt_mal} engine(s) found malware in this file. Do NOT open it.")
    elif vt_status == "completed" and vt_mal == 0:
        st.success("✅ No engines found malware in the actual file content.")

    if groq_a.get("reasons"):
        st.markdown("### 💡 AI Analysis")
        for r in groq_a["reasons"]:
            st.write(f"• {r}")

    if fname_a.get("flags"):
        st.markdown("### 🚩 Filename Flags")
        for f in fname_a["flags"]:
            st.warning(f"• {f}")

    # ── Local byte-level content analysis (ALWAYS shown) ──────────────────
    # This is the key fix for "nothing shows up" — localFileAnalysis always
    # runs in milliseconds, even if VirusTotal times out. The user always
    # sees concrete findings about what is INSIDE the file.
    lfa = data.get("localFileAnalysis") or {}
    if lfa:
        st.markdown("### 🔬 Local Content Analysis (actual file bytes inspected)")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Local Verdict", lfa.get("verdict", "UNKNOWN"))
        with c2:
            st.metric("Risk Score", f"{lfa.get('riskScore', 0)}%")
        with c3:
            st.metric("Strings Scanned", lfa.get("stringsExtracted", 0))

        findings = lfa.get("findings") or []
        if findings:
            st.markdown("#### Findings")
            for f in findings:
                st.write(f"• {f}")
        else:
            st.success("No suspicious indicators found in the file content.")

        if lfa.get("urlsFound", 0) > 0:
            st.info(f"ℹ️  Found {lfa['urlsFound']} URL(s) embedded inside the file content.")

    if groq_a.get("recommendations"):
        st.markdown("### ✅ What To Do")
        for rec in groq_a["recommendations"]:
            st.write(f"• {rec}")

    if data.get("timestamp"):
        st.caption(f"Analyzed at: {data.get('timestamp')}")

# ── TABS ─────────────────────────────────────────────────────────────────────
tab1, tab2 = st.tabs(["📝 Text Message", "📁 Upload File"])

with tab1:
    st.markdown("### Enter a message to analyze")
    message = st.text_area(
        "Message:",
        placeholder="Paste the message or URL you want to check here...",
        height=150,
        label_visibility="collapsed"
    )
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔍 Analyze Message", use_container_width=True, type="primary", key="analyze_text"):
            if not message or len(message.strip()) < 3:
                st.error("Please enter a message or URL to analyze (at least 3 characters).")
            else:
                with st.spinner("🔄 Analyzing... URL scan may take 15–30 seconds"):
                    result = analyze_message(message)
                    display_results(result)
    with col2:
        if st.button("🗑️ Clear", use_container_width=True, key="clear_text"):
            st.rerun()

    with st.expander("💡 Help — Example inputs"):
        st.markdown("""
        **Scam (should detect as DANGER):**
        ```
        You won $1,000,000! Claim now: https://fake-lottery-win.tk
        ```
        **Phishing (should detect as DANGER):**
        ```
        Your PayPal account is suspended! Verify: https://paypal-secure-verify.support/login
        ```
        **Real bank URL (should be SAFE):**
        ```
        Your bank statement is ready: https://retailnetbanking.icici.bank.in/login-page?ITM=check
        ```
        **Safe message (should be SAFE):**
        ```
        Meeting tomorrow at 10 AM in Conference Room B
        ```
        """)

with tab2:
    st.markdown("### Upload a file to analyze")
    uploaded_file = st.file_uploader(
        "Choose a file",
        type=None,
        label_visibility="collapsed"
    )

    if uploaded_file:
        st.success(f"✅ File selected: **{uploaded_file.name}** ({uploaded_file.size:,} bytes)")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔍 Analyze File", use_container_width=True, type="primary", key="analyze_file"):
                try:
                    file_bytes = uploaded_file.read()
                    mime       = uploaded_file.type or "application/octet-stream"
                    name       = uploaded_file.name

                    # Text files: read content and run full text analysis (URL scan included)
                    is_text = (
                        mime.startswith("text/") or
                        mime in ["application/json", "application/xml"] or
                        name.lower().endswith((".txt", ".csv", ".log", ".json", ".eml", ".html"))
                    )

                    if is_text:
                        try:
                            content = file_bytes.decode("utf-8")
                        except Exception:
                            content = file_bytes.decode("latin-1")

                        if len(content.strip()) < 3:
                            st.error("File content is too short to analyze.")
                        else:
                            with st.spinner("🔄 Analyzing file content..."):
                                result = analyze_message(content)
                                display_results(result)
                    else:
                        # Binary files: send actual bytes to VirusTotal for deep scan
                        with st.spinner("🔄 Uploading file to VirusTotal for deep scan... (30–60 seconds)"):
                            data = analyze_file_bytes(file_bytes, name, mime)
                            display_file_results(data)

                except Exception as e:
                    st.error(f"Error reading file: {str(e)}")
        with col2:
            if st.button("🗑️ Clear", use_container_width=True, key="clear_file"):
                st.rerun()

    st.info("📁 Upload any file — PDF, APK, EXE, ZIP, images, text files, etc.")

    with st.expander("💡 How file scanning works"):
        st.markdown("""
        **Text files** (.txt, .csv, .json, .log):
        - Content is read and analyzed by Groq AI
        - Any URLs inside the file are scanned by VirusTotal

        **Binary files** (PDF, APK, EXE, ZIP, images):
        - Actual file bytes are uploaded to VirusTotal
        - 91 antivirus engines scan the real content inside the file
        - This catches malware even if the filename looks normal (e.g. invoice.pdf with malware inside)
        - Groq AI also analyzes the filename and type for extra signals

        **Why this matters:**
        A scammer can rename malware as "bank_statement.pdf". The old approach said SAFE
        because the name looked fine. Now VirusTotal scans what is actually inside the file.
        """)

st.markdown("---")
st.markdown("""
**CyberPeace Scam Detector** | Powered by Groq AI & VirusTotal API
- 🛡️ Detects lottery scams, phishing, fake offers, banking fraud
- 🔍 Scans URLs AND file contents with 70+ antivirus engines
- ⚠️ Provides risk assessment and plain-English recommendations
""")