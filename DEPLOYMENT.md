# 🚀 Deployment & Turn.io Integration Guide

This document explains how to put the CyberPeace Scam Detector online so
that **Turn.io** (a WhatsApp business platform) can call it as a webhook.

There are **3 options**, ranked from quickest-to-try to most-production-ready.

---

## 🎯 The big picture

Right now, your server runs at `http://localhost:3000` on your computer.
Turn.io is in the cloud and **cannot reach your computer directly** —
it needs a **public URL**.

So we need to:
1. Take your local server and expose it to the internet with a public URL
2. Tell Turn.io to call that URL when a user sends a message

That's it. Two steps.

---

## 🥇 Option 1: ngrok (best for testing — 2 minutes)

**ngrok** is a free tool that gives your local server a temporary public
URL. It is the **fastest way to test** the Turn.io integration without
deploying anywhere.

### Step 1: Install ngrok
1. Go to https://ngrok.com/download
2. Download the Windows version
3. Extract the ZIP file (you'll get `ngrok.exe`)
4. Sign up for a free account at https://dashboard.ngrok.com/signup
5. Copy your auth token from the dashboard
6. In a terminal, run:
   ```bash
   ngrok config add-authtoken YOUR_AUTH_TOKEN
   ```

### Step 2: Start your server (in one terminal)
```bash
cd cyberpeace-agent
node server.js
```
You should see:
```
Server running on port 3000 🚀
```

### Step 3: Start ngrok (in a SECOND terminal)
```bash
ngrok http 3000
```

You will see a screen like this:
```
Session Status   online
Forwarding       https://a1b2c3d4.ngrok-free.app → http://localhost:3000
```

The URL **`https://a1b2c3d4.ngrok-free.app`** is your **public URL**.
Anyone on the internet can now reach your local server at this URL.

### Step 4: Test it
Open a browser and visit:
```
https://a1b2c3d4.ngrok-free.app/health
```
You should see:
```json
{"status":"ok","service":"CyberPeace Scam Detection","version":"1.0.0"}
```

✅ **Your server is now publicly accessible.**

### Step 5: Configure Turn.io to use this URL
See the "Turn.io Integration" section below for the exact code.

### Pros and cons of ngrok

| Pros | Cons |
|------|------|
| Free | URL changes every time you restart ngrok (paid plan = fixed URL) |
| 2 minutes to set up | Goes offline when your computer sleeps |
| No credit card needed | Only the free plan has the `.ngrok-free.app` domain |
| Perfect for demos and testing | Not suitable for production |

---

## 🥈 Option 2: Render (best for production — free tier)

**Render** is a cloud platform that runs your code 24/7. The free tier
is generous enough for this project.

### Step 1: Prepare your project for Render
Create a file called `render.yaml` in the project root:
```yaml
services:
  - type: web
    name: cyberpeace-scanner
    env: node
    buildCommand: npm install
    startCommand: node server.js
    plan: free
    envVars:
      - key: GROQ_API_KEY
        sync: false
      - key: VIRUSTOTAL_API_KEY
        sync: false
      - key: PORT
        value: 3000
```

### Step 2: Push your code to GitHub
1. Create a new GitHub repository
2. Push your code:
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/cyberpeace-agent.git
   git push -u origin main
   ```

### Step 3: Deploy on Render
1. Go to https://render.com and sign up (free)
2. Click "New +" → "Web Service"
3. Connect your GitHub repository
4. Render will auto-detect the `render.yaml` and configure everything
5. Add your API keys (Groq + VirusTotal) in the "Environment" tab
6. Click "Create Web Service"
7. Wait 2-3 minutes for the build to complete

### Step 4: Get your public URL
Render will give you a URL like:
```
https://cyberpeace-scanner.onrender.com
```

Test it:
```
https://cyberpeace-scanner.onrender.com/health
```

✅ **Your server is now live 24/7.**

### Pros and cons of Render

| Pros | Cons |
|------|------|
| Free tier available | Free tier spins down after 15 minutes of no traffic (wakes up in ~30 seconds on next request) |
| URL never changes | Requires GitHub |
| Runs 24/7 | Build takes 2-3 minutes the first time |
| Good for demos and small production use | |

---

## 🥉 Option 3: Railway (similar to Render)

**Railway** is another cloud platform. The setup is similar to Render.

### Step 1: Push to GitHub (same as Render)

### Step 2: Deploy on Railway
1. Go to https://railway.app and sign up
2. Click "New Project" → "Deploy from GitHub repo"
3. Select your repository
4. Add the environment variables (GROQ_API_KEY, VIRUSTOTAL_API_KEY)
5. Click "Deploy"

### Step 3: Get your URL
Railway will give you a URL like:
```
https://cyberpeace-scanner.up.railway.app
```

### Pros and cons of Railway

| Pros | Cons |
|------|------|
| Free $5 credit per month | Requires credit card (no charge unless you exceed free tier) |
| URL never changes | Free tier is limited to $5/month of usage |
| Very fast deployments | Slightly less generous free tier than Render |

---

## 🏆 My recommendation

| Use case | Best option |
|----------|-------------|
| Quick demo for the manager in 5 minutes | **ngrok** |
| Demo to multiple people over a few days | **ngrok with paid plan** ($8/month) |
| Production deployment | **Render free tier** |
| Production deployment with high traffic | **Railway or Render paid tier** |

For the manager's question about Turn.io integration, **start with ngrok**.
You can have it working in 2 minutes. Then if the manager wants to test
it themselves later, deploy to Render.

---

## 📱 Turn.io Integration

Once your server has a public URL, configure Turn.io to call it.

### The Code Block in Turn.io Journey

Add a Code block to your journey canvas. The block has two parts:
1. **The HTTP call** (calls your server)
2. **The response handler** (uses the result)

### Example Code Block for the scam detector

Replace `https://YOUR-SERVER-URL` with your actual public URL (from ngrok, Render, or Railway):

```elixir
# Call the CyberPeace Scam Detector
response = post("https://YOUR-SERVER-URL/analyze",
  timeout: 15000,
  headers: [["Content-Type", "application/json"]],
  body: %{
    "message" => "@contact.message"
  },
  mode: "sync"
)

# Parse the response
verdict = "UNKNOWN"
if response.status == 200 do
  body = response.body
  verdict = body["finalVerdict"] || "UNKNOWN"
end

# Save the verdict in a variable for the next blocks
@scam_verdict = verdict
```

### Add a Condition Block (branch based on verdict)

After the Code block, add a **Condition** block:

```
@scam_verdict == "DANGER"  → Go to "Scam warning" card
@scam_verdict == "WARNING" → Go to "Caution" card
@scam_verdict == "SAFE"    → Go to "All clear" card
```

### Example warning message (DANGER branch)

```elixir
card DangerCard do
  text("🚨 DANGER — This message looks like a scam.")
  text("We strongly recommend:")
  text("• Do NOT click any links in the message")
  text("• Do NOT reply with personal information")
  text("• Block the sender")
  text("• Report it to your local cyber cell")
  button("I understand", "ok")
end
```

### Example safe message (SAFE branch)

```elixir
card SafeCard do
  text("✅ This message appears to be safe.")
  text("However, always stay alert when sharing personal information online.")
end
```

---

## 🔒 Security note: Protect your endpoint

Anyone who knows your public URL could call your API. To prevent abuse:

### Add a simple API key check

1. Add this to your `.env` file:
   ```
   TURN_IO_API_KEY=some_long_random_string_here
   ```

2. Add a small middleware in `server.js` (before `app.use("/analyze", analyzeRoute);`):
   ```js
   app.use("/analyze", (req, res, next) => {
       const key = req.headers["x-api-key"];
       if (key !== process.env.TURN_IO_API_KEY) {
           return res.status(401).json({ error: "Unauthorized" });
       }
       next();
   });
   ```

3. In the Turn.io code block, add the header:
   ```elixir
   response = post("https://YOUR-SERVER-URL/analyze",
     timeout: 15000,
     headers: [
       ["Content-Type", "application/json"],
       ["x-api-key", "@(secrets.turn_io_api_key)"]   # store the key in Turn.io secrets
     ],
     body: %{
       "message" => "@contact.message"
     },
     mode: "sync"
   )
   ```

This way, only Turn.io (which knows the key) can call your endpoint.

---

## ✅ Quick-start checklist

- [ ] Choose your deployment option (ngrok / Render / Railway)
- [ ] Get a public URL working
- [ ] Test the URL with `curl https://YOUR-URL/health`
- [ ] Add the Code block to your Turn.io journey
- [ ] Test it with a real WhatsApp message
- [ ] (Optional) Add the API key for security

---

## 🆘 Common issues and fixes

### Issue: "ngrok URL not accessible from Turn.io"
**Fix**: Make sure you are using the **https** URL, not http. The free
ngrok plan gives you a `*.ngrok-free.app` URL.

### Issue: "Render app is slow to respond on first request"
**Fix**: This is the free tier "spinning down" after inactivity. The
first request after a long pause takes 30+ seconds. If you need always-fast
responses, upgrade to Render's $7/month plan or use Railway.

### Issue: "Turn.io says 'request timed out'"
**Fix**: Your server takes 30-60 seconds for file uploads. For text-only
analysis, the response comes in 2-5 seconds. Use a 15000ms (15 second)
timeout in the Code block — that covers text analysis reliably.

### Issue: "VirusTotal rate limit hit during demo"
**Fix**: Wait 1 minute and try again. The free tier allows 4 requests
per minute. For a demo, plan to wait between file uploads.
