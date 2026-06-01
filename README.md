# 🛡️ PhishGuardAI — AI Phishing & Scam Detector

> Paste any suspicious **email, SMS, or chat message** and instantly get a **risk score**, the **red flags** that triggered it, and a **plain-English explanation** of *why* it's dangerous — and how to stay safe.

A defensive cybersecurity tool that combines a transparent, OWASP-aware **heuristic detection engine** with an **LLM (Claude)** that explains findings to non-technical users. Built to help everyday people — and small businesses — spot phishing before they click.

![status](https://img.shields.io/badge/status-production--ready-2ecc71)
![node](https://img.shields.io/badge/node-%3E%3D18-5b8cff)
![license](https://img.shields.io/badge/license-MIT-blue)

---

## ✨ Why this project

Anyone can build an AI chat app. Far fewer build at the **AI + security** intersection. PhishGuardAI is:

- **Genuinely useful & defensive** — it helps users *protect* themselves, never attacks anyone.
- **Explainable** — it doesn't just say "scam," it shows the exact phrases, links, and tactics that fired, each mapped to *why* scammers use them.
- **Robust** — the detection engine runs **fully offline**. The AI only *enriches* the explanation, so the product is never broken by a missing API key, rate limit, or network blip.

---

## 🖥️ Demo

| Paste a message | Get an explained verdict |
| --- | --- |
| `URGENT: Your PayPal account is suspended. Verify within 24h at http://paypa1-secure.verify.xyz` | 🛑 **Dangerous — 92/100** · manufactured urgency · credential request · look-alike domain |

> _Add your screenshots/GIF here after deploying (e.g. `docs/demo.gif`)._

**Live demo:** _add your deployed URL here_

---

## 🧠 How it works

```
            ┌─────────────────────────────┐
  message → │  Heuristic Analyzer (local) │ → score + fired signals + verdict
            └──────────────┬──────────────┘
                           │
                           ▼
            ┌─────────────────────────────┐
            │  LLM Explainer (Claude)     │ → plain-English "what this means"
            │  · grounded in the signals  │   (falls back to a deterministic
            │  · never invents findings   │    explanation if no API key)
            └─────────────────────────────┘
```

### Detection signals

The engine scores a message across well-known phishing & social-engineering tactics, each weighted by severity:

| Signal | What it catches |
| --- | --- |
| **Manufactured urgency** | "act now", "within 24 hours", "account will be suspended" |
| **Credential requests** | "verify / update / confirm your account" |
| **Sensitive-data requests** | OTP, CVV, PIN, card number, Aadhaar, seed phrase |
| **Untraceable payment demands** | gift cards, wire transfer, crypto, "processing fee" |
| **Too-good-to-be-true bait** | lottery wins, refunds, free prizes, inheritance |
| **Threats** | legal action, arrest, fines, data-leak extortion |
| **Suspicious links** | raw IPs, URL shorteners, punycode/homographs, abused TLDs, brand typo-squats (`paypa1.com`), excessive sub-domains |
| **Generic greeting** | "Dear Customer" instead of your name |
| **Attachment lures** | "open the attached invoice.zip" |
| **Off-channel pivots** | "reply on WhatsApp / Telegram" |

Scores map to four verdicts: ✅ **Safe** · ⚠️ **Suspicious** · 🚩 **Likely Phishing** · 🛑 **Dangerous**.

---

## 🚀 Quick start

```bash
git clone https://github.com/<you>/ai-phishing-detector.git
cd ai-phishing-detector
npm install

# (optional) enable AI explanations
cp .env.example .env        # then add your ANTHROPIC_API_KEY

npm start
# → open http://localhost:3000
```

No API key? It still works — you'll get the full risk analysis with deterministic explanations.

### Run the tests

```bash
npm test
```

---

## 🔌 API

### `POST /api/analyze`

```jsonc
// request
{ "message": "URGENT: verify your account at http://paypa1-secure.xyz" }

// response
{
  "score": 92,
  "verdict": { "level": "dangerous", "label": "Dangerous — Very Likely a Scam", "emoji": "🛑" },
  "signals": [
    {
      "id": "suspicious_url",
      "label": "Suspicious or deceptive link",
      "severity": "high",
      "strength": 0.95,
      "evidence": "paypa1-secure.xyz — domain \"paypa1\" is a near-identical look-alike of \"paypal\"",
      "explanation": "Always hover a link and read the real domain before clicking."
    }
  ],
  "urls": ["http://paypa1-secure.xyz"],
  "summary": "Dangerous — Very Likely a Scam. Detected 3 risk signals...",
  "explanation": "This message is almost certainly a scam...",
  "explanationSource": "llm",
  "model": "claude-haiku-4-5-20251001"
}
```

### `GET /api/health`
Returns `{ "status": "ok", "llm": "enabled" | "fallback" }`.

---

## 🏗️ Tech stack

- **Backend:** Node.js + Express (ES modules)
- **AI:** Anthropic Claude via `@anthropic-ai/sdk` (optional, with graceful fallback)
- **Frontend:** vanilla HTML/CSS/JS — zero build step, animated risk gauge
- **Tests:** Node's built-in `node:test`

---

## ☁️ Deploy

Works on any Node host. The included `GET /api/health` endpoint suits platform health probes.

**Render / Railway / Fly.io**
- Build command: `npm install`
- Start command: `npm start`
- Set env var `ANTHROPIC_API_KEY` (optional) and `PORT` is read automatically.

---

## 🔒 Scope & ethics

PhishGuardAI is **strictly defensive and educational**. It analyses messages a user *already received* to help them stay safe. It does **not** generate phishing content, attack any system, or evade detection. Heuristics are transparent and inspectable in [`src/analyzer.js`](src/analyzer.js).

It is a **decision aid, not a guarantee** — always verify with the supposed sender through an official, trusted channel.

---

## 📂 Project structure

```
ai-phishing-detector/
├── server.js              # Express app + API
├── src/
│   ├── analyzer.js        # heuristic detection engine (offline, explainable)
│   └── llm.js             # Claude explanation layer + fallback
├── public/                # frontend (index.html, styles.css, app.js)
├── test/                  # node:test unit tests
├── .env.example
└── README.md
```

## 📜 License

MIT — see [LICENSE](LICENSE).
