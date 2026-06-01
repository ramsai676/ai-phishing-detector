// Optional explanation layer.
//
// The heuristic analyzer already produces a verdict and a list of fired signals.
// This layer turns that structured evidence into a short, friendly explanation a
// non-technical person can act on, using the Gemini API. If no GEMINI_API_KEY is
// set (or the call fails), we fall back to a deterministic explanation built from
// the signals, so the product always returns something useful.

import { GoogleGenAI } from '@google/genai';

const MODEL = process.env.GEMINI_MODEL || 'gemini-2.5-flash';

let client = null;
function getClient() {
  if (client) return client;
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;
  client = new GoogleGenAI({ apiKey });
  return client;
}

export function llmAvailable() {
  return Boolean(process.env.GEMINI_API_KEY);
}

function fallbackExplanation(report) {
  if (!report.signals.length) {
    return "I couldn't find the usual phishing tells (urgent threats, credential requests, suspicious links, or payment demands). That's a good sign, but it isn't a guarantee. If anything feels off, verify with the sender through a channel you trust.";
  }
  const lines = report.signals.slice(0, 4).map((s) => `- ${s.label}: ${s.explanation}`);
  const advice =
    report.verdict.level === 'safe'
      ? 'Stay alert, but nothing here strongly indicates a scam.'
      : 'Do not click links, reply with personal data, or make any payment. If it claims to be from a company you use, contact them through their official website or app instead.';
  return `This message shows the following warning signs:\n${lines.join('\n')}\n\n${advice}`;
}

const SYSTEM_PROMPT = `You are a calm, plain-spoken cybersecurity assistant that helps everyday people understand whether a message is a phishing or scam attempt.

You are given: the original message, a heuristic risk score (0-100), a verdict, and a list of detected warning signals with evidence.

Write a SHORT explanation (max ~120 words) for a non-technical reader:
1. State in one sentence whether this looks safe, suspicious, or dangerous, and why.
2. Reference the concrete evidence (quote the specific phrases/links that triggered concern).
3. End with clear, calm next-step advice (what NOT to do, and how to verify safely).

Rules:
- Never tell the user to click a link or share credentials.
- Do not invent signals that weren't detected. Ground your explanation in the provided evidence.
- No markdown headers, no preamble like "Sure", just the explanation.
- Be reassuring when the message is genuinely benign; don't manufacture fear.`;

/**
 * Produce a natural-language explanation of a heuristic report.
 * Always resolves; never throws. Returns { text, source: 'llm'|'fallback', model? }.
 */
export async function explain(message, report) {
  const c = getClient();
  if (!c) {
    return { text: fallbackExplanation(report), source: 'fallback' };
  }

  const evidence = report.signals
    .map((s) => `- ${s.label} (severity: ${s.severity}; evidence: ${s.evidence})`)
    .join('\n') || '- (no signals fired)';

  const userPrompt = `MESSAGE:
"""
${message.slice(0, 4000)}
"""

HEURISTIC RISK SCORE: ${report.score}/100
VERDICT: ${report.verdict.label}
DETECTED SIGNALS:
${evidence}

Write the explanation now.`;

  try {
    const resp = await c.models.generateContent({
      model: MODEL,
      contents: userPrompt,
      config: { systemInstruction: SYSTEM_PROMPT, maxOutputTokens: 400 },
    });
    const text = (resp.text || '').trim();
    return { text: text || fallbackExplanation(report), source: 'llm', model: MODEL };
  } catch (err) {
    // Network error, bad key, rate limit: degrade gracefully.
    return { text: fallbackExplanation(report), source: 'fallback', error: err.message };
  }
}
