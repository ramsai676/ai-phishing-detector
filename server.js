import 'dotenv/config';
import express from 'express';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { analyze } from './src/analyzer.js';
import { explain, llmAvailable } from './src/llm.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '64kb' }));
app.use(express.static(join(__dirname, 'public')));

// Health check (useful for Render/Railway/Fly probes).
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', llm: llmAvailable() ? 'enabled' : 'fallback' });
});

// Core endpoint: analyse a message.
app.post('/api/analyze', async (req, res) => {
  const message = (req.body?.message ?? '').toString();
  if (!message.trim()) {
    return res.status(400).json({ error: 'Please provide a non-empty "message" to analyse.' });
  }
  if (message.length > 20000) {
    return res.status(413).json({ error: 'Message too long (max 20,000 characters).' });
  }

  try {
    const report = analyze(message);
    const explanation = await explain(message, report);
    res.json({
      score: report.score,
      verdict: report.verdict,
      signals: report.signals,
      urls: report.urls,
      summary: report.summary,
      explanation: explanation.text,
      explanationSource: explanation.source,
      model: explanation.model || null,
    });
  } catch (err) {
    console.error('analyze error:', err);
    res.status(500).json({ error: 'Something went wrong while analysing the message.' });
  }
});

// Only start a listener when run directly (so tests can import the app/logic).
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  app.listen(PORT, () => {
    console.log(`\n  🛡️  AI Phishing & Scam Detector running on http://localhost:${PORT}`);
    console.log(`      LLM explanations: ${llmAvailable() ? 'ENABLED (Claude)' : 'fallback mode (set ANTHROPIC_API_KEY to enable)'}\n`);
  });
}

export default app;
