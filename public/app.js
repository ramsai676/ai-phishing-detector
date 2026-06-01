const $ = (id) => document.getElementById(id);

const els = {
  message: $('message'),
  analyzeBtn: $('analyze-btn'),
  sampleBtn: $('sample-btn'),
  clearBtn: $('clear-btn'),
  spinner: document.querySelector('.spinner'),
  btnLabel: document.querySelector('.btn-label'),
  result: $('result'),
  score: $('score'),
  gaugeFill: $('gauge-fill'),
  verdictBadge: $('verdict-badge'),
  verdictEmoji: $('verdict-emoji'),
  verdictLabel: $('verdict-label'),
  summary: $('summary'),
  explanation: $('explanation'),
  sourceTag: $('source-tag'),
  signals: $('signals'),
  signalCount: $('signal-count'),
  signalsBlock: $('signals-block'),
  urlsBlock: $('urls-block'),
  urls: $('urls'),
  modeHint: $('mode-hint'),
};

const VERDICT_COLORS = {
  safe: '#2ecc71',
  suspicious: '#f1c40f',
  likely_phishing: '#ff8c42',
  dangerous: '#ff4d5e',
};

const SAMPLES = [
  `URGENT: Your PayPal account has been limited due to unusual activity. You must verify your identity within 24 hours or your account will be permanently suspended. Confirm now: http://paypa1-secure.account-verify.xyz/login`,
  `Dear Customer, Congratulations! Your number has WON ₹25,00,000 in the KBC Lucky Draw. To claim your prize, share your full name, bank account number and OTP. Reply on WhatsApp +91 98xxxxxxx. Pay a small ₹4,999 processing fee to release funds.`,
  `Hi, this is from the IT helpdesk. We detected a problem with your mailbox. Please log in to re-validate your password here to avoid losing access: https://bit.ly/3xowmail`,
  `Hey, are we still on for lunch tomorrow at 1? Let me know which place works for you.`,
];
let sampleIndex = 0;

async function checkMode() {
  try {
    const r = await fetch('/api/health');
    const data = await r.json();
    els.modeHint.textContent =
      data.llm === 'enabled'
        ? '✨ AI explanations enabled (Gemini). Your message is analysed locally first, then explained.'
        : 'Running in offline heuristic mode. Add an GEMINI_API_KEY to enable AI-written explanations.';
  } catch {
    /* ignore */
  }
}

function setLoading(loading) {
  els.analyzeBtn.disabled = loading;
  els.spinner.hidden = !loading;
  els.btnLabel.textContent = loading ? 'Analysing…' : 'Analyse message';
}

function renderSignals(signals) {
  els.signals.innerHTML = '';
  els.signalCount.textContent = signals.length ? `(${signals.length})` : '';
  if (!signals.length) {
    els.signalsBlock.hidden = true;
    return;
  }
  els.signalsBlock.hidden = false;
  for (const s of signals) {
    const li = document.createElement('li');
    li.className = `signal ${s.severity}`;
    li.innerHTML = `
      <div class="signal-top">
        <span class="signal-label"></span>
        <span class="signal-sev">${s.severity}</span>
      </div>
      <div class="signal-evidence"></div>
      <div class="signal-explain"></div>`;
    li.querySelector('.signal-label').textContent = s.label;
    li.querySelector('.signal-evidence').textContent = s.evidence;
    li.querySelector('.signal-explain').textContent = s.explanation;
    els.signals.appendChild(li);
  }
}

function renderUrls(urls) {
  if (!urls.length) {
    els.urlsBlock.hidden = true;
    return;
  }
  els.urlsBlock.hidden = false;
  els.urls.innerHTML = '';
  for (const u of urls) {
    const li = document.createElement('li');
    li.textContent = u;
    els.urls.appendChild(li);
  }
}

function animateScore(target, color) {
  const circumference = 327;
  els.gaugeFill.style.stroke = color;
  els.gaugeFill.style.strokeDashoffset = String(circumference * (1 - target / 100));
  let current = 0;
  const step = Math.max(1, Math.round(target / 30));
  const timer = setInterval(() => {
    current = Math.min(target, current + step);
    els.score.textContent = current;
    if (current >= target) clearInterval(timer);
  }, 22);
}

function renderResult(data) {
  els.result.hidden = false;
  const color = VERDICT_COLORS[data.verdict.level] || '#5b8cff';

  animateScore(data.score, color);
  els.verdictEmoji.textContent = data.verdict.emoji;
  els.verdictLabel.textContent = data.verdict.label;
  els.verdictBadge.style.borderColor = color;
  els.verdictLabel.style.color = color;
  els.summary.textContent = data.summary;
  els.explanation.textContent = data.explanation;
  els.sourceTag.textContent = data.explanationSource === 'llm' ? `AI · ${data.model || 'Gemini'}` : 'Heuristic';

  renderSignals(data.signals);
  renderUrls(data.urls);

  els.result.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function analyze() {
  const message = els.message.value.trim();
  if (!message) {
    els.message.focus();
    return;
  }
  setLoading(true);
  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Analysis failed');
    renderResult(data);
  } catch (err) {
    els.result.hidden = false;
    els.explanation.textContent = `⚠️ ${err.message}`;
  } finally {
    setLoading(false);
  }
}

els.analyzeBtn.addEventListener('click', analyze);
els.message.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') analyze();
});
els.sampleBtn.addEventListener('click', () => {
  els.message.value = SAMPLES[sampleIndex % SAMPLES.length];
  sampleIndex++;
  els.message.focus();
});
els.clearBtn.addEventListener('click', () => {
  els.message.value = '';
  els.result.hidden = true;
  els.message.focus();
});

checkMode();
