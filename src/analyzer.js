// Heuristic phishing/scam analyzer.
//
// This is a transparent, rule-based engine that scores a message on a set of
// well-known phishing and social-engineering signals. It runs entirely offline
// (no API key required), so the app is always useful. The LLM layer (src/llm.js)
// builds on top of these signals to produce a natural-language explanation.
//
// Each signal returns 0..1 (how strongly it fired) and carries a weight. The
// final risk score is a weighted blend, normalised to 0..100.

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc',
]);

// Brands commonly impersonated in phishing. Used for lookalike-domain detection.
const IMPERSONATED_BRANDS = [
  'paypal', 'apple', 'microsoft', 'amazon', 'google', 'netflix', 'facebook',
  'instagram', 'whatsapp', 'icloud', 'outlook', 'office365', 'dhl', 'fedex',
  'ups', 'usps', 'hmrc', 'irs', 'sbi', 'hdfc', 'icici', 'axis', 'paytm',
  'phonepe', 'flipkart', 'coinbase', 'binance', 'metamask', 'linkedin', 'wells',
  'chase', 'bankofamerica', 'citibank',
];

const URGENCY_PATTERNS = [
  /\burgent(ly)?\b/i, /\bimmediat(e|ely)\b/i, /\bact now\b/i, /\bas soon as possible\b/i,
  /\bwithin \d+\s*(hours?|minutes?|hrs?|mins?)\b/i, /\bexpir(e|es|ing|ed)\b/i,
  /\bsuspend(ed|ing)?\b/i, /\bdeactivat(e|ed|ion)\b/i, /\blast (warning|chance|notice)\b/i,
  /\bfinal (warning|notice|reminder)\b/i, /\baccount (will be|has been) (locked|closed|blocked)\b/i,
  /\bfailure to (respond|comply|act)\b/i, /\bavoid (suspension|penalty|legal)\b/i,
];

const CREDENTIAL_PATTERNS = [
  /\bverify your (account|identity|password|details)\b/i, /\bconfirm your (account|identity|password|details|payment)\b/i,
  /\bupdate your (account|payment|billing|password|details)\b/i, /\blog ?in to (verify|confirm|update|restore|secure)\b/i,
  /\bre-?activate your account\b/i, /\benter your (password|pin|otp|cvv|card number|ssn|aadhaar)\b/i,
  /\bvalidate your (account|information|payment)\b/i, /\bunlock your account\b/i,
];

const PAYMENT_PATTERNS = [
  /\bgift ?cards?\b/i, /\b(itunes|google play|amazon|steam) (card|voucher)\b/i,
  /\bwire transfer\b/i, /\bwestern union\b/i, /\bmoneygram\b/i, /\bbitcoin\b/i, /\bcrypto(currency)?\b/i,
  /\busdt\b/i, /\beth(ereum)?\b/i, /\bsend (\$|£|€|₹|rs\.?|inr|usd)\s?\d/i,
  /\bprocessing fee\b/i, /\brelease fee\b/i, /\bcustoms (fee|charge|duty)\b/i, /\bclearance fee\b/i,
];

const REWARD_PATTERNS = [
  /\byou('| ?ha)ve won\b/i, /\bcongratulations\b/i, /\bwinner\b/i, /\bclaim your (prize|reward|gift|refund)\b/i,
  /\blottery\b/i, /\bfree (gift|prize|iphone|vacation|money)\b/i, /\bselected\b.*\b(winner|prize|reward)\b/i,
  /\b(tax )?refund (of|is) (waiting|pending|available|due)\b/i, /\binheritance\b/i, /\bunclaimed (funds?|money)\b/i,
  /\b100% free\b/i, /\bguaranteed (income|profit|returns?)\b/i,
];

const THREAT_PATTERNS = [
  /\blegal action\b/i, /\bpolice\b/i, /\barrest\b/i, /\blawsuit\b/i, /\bcourt\b/i,
  /\bfine\b/i, /\bpenalty\b/i, /\bprosecut(e|ion)\b/i, /\byour data (has been|is) (leaked|compromised|hacked)\b/i,
  /\bwe have (recorded|hacked|access to)\b/i, /\bwebcam\b/i,
];

const SENSITIVE_REQUEST_PATTERNS = [
  /\b(otp|one[- ]time password)\b/i, /\bcvv\b/i, /\bpin\b/i, /\b(card|debit|credit) (number|details)\b/i,
  /\bssn\b/i, /\bsocial security\b/i, /\baadhaar\b/i, /\bpan (card|number)\b/i, /\bnet ?banking\b/i,
  /\bpassword\b/i, /\bseed phrase\b/i, /\bprivate key\b/i, /\bmother'?s maiden name\b/i,
];

const GENERIC_GREETINGS = [
  /^\s*dear (customer|user|member|account holder|sir\/madam|client|valued customer)\b/i,
  /^\s*hello (customer|user|member|dear)\b/i, /^\s*attention\b/i,
];

const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'xyz', 'top', 'work', 'click', 'link', 'gq', 'tk', 'ml', 'cf', 'ga',
  'country', 'kim', 'science', 'party', 'review', 'stream', 'download', 'loan',
]);

const URL_REGEX = /\b((?:https?:\/\/|www\.)[^\s<>"')]+)/gi;
const RAW_DOMAIN_IN_URL = /^(?:https?:\/\/)?(?:www\.)?([^/:?#\s]+)/i;
const IP_HOST_REGEX = /^(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}(?:[:/]|$)/i;

function countMatches(text, patterns) {
  const hits = [];
  for (const re of patterns) {
    const m = text.match(re);
    if (m) hits.push(m[0].trim());
  }
  return hits;
}

function extractUrls(text) {
  const urls = text.match(URL_REGEX) || [];
  return [...new Set(urls.map((u) => u.replace(/[.,;:)]+$/, '')))];
}

function hostnameOf(url) {
  const m = url.match(RAW_DOMAIN_IN_URL);
  return m ? m[1].toLowerCase() : '';
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[a.length][b.length];
}

// Looks for brand impersonation anywhere in the hostname: a known brand used as
// a label/token but not the brand's real domain (paypal-secure.account.xyz), or
// a near-miss typo (paypa1, micros0ft). We tokenise the whole host on "." and
// "-" so brands hidden inside sub-domains or hyphenated labels are still caught.
function looksLikeBrandImpersonation(hostname) {
  const host = hostname.replace(/^www\./, '');
  const labels = host.split('.');
  const sld = labels.length >= 2 ? labels[labels.length - 2] : labels[0];
  // Tokens to inspect = every label/sub-token except the final TLD.
  const tokens = labels.slice(0, -1).flatMap((l) => l.split('-')).filter(Boolean);

  for (const brand of IMPERSONATED_BRANDS) {
    const legitDomain = `${brand}.com`;
    if (host === legitDomain || host.endsWith(`.${legitDomain}`)) continue; // real brand domain
    // The real SLD being exactly the brand on a non-.com is itself suspicious,
    // but the cases below cover the deceptive variants we care about.
    for (const token of tokens) {
      if (token === brand && sld !== brand) {
        return { brand, reason: `uses "${brand}" in the address but is not ${brand}'s official domain` };
      }
      // Typo-squat: token is a 1-2 char edit away from the brand (paypa1, amaz0n, micros0ft).
      if (token.length >= 4 && Math.abs(token.length - brand.length) <= 2) {
        const dist = levenshtein(token, brand);
        if (dist > 0 && dist <= 2) {
          return { brand, reason: `"${token}" is a near-identical look-alike of "${brand}"` };
        }
      }
    }
  }
  return null;
}

// The signal definitions. Each `detect` returns null (no fire) or
// { strength: 0..1, evidence: string, detail?: string }.
const SIGNALS = [
  {
    id: 'urgency',
    label: 'Manufactured urgency / pressure',
    weight: 1.4,
    severity: 'medium',
    detect(text) {
      const hits = countMatches(text, URGENCY_PATTERNS);
      if (!hits.length) return null;
      return {
        strength: Math.min(1, 0.45 + 0.2 * hits.length),
        evidence: hits.slice(0, 3).join(', '),
        detail: 'Scammers create time pressure so you act before thinking.',
      };
    },
  },
  {
    id: 'credential_request',
    label: 'Asks you to verify / update credentials',
    weight: 2.2,
    severity: 'high',
    detect(text) {
      const hits = countMatches(text, CREDENTIAL_PATTERNS);
      if (!hits.length) return null;
      return {
        strength: Math.min(1, 0.6 + 0.2 * hits.length),
        evidence: hits.slice(0, 3).join(', '),
        detail: 'Legitimate companies do not ask you to "verify" your account through an emailed link.',
      };
    },
  },
  {
    id: 'sensitive_data',
    label: 'Requests sensitive data (OTP, CVV, PIN, seed phrase…)',
    weight: 2.6,
    severity: 'high',
    detect(text) {
      const hits = countMatches(text, SENSITIVE_REQUEST_PATTERNS);
      if (!hits.length) return null;
      return {
        strength: Math.min(1, 0.6 + 0.18 * hits.length),
        evidence: hits.slice(0, 4).join(', '),
        detail: 'No legitimate institution asks for your OTP, CVV, PIN, full card number, or wallet seed phrase.',
      };
    },
  },
  {
    id: 'payment_demand',
    label: 'Demands payment via untraceable methods',
    weight: 2.3,
    severity: 'high',
    detect(text) {
      const hits = countMatches(text, PAYMENT_PATTERNS);
      if (!hits.length) return null;
      return {
        strength: Math.min(1, 0.6 + 0.2 * hits.length),
        evidence: hits.slice(0, 3).join(', '),
        detail: 'Gift cards, wire transfers, and crypto are favourites of scammers because they are irreversible.',
      };
    },
  },
  {
    id: 'reward_bait',
    label: 'Too-good-to-be-true reward / prize / refund',
    weight: 1.7,
    severity: 'medium',
    detect(text) {
      const hits = countMatches(text, REWARD_PATTERNS);
      if (!hits.length) return null;
      return {
        strength: Math.min(1, 0.5 + 0.2 * hits.length),
        evidence: hits.slice(0, 3).join(', '),
        detail: 'Unexpected winnings, refunds, or inheritances are classic bait.',
      };
    },
  },
  {
    id: 'threats',
    label: 'Threats of legal / financial consequences',
    weight: 1.6,
    severity: 'medium',
    detect(text) {
      const hits = countMatches(text, THREAT_PATTERNS);
      if (!hits.length) return null;
      return {
        strength: Math.min(1, 0.45 + 0.2 * hits.length),
        evidence: hits.slice(0, 3).join(', '),
        detail: 'Fear of arrest, fines, or exposure is used to override your judgement.',
      };
    },
  },
  {
    id: 'generic_greeting',
    label: 'Generic, impersonal greeting',
    weight: 0.8,
    severity: 'low',
    detect(text) {
      const hits = countMatches(text, GENERIC_GREETINGS);
      if (!hits.length) return null;
      return {
        strength: 0.6,
        evidence: hits[0],
        detail: 'A real provider who has your account usually uses your name, not "Dear Customer".',
      };
    },
  },
  {
    id: 'suspicious_url',
    label: 'Suspicious or deceptive link',
    weight: 2.4,
    severity: 'high',
    detect(text) {
      const urls = extractUrls(text);
      if (!urls.length) return null;
      const findings = [];
      let strength = 0;
      for (const url of urls) {
        const host = hostnameOf(url);
        if (!host) continue;
        if (IP_HOST_REGEX.test(url)) {
          findings.push(`${host} - raw IP address instead of a domain`);
          strength = Math.max(strength, 0.9);
        }
        if (URL_SHORTENERS.has(host)) {
          findings.push(`${host} - shortened link hides the true destination`);
          strength = Math.max(strength, 0.7);
        }
        if (/xn--/.test(host)) {
          findings.push(`${host} - punycode domain (possible homograph attack)`);
          strength = Math.max(strength, 0.85);
        }
        const tld = host.split('.').pop();
        if (SUSPICIOUS_TLDS.has(tld)) {
          findings.push(`${host} - uncommon/abused top-level domain (.${tld})`);
          strength = Math.max(strength, 0.6);
        }
        if (host.split('.').length >= 5) {
          findings.push(`${host} - excessive sub-domains used to look legitimate`);
          strength = Math.max(strength, 0.6);
        }
        const imp = looksLikeBrandImpersonation(host);
        if (imp) {
          findings.push(`${host} - ${imp.reason}`);
          strength = Math.max(strength, 0.95);
        }
      }
      if (!findings.length) return null;
      return {
        strength,
        evidence: findings.slice(0, 4).join(' · '),
        detail: 'Always hover a link and read the real domain before clicking.',
      };
    },
  },
  {
    id: 'attachment_lure',
    label: 'Pushes you to open an attachment',
    weight: 1.3,
    severity: 'medium',
    detect(text) {
      const re = /\b(open|see|review|download)\b[^.\n]{0,40}\b(attach(ment|ed)?|invoice|receipt|document|\.(zip|rar|exe|scr|docm|xlsm|html?))\b/i;
      const m = text.match(re);
      if (!m) return null;
      return {
        strength: 0.6,
        evidence: m[0].trim(),
        detail: 'Unexpected attachments - especially .zip/.exe/.html - are a common malware delivery method.',
      };
    },
  },
  {
    id: 'reply_offchannel',
    label: 'Pushes contact off-channel',
    weight: 1.1,
    severity: 'low',
    detect(text) {
      const re = /\b(whatsapp|telegram|text me|reply with your (whatsapp|number|phone)|contact me on|reach me at)\b/i;
      const m = text.match(re);
      if (!m) return null;
      return {
        strength: 0.5,
        evidence: m[0].trim(),
        detail: 'Moving you to a private channel helps the scammer avoid detection.',
      };
    },
  },
];

const VERDICTS = [
  { min: 0, max: 24, level: 'safe', label: 'Likely Safe', emoji: '✅' },
  { min: 25, max: 49, level: 'suspicious', label: 'Suspicious', emoji: '⚠️' },
  { min: 50, max: 74, level: 'likely_phishing', label: 'Likely Phishing', emoji: '🚩' },
  { min: 75, max: 100, level: 'dangerous', label: 'Dangerous - Very Likely a Scam', emoji: '🛑' },
];

function verdictFor(score) {
  return VERDICTS.find((v) => score >= v.min && score <= v.max) || VERDICTS[0];
}

/**
 * Analyse a message and return a structured, explainable risk report.
 * @param {string} message
 * @returns {{score:number, verdict:object, signals:Array, urls:string[], summary:string}}
 */
export function analyze(message) {
  const text = (message || '').toString();
  const trimmed = text.trim();

  if (!trimmed) {
    return {
      score: 0,
      verdict: verdictFor(0),
      signals: [],
      urls: [],
      summary: 'No message was provided to analyse.',
    };
  }

  const fired = [];
  let weightedSum = 0;
  let firedWeight = 0;

  for (const sig of SIGNALS) {
    const result = sig.detect(text);
    if (result) {
      fired.push({
        id: sig.id,
        label: sig.label,
        severity: sig.severity,
        strength: Number(result.strength.toFixed(2)),
        evidence: result.evidence,
        explanation: result.detail,
      });
      weightedSum += sig.weight * result.strength;
      firedWeight += sig.weight;
    }
  }

  // Normalise against a realistic "max suspicious" envelope rather than the sum
  // of every possible weight (a real scam fires ~3-5 signals, not all 11).
  const ENVELOPE = 7.5;
  let score = Math.round(Math.min(100, (weightedSum / ENVELOPE) * 100));

  // Severity-based floors. A single high-severity smoking gun (e.g. asking for
  // an OTP) should never read as "safe" just because nothing else fired; and
  // several strong, independent indicators together are unambiguously dangerous.
  const strongHigh = fired.filter((f) => f.severity === 'high' && f.strength >= 0.6).length;
  if (strongHigh >= 2) score = Math.max(score, 80);
  else if (strongHigh >= 1) score = Math.max(score, 55);

  const verdict = verdictFor(score);
  fired.sort((a, b) => b.strength * weightOf(b.id) - a.strength * weightOf(a.id));

  return {
    score,
    verdict,
    signals: fired,
    urls: extractUrls(text),
    summary: buildSummary(verdict, fired),
  };
}

function weightOf(id) {
  return SIGNALS.find((s) => s.id === id)?.weight ?? 1;
}

function buildSummary(verdict, fired) {
  if (!fired.length) {
    return 'No common phishing or scam signals were detected. Stay alert anyway - context matters.';
  }
  const top = fired.slice(0, 3).map((f) => f.label.toLowerCase());
  return `${verdict.label}. Detected ${fired.length} risk signal${fired.length > 1 ? 's' : ''}, most notably: ${top.join('; ')}.`;
}

export { SIGNALS, VERDICTS };
