import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../src/analyzer.js';

test('benign message scores as safe', () => {
  const r = analyze('Hey, are we still on for lunch tomorrow at 1? Let me know.');
  assert.equal(r.verdict.level, 'safe');
  assert.ok(r.score < 25, `expected low score, got ${r.score}`);
  assert.equal(r.signals.length, 0);
});

test('classic PayPal phishing scores dangerous', () => {
  const msg =
    'URGENT: Your PayPal account has been suspended. Verify your identity within 24 hours at http://paypa1-secure.account-verify.xyz/login or it will be permanently closed.';
  const r = analyze(msg);
  assert.ok(r.score >= 75, `expected high score, got ${r.score}`);
  assert.equal(r.verdict.level, 'dangerous');
  const ids = r.signals.map((s) => s.id);
  assert.ok(ids.includes('urgency'));
  assert.ok(ids.includes('suspicious_url'));
});

test('OTP request alone is never marked safe', () => {
  const r = analyze('Please share the OTP you just received to confirm.');
  assert.ok(r.score >= 55, `expected elevated score, got ${r.score}`);
  assert.ok(r.signals.some((s) => s.id === 'sensitive_data'));
});

test('detects raw IP address links', () => {
  const r = analyze('Login here to fix your account: http://192.168.10.5/secure');
  const url = r.signals.find((s) => s.id === 'suspicious_url');
  assert.ok(url, 'expected suspicious_url signal');
  assert.match(url.evidence, /raw IP/i);
});

test('detects brand typo-squatting', () => {
  const r = analyze('Sign in at https://micros0ft-account.com to keep your subscription.');
  const url = r.signals.find((s) => s.id === 'suspicious_url');
  assert.ok(url, 'expected suspicious_url signal');
});

test('detects URL shortener', () => {
  const r = analyze('Re-validate your mailbox password: https://bit.ly/3xowmail');
  const url = r.signals.find((s) => s.id === 'suspicious_url');
  assert.ok(url);
  assert.match(url.evidence, /shortened/i);
});

test('gift-card scam triggers payment signal', () => {
  const r = analyze('I need you to buy two $100 Amazon gift cards and send me the codes urgently.');
  assert.ok(r.signals.some((s) => s.id === 'payment_demand'));
  assert.ok(r.score >= 50);
});

test('empty input is handled gracefully', () => {
  const r = analyze('   ');
  assert.equal(r.score, 0);
  assert.equal(r.signals.length, 0);
});

test('report shape is stable', () => {
  const r = analyze('Congratulations, you have won a free iPhone! Claim your prize now.');
  assert.ok(typeof r.score === 'number');
  assert.ok(r.verdict && r.verdict.level && r.verdict.label);
  assert.ok(Array.isArray(r.signals));
  assert.ok(Array.isArray(r.urls));
  assert.ok(typeof r.summary === 'string');
});
