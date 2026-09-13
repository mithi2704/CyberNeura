import test from 'node:test';
import assert from 'node:assert/strict';

// Test normalized logic
function normalizeUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { isValid: false, isEligible: false, normalizedUrl: '' };
  }
  const trimmed = rawUrl.trim();
  if (trimmed.length > 4096) {
    return { isValid: false, isEligible: false, normalizedUrl: '' };
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { isValid: false, isEligible: false, normalizedUrl: '' };
  }

  const scheme = parsed.protocol.toLowerCase();
  const unsupported = new Set(['chrome:', 'chrome-extension:', 'edge:', 'about:', 'file:', 'data:', 'javascript:', 'blob:']);
  if (unsupported.has(scheme)) {
    return { isValid: true, isEligible: false, normalizedUrl: trimmed, scheme };
  }

  const supported = new Set(['http:', 'https:']);
  if (!supported.has(scheme)) {
    return { isValid: true, isEligible: false, normalizedUrl: trimmed, scheme };
  }

  const hostname = parsed.hostname.toLowerCase();
  const internal = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1']);
  if (internal.has(hostname)) {
    return { isValid: true, isEligible: false, normalizedUrl: trimmed, hostname };
  }

  const canonicalUrl = `${scheme}//${hostname}${parsed.port ? `:${parsed.port}` : ''}${parsed.pathname}${parsed.search}`;
  return {
    isValid: true,
    isEligible: true,
    normalizedUrl: canonicalUrl,
    hostname,
    scheme,
  };
}

test('URL Normalizer: accepts valid web URLs', () => {
  const res = normalizeUrl('https://example.com/login?ref=123#fragment');
  assert.equal(res.isValid, true);
  assert.equal(res.isEligible, true);
  assert.equal(res.normalizedUrl, 'https://example.com/login?ref=123');
  assert.equal(res.hostname, 'example.com');
  assert.equal(res.scheme, 'https:');
});

test('URL Normalizer: preserves security-relevant query parameters', () => {
  const res = normalizeUrl('http://phishing-site.xyz/auth?user=admin&target=bank');
  assert.equal(res.isEligible, true);
  assert.equal(res.normalizedUrl, 'http://phishing-site.xyz/auth?user=admin&target=bank');
});

test('URL Normalizer: rejects browser-internal chrome:// URLs', () => {
  const res = normalizeUrl('chrome://settings');
  assert.equal(res.isValid, true);
  assert.equal(res.isEligible, false);
});

test('URL Normalizer: rejects chrome-extension:// schemes', () => {
  const res = normalizeUrl('chrome-extension://abcdefghijklmnopqrstuvwxyz/page.html');
  assert.equal(res.isEligible, false);
});

test('URL Normalizer: rejects javascript: and data: schemes', () => {
  const res1 = normalizeUrl('javascript:alert(1)');
  assert.equal(res1.isEligible, false);
  const res2 = normalizeUrl('data:text/html,<h1>Test</h1>');
  assert.equal(res2.isEligible, false);
});

test('URL Normalizer: rejects localhost loopback destinations', () => {
  const res = normalizeUrl('http://localhost:3000/dashboard');
  assert.equal(res.isEligible, false);
});

test('URL Normalizer: handles empty or malformed strings gracefully', () => {
  const res1 = normalizeUrl('');
  assert.equal(res1.isValid, false);
  const res2 = normalizeUrl('not-a-valid-url');
  assert.equal(res2.isValid, false);
});
