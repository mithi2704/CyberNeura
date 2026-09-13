/**
 * URL Normalization and Local Pre-Check Engine for CyberNeura Chrome Extension.
 * Ensures strict security data hygiene while preserving all threat indicators.
 */

export interface NormalizedUrlResult {
  isValid: boolean;
  isEligible: boolean;
  normalizedUrl: string;
  hostname: string;
  scheme: string;
  rejectionReason?: string;
}

const SUPPORTED_SCHEMES = new Set(['http:', 'https:']);

const UNSUPPORTED_SCHEMES = new Set([
  'chrome:',
  'chrome-extension:',
  'edge:',
  'about:',
  'file:',
  'data:',
  'javascript:',
  'blob:',
  'view-source:',
  'filesystem:',
]);

const INTERNAL_HOSTNAMES = new Set([
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
]);

/**
 * Validates and normalizes candidate URLs.
 * Preserves security-critical query parameters (e.g. login targets, redirects).
 */
export function normalizeUrl(rawUrl: string): NormalizedUrlResult {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return {
      isValid: false,
      isEligible: false,
      normalizedUrl: '',
      hostname: '',
      scheme: '',
      rejectionReason: 'Empty or missing URL string',
    };
  }

  const trimmed = rawUrl.trim();

  // Guard against extreme URI lengths
  if (trimmed.length > 4096) {
    return {
      isValid: false,
      isEligible: false,
      normalizedUrl: '',
      hostname: '',
      scheme: '',
      rejectionReason: 'URL exceeds maximum allowable length of 4096 characters',
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch (err) {
    return {
      isValid: false,
      isEligible: false,
      normalizedUrl: '',
      hostname: '',
      scheme: '',
      rejectionReason: 'Malformed URL syntax',
    };
  }

  const scheme = parsed.protocol.toLowerCase();

  // Filter browser-internal and non-web protocols
  if (UNSUPPORTED_SCHEMES.has(scheme)) {
    return {
      isValid: true,
      isEligible: false,
      normalizedUrl: trimmed,
      hostname: parsed.hostname.toLowerCase(),
      scheme,
      rejectionReason: `Internal or unsupported scheme: ${scheme}`,
    };
  }

  if (!SUPPORTED_SCHEMES.has(scheme)) {
    return {
      isValid: true,
      isEligible: false,
      normalizedUrl: trimmed,
      hostname: parsed.hostname.toLowerCase(),
      scheme,
      rejectionReason: `Unsupported protocol scheme: ${scheme}`,
    };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Local pre-check: skip local development loopback addresses unless configured
  if (INTERNAL_HOSTNAMES.has(hostname) || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    return {
      isValid: true,
      isEligible: false,
      normalizedUrl: trimmed,
      hostname,
      scheme,
      rejectionReason: 'Loopback or private internal network address',
    };
  }

  // Canonicalize URL:
  // - Protocol and hostname to lowercase
  // - Remove UI scroll anchor fragments (#...) but keep all query parameters intact
  const canonicalUrl = `${scheme}//${hostname}${parsed.port ? `:${parsed.port}` : ''}${parsed.pathname}${parsed.search}`;

  return {
    isValid: true,
    isEligible: true,
    normalizedUrl: canonicalUrl,
    hostname,
    scheme,
  };
}

/**
 * Extracts clean domain name for display (e.g., "login.example.com" or "example.com").
 */
export function extractDisplayDomain(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname.toLowerCase();
  } catch {
    return url;
  }
}
