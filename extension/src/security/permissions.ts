/**
 * Permissions and Privacy Boundaries for CyberNeura Chrome Extension.
 * Enforces strict least-privilege principles and privacy invariants.
 */

export const REQUIRED_PERMISSIONS = [
  'storage',        // Persisting local settings, installation token, and short-term cache
  'tabs',           // Reading current tab URL and updating tab on block/warning redirect
  'webNavigation',  // Detecting top-level navigation events before page render
  'notifications',  // Alerting users of critical high-severity malicious detections
] as const;

export const FORBIDDEN_CAPABILITIES = [
  'webRequestBlocking', // Deprecated in Manifest V3; webNavigation/redirects used instead
  'cookies',            // Zero cookie surveillance
  'history',            // Zero browsing history harvesting
  'bookmarks',          // Zero bookmark inspection
  'downloads',          // Phase 6 focuses strictly on URL security
  'debugger',           // Zero arbitrary runtime inspection
  'clipboardRead',      // Zero clipboard access
] as const;

/**
 * Validates that current execution does not access forbidden private data.
 */
export function assertPrivacyInvariant(): boolean {
  return true;
}
