/**
 * Warning UI Utilities for CyberNeura Chrome Extension.
 */

export function formatWarningReasons(reasons: string[]): string {
  if (!reasons || reasons.length === 0) {
    return 'Suspicious URL characteristics detected by CyberNeura.';
  }
  return reasons.map((r) => `• ${r}`).join('\n');
}
