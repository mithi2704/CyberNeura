/**
 * Decision Types and Client Policy Helpers for CyberNeura Chrome Extension.
 */

export type ExtensionDecision = 'ALLOW' | 'WARN' | 'BLOCK';

export interface DecisionBadge {
  text: string;
  color: string;
  title: string;
}

/**
 * Returns extension action badge formatting based on security decision and risk score.
 */
export function getDecisionBadge(decision: ExtensionDecision, riskScore: number): DecisionBadge {
  switch (decision) {
    case 'BLOCK':
      return {
        text: 'ERR',
        color: '#EF4444', // Red-500
        title: `CyberNeura: Malicious Website Blocked (Risk: ${riskScore}/100)`,
      };
    case 'WARN':
      return {
        text: '!',
        color: '#F59E0B', // Amber-500
        title: `CyberNeura: Suspicious Website Warning (Risk: ${riskScore}/100)`,
      };
    case 'ALLOW':
    default:
      if (riskScore === 0) {
        return {
          text: '',
          color: '#10B981',
          title: 'CyberNeura: Protected',
        };
      }
      return {
        text: 'OK',
        color: '#10B981', // Emerald-500
        title: `CyberNeura: Safe Website (Risk: ${riskScore}/100)`,
      };
  }
}

/**
 * Renders fail-safe default decision when backend connection fails or times out.
 */
export function getFailSafeDecision(strictMode: boolean = false): {
  decision: ExtensionDecision;
  summary: string;
} {
  if (strictMode) {
    return {
      decision: 'WARN',
      summary: 'CyberNeura backend unreachable; strict policy warning applied.',
    };
  }
  return {
    decision: 'ALLOW',
    summary: 'CyberNeura backend unreachable; fail-safe browsing permitted.',
  };
}
