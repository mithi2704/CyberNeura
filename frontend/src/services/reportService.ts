import { aiClient } from '../lib/api/aiService';
import type { URLScan } from '../types';

export async function exportScansToCSV(scans: URLScan[]) {
  try {
    const res = await aiClient.get('/reports/scans/export', { responseType: 'blob' });
    const blob = new Blob([res.data], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `cyberneura_threat_logs_${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  } catch (err) {
    console.warn('Backend CSV export unavailable, generating locally:', err);
    // Fallback: generate CSV from provided scans array
    const headers = ['URL', 'Risk Score', 'Prediction', 'Confidence', 'Threat Category', 'IP Address', 'Country', 'Scanned At'];
    const rows = scans.map(s => [
      `"${s.url}"`,
      s.riskScore,
      s.prediction,
      s.confidence,
      `"${s.threatCategory}"`,
      s.ipAddress || '',
      `"${s.country || ''}"`,
      s.scannedAt
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `cyberneura_threat_logs_${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }
}

export async function downloadPDFReport(scan: URLScan) {
  try {
    const res = await aiClient.get(`/reports/scan/${scan.id}`, { responseType: 'blob' });
    const blob = new Blob([res.data], { type: 'text/plain;charset=utf-8;' });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `cyberneura_report_${scan.id}.txt`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  } catch (err) {
    console.warn('Backend report unavailable, generating locally:', err);
    // Fallback: generate report text from scan object with full Phase 3 evidence and risk factors
    const factors = scan.riskFactors || scan.riskAssessment?.risk_factors || [];
    const findings = scan.correlatedFindings || scan.riskAssessment?.correlated_findings || [];
    const evidenceList = scan.evidence || scan.riskAssessment?.evidence || [];

    const factorText = factors.length > 0
      ? factors.map(f => `  * ${f.factor_name}: +${f.contribution}/${f.max_contribution} pts (${f.direction}) - ${f.description}`).join('\n')
      : '  * No granular factor breakdown available.';

    const findingsText = findings.length > 0
      ? findings.map(f => `  * [${f.finding_type}] (${f.severity}, ${Math.round(f.confidence * 100)}% Conf): ${f.description}`).join('\n')
      : '  * No multi-source threat correlations triggered.';

    const evidenceText = evidenceList.length > 0
      ? evidenceList.map(e => `  * [${e.source}] ${e.evidence_type || e.type} (${e.severity}): ${e.description}`).join('\n')
      : '  * Standard baseline evidence profile.';

    const content = `
================================================================================
                    CYBERNEURA SECURITY PLATFORM
                   COMPREHENSIVE RISK ASSESSMENT
================================================================================
Generated At: ${new Date().toISOString()}
Scan Identifier: ${scan.id}
Risk Engine Version: 1.0.0 | Configuration Version: 2026.09.1

[EXECUTIVE SUMMARY]
${scan.summary || scan.riskAssessment?.summary || 'Comprehensive multi-source security assessment completed.'}

[ASSESSMENT CLASSIFICATION]
Target URL: ${scan.url}
Final Prediction: ${scan.prediction.toUpperCase()}
Risk Score: ${scan.riskScore} / 100
Confidence: ${scan.confidence}%
Threat Category: ${scan.threatCategory}
Severity: ${scan.severity || (scan.riskScore >= 80 ? 'CRITICAL' : scan.riskScore >= 40 ? 'MEDIUM' : 'INFO')}
Independent Confirmations: ${scan.independentConfirmations || 0}

[CYBERNEURA ANALYSIS]
${scan.explanation || 'Analyzed across machine-learning neural patterns, external threat intelligence feeds, DNS, and WHOIS domain registries.'}

[RISK FACTORS CONTRIBUTION BREAKDOWN]
${factorText}

[CORRELATED CONSENSUS FINDINGS]
${findingsText}

[EVIDENCE OBJECTS (${evidenceList.length} items)]
${evidenceText}

[INFRASTRUCTURE & DOMAIN TELEMETRY]
Resolving IP Address: ${scan.ipAddress || 'Unavailable'}
Location Target: ${scan.country || 'Unknown'}
Hosting Registrar: ${scan.hostingProvider || 'Unknown'}
Domain Registration Age: ${scan.domainAge || 'Unknown'}
SSL Certificate Status: ${scan.sslStatus?.toUpperCase() || 'NONE'}

[ACTIONABLE SECURITY RECOMMENDATIONS]
${scan.recommendations && scan.recommendations.length > 0
  ? scan.recommendations.map((r, i) => `  ${i + 1}. ${r}`).join('\n')
  : '  1. No urgent defensive actions required.'}

================================================================================
Protected by CyberNeura AI Security Operations Center
Deterministic & Auditable Threat Intelligence Engine
================================================================================
`;

    const blob = new Blob([content], { type: 'text/plain;charset=utf-8;' });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `cyberneura_assessment_${scan.id}.txt`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }
}
