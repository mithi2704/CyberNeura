import { scanURL, aiClient } from '../lib/api/aiService';
import type { ScanResponse } from '../lib/api/aiService';
import type { URLScan } from '../types';

export async function executeURLScan(url: string, userId?: string): Promise<URLScan> {
  // Call backend ML scan pipeline — persists to scan_store + Supabase automatically
  const scanResult: ScanResponse = await scanURL(url);

  const scanRecord: URLScan = {
    id: (scanResult as any).id || ('s-' + Math.random().toString(36).substring(2, 9)),
    url,
    riskScore: scanResult.riskScore,
    prediction: scanResult.prediction,
    confidence: scanResult.confidence,
    threatCategory: scanResult.threatCategory || (scanResult.prediction === 'safe' ? 'Safe' : (scanResult.prediction === 'malicious' ? 'Phishing' : 'Suspicious')),
    explanation: scanResult.explanation,
    probability: scanResult.probability,
    domainAge: scanResult.domainAge,
    hostingProvider: scanResult.hostingProvider,
    ipAddress: scanResult.ipAddress,
    country: scanResult.country,
    sslStatus: scanResult.sslStatus,
    whoisRecord: scanResult.whoisRecord,
    dnsRecords: scanResult.dnsRecords,
    recommendations: scanResult.recommendations,
    scannedBy: userId,
    scannedAt: (scanResult as any).scannedAt || new Date().toISOString(),
    threatIntelligence: scanResult.threatIntelligence,
    evidence: scanResult.evidence,
    independentConfirmations: scanResult.independentConfirmations,
    riskAssessment: scanResult.riskAssessment,
    riskFactors: scanResult.riskFactors,
    correlatedFindings: scanResult.correlatedFindings,
    evidenceCount: scanResult.evidenceCount ?? scanResult.evidence?.length ?? 0,
    severity: scanResult.severity,
    summary: scanResult.summary,
  };

  return scanRecord;
}

export async function fetchURLScans(): Promise<URLScan[]> {
  try {
    const res = await aiClient.get('/scans?page=1&page_size=50');
    if (res.data && Array.isArray(res.data.items)) {
      return res.data.items.map((it: any) => ({
        id: it.id,
        url: it.url,
        riskScore: it.riskScore ?? it.risk_score ?? 0,
        prediction: it.prediction ?? 'safe',
        confidence: it.confidence ?? 95,
        threatCategory: it.threatCategory ?? it.threat_category ?? (it.prediction === 'safe' ? 'Safe' : 'Phishing'),
        ipAddress: it.ipAddress ?? it.ip_address,
        sslStatus: it.sslStatus ?? it.ssl_status ?? 'valid',
        scannedAt: it.scannedAt ?? it.scanned_at ?? new Date().toISOString(),
        threatIntelligence: it.threatIntelligence ?? it.threat_intelligence,
        evidenceCount: it.evidenceCount ?? it.evidence_count ?? 0,
        severity: it.severity,
        summary: it.summary,
        primaryThreatSource: it.primaryThreatSource ?? it.primary_threat_source,
      }));
    }
    return [];
  } catch (err) {

    console.warn('Could not fetch from backend /scans:', err);
    return [];
  }
}

export async function deleteURLScan(id: string): Promise<boolean> {
  try {
    await aiClient.delete(`/scans/${id}`);
    return true;
  } catch (err) {
    console.warn('Backend delete scan error:', err);
    return false;
  }
}

export async function clearAllURLScans(): Promise<boolean> {
  try {
    await aiClient.post('/settings/clear-logs');
    return true;
  } catch (err) {
    console.warn('Backend clear-logs error:', err);
    return false;
  }
}
