import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { executeURLScan, fetchURLScans } from '../../services/urlScanService';
import { realtimeService } from '../../services/realtimeService';
import { aiClient } from '../../lib/api/aiService';
import type { URLScan } from '../../types';
import { URLScanner } from '../../components/scanner/URLScanner';
import { RiskAnalysisPanel } from '../../components/scanner/RiskAnalysisPanel';
import { RecentScans } from '../../components/scanner/RecentScans';
import { SafeBrowsingToggle } from '../../components/dashboard/SafeBrowsingToggle';
import { AIAssistant } from '../../components/dashboard/AIAssistant';
import { ThreatTrendsChart } from '../../components/charts/ThreatTrendsChart';
import { ScanDistributionChart } from '../../components/charts/ScanDistributionChart';
import { GlassCard } from '../../components/ui/GlassCard';
import { ShieldCheck, ShieldAlert, Database, Layers, Radio } from 'lucide-react';

export const DashboardPage: React.FC = () => {
  const { user } = useAuth();
  const [scans, setScans] = useState<URLScan[]>([]);
  const [activeScan, setActiveScan] = useState<URLScan | null>(null);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<{
    totalScans: number;
    threatsBlocked: number;
    providerStats?: {
      googleWebRiskMatches: number;
      phishtankMatches: number;
      urlhausMatches: number;
      totalLookups: number;
    };
  } | null>(null);
  const [breakdown, setBreakdown] = useState<{
    mlDetections: number;
    googleConfirmations: number;
    phishtankConfirmations: number;
    urlhausConfirmations: number;
    multiSourceDetections: number;
  } | null>(null);

  const loadData = async () => {
    try {
      const [list, statsRes, breakdownRes] = await Promise.all([
        fetchURLScans(),
        aiClient.get('/dashboard/stats').catch(() => ({ data: null })),
        aiClient.get('/threats/breakdown').catch(() => ({ data: null })),
      ]);
      setScans(list);
      if (statsRes?.data) setStats(statsRes.data);
      if (breakdownRes?.data) setBreakdown(breakdownRes.data);
    } catch (err) {
      console.warn('Dashboard data fetch warning:', err);
    }
  };

  useEffect(() => {
    // Initial fetch
    loadData();

    // Import realtimeService dynamically or statically
    const unsubScans = realtimeService.subscribeToScans((scanPayload) => {
      const newScan: URLScan = {
        id: scanPayload.id,
        url: scanPayload.url,
        riskScore: scanPayload.riskScore,
        prediction: scanPayload.prediction,
        confidence: scanPayload.confidence,
        threatCategory: scanPayload.threatCategory || (scanPayload.prediction === 'safe' ? 'Safe' : 'Phishing'),
        ipAddress: scanPayload.ipAddress,
        sslStatus: scanPayload.sslStatus,
        scannedAt: scanPayload.scannedAt,
        severity: scanPayload.severity,
        summary: scanPayload.summary,
      };

      setScans((prev) => [newScan, ...prev.filter((s) => s.id !== newScan.id)]);
      setStats((prev) => prev ? {
        ...prev,
        totalScans: prev.totalScans + 1,
        threatsBlocked: newScan.prediction !== 'safe' ? prev.threatsBlocked + 1 : prev.threatsBlocked,
      } : null);
    });

    const unsubAssessments = realtimeService.subscribeToRiskAssessments((assessment) => {
      setActiveScan((prev) => {
        if (prev && (prev.id === assessment.scan_id || prev.url === assessment.url)) {
          return {
            ...prev,
            riskScore: assessment.risk_score,
            prediction: assessment.prediction as any,
            confidence: assessment.confidence,
            threatCategory: assessment.threat_category || prev.threatCategory,
            severity: assessment.severity,
            summary: assessment.summary || prev.summary,
          };
        }
        return prev;
      });
    });

    const unsubThreats = realtimeService.subscribeToThreats((threat) => {
      setBreakdown((prev) => {
        if (!prev) return prev;
        const p = threat.provider.toLowerCase();
        return {
          ...prev,
          googleConfirmations: p.includes('google') ? prev.googleConfirmations + 1 : prev.googleConfirmations,
          phishtankConfirmations: p.includes('phish') ? prev.phishtankConfirmations + 1 : prev.phishtankConfirmations,
          urlhausConfirmations: p.includes('haus') ? prev.urlhausConfirmations + 1 : prev.urlhausConfirmations,
        };
      });
    });

    // Reconnection / polling resync
    const unsubResync = realtimeService.onResync(() => {
      loadData();
    });

    return () => {
      unsubScans();
      unsubAssessments();
      unsubThreats();
      unsubResync();
    };
  }, []);

  const handleScan = async (url: string) => {
    setLoading(true);
    try {
      const result = await executeURLScan(url, user?.uid);
      setActiveScan(result);
      setScans((prev) => [result, ...prev.filter((s) => s.id !== result.id)]);
      // Refresh stats after scan
      loadData();
    } catch (e) {
      console.error('Scan failed:', e);
    } finally {
      setLoading(false);
    }
  };

  const googleCount = breakdown?.googleConfirmations ?? stats?.providerStats?.googleWebRiskMatches ?? 0;
  const phishtankCount = breakdown?.phishtankConfirmations ?? stats?.providerStats?.phishtankMatches ?? 0;
  const urlhausCount = breakdown?.urlhausConfirmations ?? stats?.providerStats?.urlhausMatches ?? 0;
  const multiSourceCount = breakdown?.multiSourceDetections ?? 0;

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-8 items-start">
      {/* Left Columns - Security Actions & Visualizers */}
      <div className="xl:col-span-8 space-y-8">
        {/* Scanner form */}
        <URLScanner onScan={handleScan} loading={loading} />
        
        {/* Detail Analysis view */}
        <RiskAnalysisPanel scan={activeScan} />

        {/* Phase 2: Threat Intelligence Matches Metric Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <GlassCard className="p-4 space-y-1" hoverEffect={false}>
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-bold text-cyber-muted tracking-wider">Google Web Risk</span>
              <Database className="w-3.5 h-3.5 text-cyber-blue" />
            </div>
            <p className="text-xl font-bold font-cyber text-cyber-text">{googleCount}</p>
            <p className="text-[10px] text-cyber-muted font-light">Verified matches</p>
          </GlassCard>

          <GlassCard className="p-4 space-y-1" hoverEffect={false}>
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-bold text-cyber-muted tracking-wider">PhishTank</span>
              <ShieldAlert className="w-3.5 h-3.5 text-cyber-pink" />
            </div>
            <p className="text-xl font-bold font-cyber text-cyber-text">{phishtankCount}</p>
            <p className="text-[10px] text-cyber-muted font-light">Phishing confirmations</p>
          </GlassCard>

          <GlassCard className="p-4 space-y-1" hoverEffect={false}>
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-bold text-cyber-muted tracking-wider">URLhaus</span>
              <Radio className="w-3.5 h-3.5 text-cyber-yellow" />
            </div>
            <p className="text-xl font-bold font-cyber text-cyber-text">{urlhausCount}</p>
            <p className="text-[10px] text-cyber-muted font-light">Malware distributions</p>
          </GlassCard>

          <GlassCard className="p-4 space-y-1" hoverEffect={false}>
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-bold text-cyber-muted tracking-wider">Multi-Source</span>
              <Layers className="w-3.5 h-3.5 text-cyber-green" />
            </div>
            <p className="text-xl font-bold font-cyber text-emerald-400">{multiSourceCount}</p>
            <p className="text-[10px] text-cyber-muted font-light">Correlated threats</p>
          </GlassCard>
        </div>
        
        {/* Bottom charts row */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <ThreatTrendsChart type="dashboard" scans={scans} />
          <ScanDistributionChart type="dashboard" scans={scans} />
        </div>
      </div>

      {/* Right Column - Status sidebar controls */}
      <div className="xl:col-span-4 space-y-8">
        <RecentScans
          scans={scans}
          onSelectScan={setActiveScan}
          activeScanId={activeScan?.id}
        />
        
        <SafeBrowsingToggle />
        
        <AIAssistant />
      </div>
    </div>
  );
};
export default DashboardPage;
