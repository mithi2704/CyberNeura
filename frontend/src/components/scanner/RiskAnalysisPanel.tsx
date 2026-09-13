import React, { useState } from 'react';
import type { URLScan, RiskFactor, CorrelatedFinding } from '../../types';
import { GlassCard } from '../ui/GlassCard';
import { RiskBar } from '../ui/RiskBar';
import { StatusBadge } from '../ui/StatusBadge';
import { CyberButton } from '../ui/CyberButton';
import { downloadPDFReport } from '../../services/reportService';
import { refreshScanIntelligence } from '../../lib/api/aiService';
import { 
  Search, 
  FileDown, 
  Globe, 
  Clock, 
  Server, 
  Activity, 
  ShieldCheck, 
  ShieldAlert, 
  Shield,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Database,
  Layers,
  Cpu,
  History,
  FileCheck,
  Zap,
  Info
} from 'lucide-react';

interface RiskAnalysisPanelProps {
  scan: URLScan | null;
}

export const RiskAnalysisPanel: React.FC<RiskAnalysisPanelProps> = ({ scan: initialScan }) => {
  const [activeTab, setActiveTab] = useState<'details' | 'riskFactors' | 'evidence' | 'threatIntel' | 'whois' | 'dns'>('details');
  const [currentScan, setCurrentScan] = useState<URLScan | null>(initialScan);
  const [refreshing, setRefreshing] = useState(false);

  // Sync state if prop changes
  React.useEffect(() => {
    setCurrentScan(initialScan);
  }, [initialScan]);

  if (!currentScan) {
    return (
      <GlassCard className="h-[420px] flex flex-col items-center justify-center text-center" hoverEffect={false}>
        <div className="w-20 h-20 rounded-full border border-dashed border-gray-600 flex items-center justify-center mb-4 animate-pulse-glow">
          <Search className="w-8 h-8 text-cyber-muted" />
        </div>
        <h4 className="text-lg font-bold font-cyber text-cyber-text">Risk Analysis</h4>
        <p className="text-sm text-cyber-muted font-light mt-1 max-w-xs">
          Scan a URL to see risk analysis, evidence correlation, and threat intelligence breakdown
        </p>
      </GlassCard>
    );
  }

  const scan = currentScan;
  const isMalicious = scan.prediction === 'malicious';
  const isSuspicious = scan.prediction === 'suspicious';
  const intel = scan.threatIntelligence || {};
  const googleRes = intel.google_webrisk;
  const phishtankRes = intel.phishtank;
  const urlhausRes = intel.urlhaus;

  // Phase 3 Assessment values
  const assessment = scan.riskAssessment;
  const factors: RiskFactor[] = scan.riskFactors || assessment?.risk_factors || [
    {
      id: 'f1',
      factor_type: 'ML_PREDICTION',
      factor_name: 'Machine Learning Probability',
      normalized_value: (scan.probability || (scan.riskScore / 100)),
      weight: 0.30,
      contribution: Math.round((scan.probability || (scan.riskScore / 100)) * 30),
      max_contribution: 30,
      direction: scan.riskScore >= 50 ? 'RISK_INCREASING' : 'RISK_DECREASING',
      description: `Neural model predicted ${scan.prediction} based on lexical features.`,
      created_at: scan.scannedAt,
    },
    {
      id: 'f2',
      factor_type: 'THREAT_INTELLIGENCE',
      factor_name: 'External Threat Intelligence',
      normalized_value: scan.independentConfirmations ? 1.0 : 0.0,
      weight: 0.30,
      contribution: scan.independentConfirmations ? 30 : 0,
      max_contribution: 30,
      direction: scan.independentConfirmations ? 'RISK_INCREASING' : 'NEUTRAL',
      description: scan.independentConfirmations ? `${scan.independentConfirmations} verified provider matches.` : 'No external database matches.',
      created_at: scan.scannedAt,
    },
    {
      id: 'f3',
      factor_type: 'DNS_INFRASTRUCTURE',
      factor_name: 'DNS Resolution',
      normalized_value: scan.ipAddress ? 0.0 : 0.5,
      weight: 0.10,
      contribution: scan.ipAddress ? 0 : 5,
      max_contribution: 10,
      direction: scan.ipAddress ? 'RISK_DECREASING' : 'RISK_INCREASING',
      description: scan.ipAddress ? `Resolves to ${scan.ipAddress}` : 'No valid A records resolved.',
      created_at: scan.scannedAt,
    },
    {
      id: 'f4',
      factor_type: 'WHOIS_DOMAIN',
      factor_name: 'Domain Age',
      normalized_value: 0.2,
      weight: 0.10,
      contribution: 2,
      max_contribution: 10,
      direction: 'NEUTRAL',
      description: scan.domainAge ? `Registered: ${scan.domainAge}` : 'WHOIS details unavailable.',
      created_at: scan.scannedAt,
    },
    {
      id: 'f5',
      factor_type: 'URL_FEATURES',
      factor_name: 'Lexical Features',
      normalized_value: 0.3,
      weight: 0.10,
      contribution: 3,
      max_contribution: 10,
      direction: 'NEUTRAL',
      description: 'Standard lexical syntax analysis.',
      created_at: scan.scannedAt,
    },
    {
      id: 'f6',
      factor_type: 'HISTORICAL_EVIDENCE',
      factor_name: 'Scan History',
      normalized_value: 0.1,
      weight: 0.10,
      contribution: 1,
      max_contribution: 10,
      direction: 'NEUTRAL',
      description: 'Evaluated against prior CyberNeura observations.',
      created_at: scan.scannedAt,
    },
  ];

  const findings: CorrelatedFinding[] = scan.correlatedFindings || assessment?.correlated_findings || [];
  const evidenceItems = scan.evidence || assessment?.evidence || [];
  const severity = scan.severity || assessment?.severity || (isMalicious ? 'CRITICAL' : isSuspicious ? 'MEDIUM' : 'INFO');
  const summary = scan.summary || assessment?.summary || (
    isMalicious 
      ? 'Critical threat indicators identified across analysis sources.' 
      : isSuspicious 
      ? 'Elevated risk signals detected without external confirmation.' 
      : 'Clean security profile. No actionable threat detected.'
  );

  const handleRefresh = async () => {
    if (!scan?.id) return;
    setRefreshing(true);
    try {
      const refreshed = await refreshScanIntelligence(scan.id);
      if (refreshed && (refreshed as any).results) {
        const intelMap: Record<string, any> = {};
        for (const p of (refreshed as any).results) {
          intelMap[p.provider] = p;
        }
        setCurrentScan(prev => prev ? {
          ...prev,
          threatIntelligence: intelMap,
        } : null);
      }
    } catch (err) {
      console.warn('Failed to refresh threat intelligence:', err);
    } finally {
      setRefreshing(false);
    }
  };

  const getProviderBadge = (res?: any) => {
    if (!res || !res.available) {
      if (res?.error && res.error.includes('not configured')) {
        return (
          <span className="text-[10px] font-semibold text-cyber-muted bg-gray-800/40 border border-gray-700/50 px-2 py-0.5 rounded flex items-center gap-1">
            NOT CONFIGURED
          </span>
        );
      }
      return (
        <span className="text-[10px] font-semibold text-cyber-yellow bg-cyber-yellow/10 border border-cyber-yellow/20 px-2 py-0.5 rounded flex items-center gap-1">
          <AlertTriangle className="w-2.5 h-2.5" /> UNAVAILABLE
        </span>
      );
    }
    if (res.matched) {
      return (
        <span className="text-[10px] font-bold text-cyber-pink bg-cyber-pink/10 border border-cyber-pink/30 px-2 py-0.5 rounded flex items-center gap-1 animate-pulse">
          <XCircle className="w-2.5 h-2.5" /> MATCH
        </span>
      );
    }
    return (
      <span className="text-[10px] font-semibold text-cyber-green bg-cyber-green/10 border border-cyber-green/20 px-2 py-0.5 rounded flex items-center gap-1">
        <CheckCircle2 className="w-2.5 h-2.5" /> NO MATCH
      </span>
    );
  };

  return (
    <GlassCard className="w-full space-y-6" hoverEffect={false}>
      {/* Header Panel */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-cyber-inner-border pb-4">
        <div className="space-y-1.5 max-w-full overflow-hidden">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs uppercase text-cyber-blue font-bold font-cyber">Threat Report</span>
            <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
              severity === 'CRITICAL' ? 'text-red-400 bg-red-500/10 border-red-500/30' :
              severity === 'HIGH' ? 'text-cyber-pink bg-cyber-pink/10 border-cyber-pink/30' :
              severity === 'MEDIUM' ? 'text-cyber-yellow bg-cyber-yellow/10 border-cyber-yellow/30' :
              'text-cyber-blue bg-cyber-blue/10 border-cyber-blue/30'
            }`}>
              {severity}
            </span>
            {scan.independentConfirmations && scan.independentConfirmations > 0 ? (
              <span className="text-[10px] uppercase font-bold text-cyber-pink bg-cyber-pink/10 border border-cyber-pink/30 px-2 py-0.5 rounded-full">
                {scan.independentConfirmations} Confirmed Source{scan.independentConfirmations > 1 ? 's' : ''}
              </span>
            ) : null}
          </div>
          <h3 className="text-lg font-semibold text-cyber-text truncate max-w-xl" title={scan.url}>{scan.url}</h3>
          <p className="text-xs text-cyber-muted font-light leading-relaxed">{summary}</p>
        </div>
        <div className="flex items-center gap-2">
          <CyberButton
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-1.5 cursor-pointer whitespace-nowrap text-xs"
            title="Re-query external intelligence providers"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-cyber-blue' : ''}`} />
            {refreshing ? 'Refreshing...' : 'Refresh Intel'}
          </CyberButton>
          <CyberButton
            variant="outline"
            size="sm"
            onClick={() => downloadPDFReport(scan)}
            className="flex items-center gap-2 cursor-pointer whitespace-nowrap text-xs"
          >
            <FileDown className="w-4 h-4" /> Download Report
          </CyberButton>
        </div>
      </div>

      {/* Stats Summary Cards (4-Column Metric Strip) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border space-y-1.5 flex flex-col justify-between">
          <span className="text-[11px] text-cyber-muted uppercase tracking-wider">Prediction</span>
          <div className="flex items-center justify-between mt-1">
            <StatusBadge type={scan.prediction} />
            {isMalicious ? (
              <ShieldAlert className="w-5 h-5 text-cyber-pink" />
            ) : isSuspicious ? (
              <Shield className="w-5 h-5 text-cyber-yellow" />
            ) : (
              <ShieldCheck className="w-5 h-5 text-cyber-green" />
            )}
          </div>
        </div>

        <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border space-y-2">
          <div className="flex justify-between text-[11px] text-cyber-muted uppercase tracking-wider">
            <span>Risk Score</span>
            <span className={isMalicious ? 'text-cyber-pink font-bold' : isSuspicious ? 'text-cyber-yellow font-bold' : 'text-cyber-green font-bold'}>
              {scan.riskScore}/100
            </span>
          </div>
          <RiskBar score={scan.riskScore} />
        </div>

        <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border space-y-1.5 flex flex-col justify-between">
          <span className="text-[11px] text-cyber-muted uppercase tracking-wider">Confidence</span>
          <h4 className="text-xl font-bold font-cyber text-cyber-text mt-1">
            {scan.confidence}% <span className="text-xs text-cyber-muted font-normal">certainty</span>
          </h4>
        </div>

        <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border space-y-1.5 flex flex-col justify-between">
          <span className="text-[11px] text-cyber-muted uppercase tracking-wider">Threat Category</span>
          <div className="flex items-center justify-between mt-1">
            <span className="font-semibold text-cyber-text text-sm">{scan.threatCategory || 'Safe'}</span>
            <span className="text-[11px] text-cyber-muted font-mono">{evidenceItems.length} Evidence</span>
          </div>
        </div>
      </div>

      {/* Evidence Sources Rapid Status Bar (All 7 Sources) */}
      <div className="p-3.5 rounded-xl bg-cyber-inner/70 border border-cyber-inner-border space-y-2 text-xs">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-cyber-muted font-cyber text-[11px] tracking-wide uppercase">
            <Layers className="w-3.5 h-3.5 text-cyber-blue" />
            Evidence Sources Status:
          </div>
          <span className="text-[10px] text-cyber-muted font-mono">
            {evidenceItems.length} facts compiled
          </span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2 text-[11px]">
          {/* ML */}
          <div className="p-2 rounded-lg bg-cyber-input/60 border border-cyber-inner-border flex items-center justify-between gap-1">
            <span className="text-cyber-muted truncate">ML Model</span>
            <span className={`text-[10px] font-bold ${isMalicious ? 'text-cyber-pink' : isSuspicious ? 'text-cyber-yellow' : 'text-cyber-green'}`}>
              {Math.round((scan.probability ?? (scan.riskScore / 100)) * 100)}%
            </span>
          </div>
          {/* Google */}
          <div className="p-2 rounded-lg bg-cyber-input/60 border border-cyber-inner-border flex items-center justify-between gap-1">
            <span className="text-cyber-muted truncate">Google</span>
            {googleRes?.matched ? <span className="text-[10px] font-bold text-cyber-pink">MATCH</span> : <span className="text-[10px] text-cyber-muted">CLEAN</span>}
          </div>
          {/* PhishTank */}
          <div className="p-2 rounded-lg bg-cyber-input/60 border border-cyber-inner-border flex items-center justify-between gap-1">
            <span className="text-cyber-muted truncate">PhishTank</span>
            {phishtankRes?.matched ? <span className="text-[10px] font-bold text-cyber-pink">MATCH</span> : <span className="text-[10px] text-cyber-muted">CLEAN</span>}
          </div>
          {/* URLhaus */}
          <div className="p-2 rounded-lg bg-cyber-input/60 border border-cyber-inner-border flex items-center justify-between gap-1">
            <span className="text-cyber-muted truncate">URLhaus</span>
            {urlhausRes?.matched ? <span className="text-[10px] font-bold text-cyber-pink">MATCH</span> : <span className="text-[10px] text-cyber-muted">CLEAN</span>}
          </div>
          {/* DNS */}
          <div className="p-2 rounded-lg bg-cyber-input/60 border border-cyber-inner-border flex items-center justify-between gap-1">
            <span className="text-cyber-muted truncate">DNS</span>
            <span className="text-[10px] text-cyber-blue font-mono">{scan.ipAddress ? 'OK' : 'ANOMALY'}</span>
          </div>
          {/* WHOIS */}
          <div className="p-2 rounded-lg bg-cyber-input/60 border border-cyber-inner-border flex items-center justify-between gap-1">
            <span className="text-cyber-muted truncate">WHOIS</span>
            <span className="text-[10px] text-cyber-text font-mono truncate max-w-[50px]">{scan.domainAge ? scan.domainAge.split(',')[0] : 'N/A'}</span>
          </div>
          {/* History */}
          <div className="p-2 rounded-lg bg-cyber-input/60 border border-cyber-inner-border flex items-center justify-between gap-1">
            <span className="text-cyber-muted truncate">History</span>
            <span className="text-[10px] text-cyber-green font-mono">RECORDED</span>
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex border-b border-cyber-inner-border text-xs overflow-x-auto custom-scrollbar">
        {(['details', 'riskFactors', 'evidence', 'threatIntel', 'whois', 'dns'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2.5 font-medium border-b-2 transition-all cursor-pointer whitespace-nowrap ${
              activeTab === tab
                ? 'border-cyber-blue text-cyber-text bg-cyber-inner'
                : 'border-transparent text-cyber-muted hover:text-cyber-text'
            }`}
          >
            {tab === 'details' ? 'DETAILS' : 
             tab === 'riskFactors' ? 'RISK FACTORS' : 
             tab === 'evidence' ? `EVIDENCE (${evidenceItems.length})` : 
             tab === 'threatIntel' ? 'THREAT INTEL' : 
             tab.toUpperCase()}
          </button>
        ))}
      </div>

      {/* Tab Panels */}
      <div className="min-h-[260px]">
        {/* TAB 1: DETAILS */}
        {activeTab === 'details' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 animate-in fade-in duration-200">
            {/* Domain Metrics & Security Assessment */}
            <div className="space-y-4">
              <h4 className="text-xs font-bold font-cyber text-cyber-muted uppercase tracking-wider">
                Domain Metrics
              </h4>
              <div className="grid grid-cols-2 gap-4 text-xs">
                <div className="p-3 rounded-lg bg-cyber-inner border border-cyber-inner-border flex items-center gap-3">
                  <Clock className="w-4 h-4 text-cyber-blue shrink-0" />
                  <div>
                    <p className="text-[10px] text-cyber-muted uppercase font-medium">Domain Age</p>
                    <p className="text-cyber-text font-medium mt-0.5">{scan.domainAge || 'Unknown'}</p>
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-cyber-inner border border-cyber-inner-border flex items-center gap-3">
                  <Server className="w-4 h-4 text-cyber-blue shrink-0" />
                  <div>
                    <p className="text-[10px] text-cyber-muted uppercase font-medium">Host Provider</p>
                    <p className="text-cyber-text font-medium mt-0.5 truncate max-w-[120px]">{scan.hostingProvider || 'Unknown'}</p>
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-cyber-inner border border-cyber-inner-border flex items-center gap-3">
                  <Activity className="w-4 h-4 text-cyber-blue shrink-0" />
                  <div>
                    <p className="text-[10px] text-cyber-muted uppercase font-medium">IP Address</p>
                    <p className="text-cyber-text font-medium mt-0.5">{scan.ipAddress || 'Unavailable'}</p>
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-cyber-inner border border-cyber-inner-border flex items-center gap-3">
                  <Globe className="w-4 h-4 text-cyber-blue shrink-0" />
                  <div>
                    <p className="text-[10px] text-cyber-muted uppercase font-medium">Country Target</p>
                    <p className="text-cyber-text font-medium mt-0.5">{scan.country || 'Unknown'}</p>
                  </div>
                </div>
              </div>

              {/* Deterministic CyberNeura Analysis */}
              <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border space-y-2">
                <div className="flex items-center justify-between">
                  <h5 className="text-[11px] font-bold text-cyber-blue uppercase font-cyber tracking-wider flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5" /> CyberNeura Security Assessment
                  </h5>
                  <span className="text-[10px] text-cyber-muted font-mono">v1.0.0</span>
                </div>
                <p className="text-xs text-cyber-text leading-relaxed font-light">
                  {scan.explanation || (
                    scan.prediction === 'safe'
                      ? 'No significant anomalies detected across machine-learning or external databases. Domain footprint aligns with legitimate registered entities.'
                      : scan.prediction === 'suspicious'
                      ? 'Elevated risk signals detected. Domain exhibits structural anomalies without definitive external blacklist confirmation.'
                      : 'Severe threat indicators identified. Independent security telemetry verified active malicious activities.'
                  )}
                </p>
              </div>
            </div>

            {/* Recommendations */}
            <div className="space-y-4">
              <h4 className="text-xs font-bold font-cyber text-cyber-muted uppercase tracking-wider">
                Defensive Action Plan
              </h4>
              <div className="space-y-3">
                {scan.recommendations && scan.recommendations.length > 0 ? (
                  scan.recommendations.map((rec, i) => (
                    <div key={i} className="flex gap-3 text-xs leading-relaxed p-3 rounded-xl bg-cyber-inner/50 border border-cyber-inner-border">
                      <span className="w-5 h-5 rounded-full bg-cyber-blue/10 border border-cyber-blue/20 flex items-center justify-center text-cyber-blue text-[10px] font-bold shrink-0 mt-0.5">
                        {i + 1}
                      </span>
                      <p className="text-cyber-text font-light">{rec}</p>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-cyber-muted">No urgent security actions required.</p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: RISK FACTORS BREAKDOWN */}
        {activeTab === 'riskFactors' && (
          <div className="space-y-5 animate-in fade-in duration-200">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="text-xs font-bold font-cyber text-cyber-muted uppercase tracking-wider">
                  Weighted Factor Contributions
                </h4>
                <p className="text-[11px] text-cyber-muted mt-0.5">
                  Deterministic breakdown of points contributing to the final {scan.riskScore}/100 risk score.
                </p>
              </div>
              <span className="text-xs font-mono font-bold text-cyber-blue bg-cyber-blue/10 px-2.5 py-1 rounded border border-cyber-blue/20">
                Score: {scan.riskScore} / 100
              </span>
            </div>

            <div className="space-y-2.5">
              {factors.map((f, idx) => {
                const pct = Math.min(100, Math.round((f.contribution / (f.max_contribution || 10)) * 100));
                return (
                  <div key={idx} className="p-3.5 rounded-xl bg-cyber-inner border border-cyber-inner-border space-y-2 text-xs">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-cyber-text">{f.factor_name}</span>
                        <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase ${
                          f.direction === 'RISK_INCREASING' ? 'text-cyber-pink bg-cyber-pink/10 border-cyber-pink/20' :
                          f.direction === 'RISK_DECREASING' ? 'text-cyber-green bg-cyber-green/10 border-cyber-green/20' :
                          'text-cyber-muted bg-gray-800/40 border-gray-700/40'
                        }`}>
                          {f.direction.replace('_', ' ')}
                        </span>
                      </div>
                      <div className="font-mono text-xs font-bold text-cyber-text">
                        <span className={f.contribution > 0 ? 'text-cyber-pink' : 'text-cyber-muted'}>
                          +{f.contribution}
                        </span>
                        <span className="text-cyber-muted font-normal text-[10px]"> / {f.max_contribution} pts</span>
                      </div>
                    </div>
                    {/* Progress indicator */}
                    <div className="w-full bg-cyber-input h-1.5 rounded-full overflow-hidden">
                      <div 
                        className={`h-full rounded-full ${
                          f.contribution >= (f.max_contribution * 0.7) ? 'bg-cyber-pink' :
                          f.contribution > 0 ? 'bg-cyber-yellow' : 'bg-cyber-green'
                        }`}
                        style={{ width: `${Math.max(5, pct)}%` }}
                      />
                    </div>
                    <p className="text-[11px] text-cyber-muted font-light">{f.description}</p>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* TAB 3: EVIDENCE ITEMS & CORRELATED FINDINGS */}
        {activeTab === 'evidence' && (
          <div className="space-y-6 animate-in fade-in duration-200">
            {/* Correlated Consensus Findings */}
            {findings && findings.length > 0 && (
              <div className="space-y-3">
                <h4 className="text-xs font-bold font-cyber text-cyber-pink uppercase tracking-wider flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5" /> Correlated Threat Findings
                </h4>
                <div className="space-y-2">
                  {findings.map((finding, idx) => (
                    <div key={idx} className="p-3.5 rounded-xl bg-cyber-inner border border-cyber-pink/30 space-y-1.5 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-cyber-text font-cyber">{finding.finding_type}</span>
                        <span className="text-[10px] font-bold text-red-400 bg-red-500/10 border border-red-500/30 px-2 py-0.5 rounded uppercase">
                          {finding.severity} ({Math.round(finding.confidence * 100)}% Conf)
                        </span>
                      </div>
                      <p className="text-cyber-text font-light text-[11px]">{finding.description}</p>
                      <div className="flex items-center gap-2 pt-1 text-[10px] text-cyber-muted font-mono">
                        <span>Corroborating Sources:</span>
                        {finding.sources.map((s, si) => (
                          <span key={si} className="px-1.5 py-0.5 rounded bg-cyber-input border border-cyber-inner-border text-cyber-blue">
                            {s}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Normalized Evidence List */}
            <div className="space-y-3">
              <h4 className="text-xs font-bold font-cyber text-cyber-muted uppercase tracking-wider">
                Compiled Evidence Objects ({evidenceItems.length})
              </h4>
              {evidenceItems.length > 0 ? (
                <div className="space-y-2 max-h-72 overflow-y-auto pr-1 custom-scrollbar">
                  {evidenceItems.map((ev, idx) => (
                    <div key={idx} className="p-3 rounded-lg bg-cyber-inner border border-cyber-inner-border flex items-start justify-between gap-3 text-xs">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-cyber-text">{ev.source}</span>
                          <span className="text-[10px] text-cyber-muted font-mono">({ev.evidence_type || ev.type})</span>
                          <span className={`text-[9px] font-mono px-1 py-0.2 rounded border ${
                            ev.state === 'CONFIRMED' ? 'text-cyber-pink border-cyber-pink/30' :
                            ev.state === 'UNAVAILABLE' ? 'text-cyber-yellow border-cyber-yellow/30' :
                            'text-cyber-muted border-gray-700/40'
                          }`}>
                            {ev.state || (ev.matched ? 'CONFIRMED' : 'SUPPORTING')}
                          </span>
                        </div>
                        <p className="text-cyber-muted font-light text-[11px]">{ev.description}</p>
                      </div>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase shrink-0 ${
                        ev.severity === 'CRITICAL' ? 'bg-red-500/15 text-red-400 border border-red-500/30' :
                        ev.severity === 'HIGH' ? 'bg-cyber-pink/15 text-cyber-pink border border-cyber-pink/30' :
                        ev.severity === 'MEDIUM' ? 'bg-cyber-yellow/15 text-cyber-yellow border border-cyber-yellow/30' :
                        'bg-cyber-blue/15 text-cyber-blue border border-cyber-blue/30'
                      }`}>
                        {ev.severity}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-cyber-muted">No evidence objects recorded.</p>
              )}
            </div>
          </div>
        )}

        {/* TAB 4: THREAT INTEL */}
        {activeTab === 'threatIntel' && (
          <div className="space-y-6 animate-in fade-in duration-200">
            {/* Provider Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              {/* Google Web Risk */}
              <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-cyber-text">Google Web Risk</span>
                  {getProviderBadge(googleRes)}
                </div>
                <div className="space-y-1 text-[11px] text-cyber-muted">
                  <p>Threat Types: <span className="text-cyber-text">{googleRes?.categories?.length ? googleRes.categories.join(', ') : 'None'}</span></p>
                  <p>Latency: <span className="font-mono text-cyber-text">{googleRes?.latency_ms ? `${googleRes.latency_ms}ms` : '—'}</span></p>
                  {googleRes?.expires_at && (
                    <p className="truncate" title={googleRes.expires_at}>Cache Expires: <span className="font-mono text-cyber-text">{new Date(googleRes.expires_at).toLocaleTimeString()}</span></p>
                  )}
                </div>
              </div>

              {/* PhishTank */}
              <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-cyber-text">PhishTank</span>
                  {getProviderBadge(phishtankRes)}
                </div>
                <div className="space-y-1 text-[11px] text-cyber-muted">
                  <p>Verified Phish: <span className="text-cyber-text">{phishtankRes?.metadata?.verified ? 'Yes' : 'No'}</span></p>
                  <p>Online Status: <span className="text-cyber-text">{phishtankRes?.metadata?.valid ? 'Active' : 'N/A'}</span></p>
                  <p>Latency: <span className="font-mono text-cyber-text">{phishtankRes?.latency_ms ? `${phishtankRes.latency_ms}ms` : '—'}</span></p>
                </div>
              </div>

              {/* URLhaus */}
              <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-cyber-text">URLhaus</span>
                  {getProviderBadge(urlhausRes)}
                </div>
                <div className="space-y-1 text-[11px] text-cyber-muted">
                  <p>Payload Status: <span className="text-cyber-text">{urlhausRes?.metadata?.status || 'None'}</span></p>
                  <p>Tags: <span className="text-cyber-text">{urlhausRes?.metadata?.tags?.length ? urlhausRes.metadata.tags.join(', ') : 'None'}</span></p>
                  <p>Latency: <span className="font-mono text-cyber-text">{urlhausRes?.latency_ms ? `${urlhausRes.latency_ms}ms` : '—'}</span></p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: WHOIS */}
        {activeTab === 'whois' && (
          <div className="animate-in fade-in duration-200">
            <div className="p-4 rounded-xl bg-cyber-input border border-cyber-inner-border font-mono text-xs text-cyber-muted leading-relaxed overflow-x-auto h-60 custom-scrollbar whitespace-pre">
              {scan.whoisRecord || 'No WHOIS record found for this domain.'}
            </div>
          </div>
        )}

        {/* TAB 6: DNS */}
        {activeTab === 'dns' && (
          <div className="animate-in fade-in duration-200">
            <div className="p-4 rounded-xl bg-cyber-input border border-cyber-inner-border font-mono text-xs text-cyber-muted leading-relaxed overflow-x-auto h-60 custom-scrollbar whitespace-pre">
              {scan.dnsRecords || 'No DNS records resolved for this domain.'}
            </div>
          </div>
        )}
      </div>
    </GlassCard>
  );
};

export default RiskAnalysisPanel;
