import React, { useState, useEffect } from 'react';
import { fetchThreatLogs, deleteThreatLog, subscribeToLiveThreats } from '../../services/threatService';
import { getProviderStatus, lookupThreatIntelligence, getEvidenceStats } from '../../lib/api/aiService';
import type { ThreatLog, ProviderStatusInfo, ThreatIntelResult } from '../../types';
import { GlassCard } from '../../components/ui/GlassCard';
import { ThreatTrendsChart } from '../../components/charts/ThreatTrendsChart';
import { ScanDistributionChart } from '../../components/charts/ScanDistributionChart';
import { StatusBadge } from '../../components/ui/StatusBadge';
import { CyberButton } from '../../components/ui/CyberButton';
import { CyberInput } from '../../components/ui/CyberInput';
import { 
  ShieldAlert, 
  Trash2, 
  Radio, 
  Search, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle,
  Server,
  Activity,
  Layers,
  Database,
  ShieldCheck,
  Zap
} from 'lucide-react';

export const ThreatIntelPage: React.FC = () => {
  const [threats, setThreats] = useState<ThreatLog[]>([]);
  const [providers, setProviders] = useState<ProviderStatusInfo[]>([]);
  const [evidenceStats, setEvidenceStats] = useState<{
    total_assessments: number;
    total_evidence_items: number;
    source_breakdown: Record<string, number>;
    severity_breakdown: Record<string, number>;
    total_correlated_findings: number;
  } | null>(null);
  const [lookupUrl, setLookupUrl] = useState('');
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupResult, setLookupResult] = useState<{
    url: string;
    providers: ThreatIntelResult[];
    independentConfirmations: number;
    checkedAt: string;
  } | null>(null);

  const loadData = async () => {
    try {
      const [list, provRes, statsRes] = await Promise.all([
        fetchThreatLogs(),
        getProviderStatus(),
        getEvidenceStats().catch(() => null),
      ]);
      setThreats(list);
      if (provRes && provRes.providers) {
        setProviders(provRes.providers);
      }
      if (statsRes) {
        setEvidenceStats(statsRes);
      }
    } catch (err) {
      console.warn('Threat Intel page data load warning:', err);
    }
  };

  useEffect(() => {
    loadData();

    // Subscribe to live threats telemetry
    const unsubscribe = subscribeToLiveThreats((newThreat) => {
      setThreats(prev => {
        if (prev.some(t => t.url === newThreat.url)) return prev;
        return [newThreat, ...prev];
      });
    });

    return () => {
      unsubscribe();
    };
  }, []);

  const handleDeleteThreat = async (id: string) => {
    const success = await deleteThreatLog(id);
    if (success) {
      setThreats(prev => prev.filter(t => t.id !== id));
    }
  };

  const handleManualLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupUrl.trim()) return;
    setLookupLoading(true);
    try {
      const res = await lookupThreatIntelligence(lookupUrl.trim());
      setLookupResult(res);
    } catch (err) {
      console.warn('Manual threat lookup failed:', err);
    } finally {
      setLookupLoading(false);
    }
  };

  const getRelativeTime = (isoString: string) => {
    try {
      const ms = Date.now() - new Date(isoString).getTime();
      const minutes = Math.floor(ms / 60000);
      if (minutes < 1) return 'Just now';
      if (minutes < 60) return `${minutes} min ago`;
      const hours = Math.floor(minutes / 60);
      if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
      return new Date(isoString).toLocaleDateString();
    } catch (e) {
      return 'Recent';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'HEALTHY':
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
      case 'DEGRADED':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
      default:
        return 'text-cyber-muted bg-gray-800/40 border-gray-700/50';
    }
  };

  return (
    <div className="space-y-8">
      {/* 1. Live Threat Intelligence Provider Status Strip */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {providers.map((p) => (
          <GlassCard key={p.name} className="p-4" hoverEffect={false}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-cyber-blue" />
                <span className="text-xs font-semibold text-cyber-text capitalize">
                  {p.name.replace('_', ' ')}
                </span>
              </div>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${getStatusColor(p.status)}`}>
                {p.status.replace('_', ' ')}
              </span>
            </div>
            <div className="mt-2.5 flex items-center justify-between text-[10px] text-cyber-muted">
              <span>Configuration: <strong className="text-cyber-text font-normal">{p.configured ? 'Active' : 'Unconfigured'}</strong></span>
              <span>Mode: <strong className="text-cyber-text font-normal">{p.enabled ? 'Enabled' : 'Disabled'}</strong></span>
            </div>
          </GlassCard>
        ))}
        {providers.length === 0 && (
          <>
            <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border text-xs text-cyber-muted flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyber-blue animate-pulse" />
              <span>Google Web Risk: Synchronizing...</span>
            </div>
            <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border text-xs text-cyber-muted flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyber-blue animate-pulse" />
              <span>PhishTank: Synchronizing...</span>
            </div>
            <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border text-xs text-cyber-muted flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyber-blue animate-pulse" />
              <span>URLhaus: Synchronizing...</span>
            </div>
          </>
        )}
      </div>

      {/* 2. Phase 3 Multi-Source Evidence Intelligence Overview */}
      {evidenceStats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border space-y-1">
            <span className="text-[11px] text-cyber-muted uppercase tracking-wider">Analyzed Targets</span>
            <h4 className="text-xl font-bold font-cyber text-cyber-text">
              {evidenceStats.total_assessments} <span className="text-xs text-cyber-muted font-normal">scans</span>
            </h4>
          </div>
          <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border space-y-1">
            <span className="text-[11px] text-cyber-muted uppercase tracking-wider">Compiled Facts</span>
            <h4 className="text-xl font-bold font-cyber text-cyber-blue">
              {evidenceStats.total_evidence_items} <span className="text-xs text-cyber-muted font-normal">items</span>
            </h4>
          </div>
          <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border space-y-1">
            <span className="text-[11px] text-cyber-muted uppercase tracking-wider">Critical Evidence</span>
            <h4 className="text-xl font-bold font-cyber text-cyber-pink">
              {evidenceStats.severity_breakdown?.CRITICAL ?? 0} <span className="text-xs text-cyber-muted font-normal">flags</span>
            </h4>
          </div>
          <div className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border space-y-1">
            <span className="text-[11px] text-cyber-muted uppercase tracking-wider">Correlated Findings</span>
            <h4 className="text-xl font-bold font-cyber text-cyber-yellow">
              {evidenceStats.total_correlated_findings} <span className="text-xs text-cyber-muted font-normal">consensus</span>
            </h4>
          </div>
        </div>
      )}

      {/* 3. On-Demand Threat Intelligence Reputation Lookup */}
      <GlassCard hoverEffect={false}>
        <div className="flex items-center gap-2 mb-4">
          <Layers className="w-4 h-4 text-cyber-blue" />
          <h3 className="text-xs font-semibold text-cyber-text font-cyber uppercase tracking-wider">
            Direct Threat Intelligence Query
          </h3>
        </div>
        <form onSubmit={handleManualLookup} className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1">
            <CyberInput
              value={lookupUrl}
              onChange={(e) => setLookupUrl(e.target.value)}
              placeholder="Enter indicator (URL or domain) for multi-source intelligence reputation..."
              icon={Search}
              className="text-xs py-2"
            />
          </div>
          <CyberButton
            variant="primary"
            size="sm"
            type="submit"
            disabled={lookupLoading || !lookupUrl.trim()}
            className="cursor-pointer whitespace-nowrap text-xs"
          >
            {lookupLoading ? 'Checking Providers...' : 'Query Intel'}
          </CyberButton>
        </form>

        {/* Lookup Results Card */}
        {lookupResult && (
          <div className="mt-4 p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border space-y-3 animate-in fade-in duration-200">
            <div className="flex items-center justify-between text-xs border-b border-cyber-inner-border pb-2">
              <span className="font-semibold text-cyber-text truncate max-w-md">{lookupResult.url}</span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                lookupResult.independentConfirmations > 0 ? 'bg-cyber-pink/20 text-cyber-pink border border-cyber-pink/30' : 'bg-cyber-green/20 text-cyber-green border border-cyber-green/30'
              }`}>
                {lookupResult.independentConfirmations > 0 ? `${lookupResult.independentConfirmations} Confirmed Threat Matches` : 'Clean Reputation'}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
              {lookupResult.providers.map((p) => (
                <div key={p.provider} className="p-3 rounded-lg bg-cyber-input/60 border border-cyber-inner-border space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-cyber-text capitalize">{p.provider.replace('_', ' ')}</span>
                    {p.matched ? (
                      <span className="text-[10px] font-bold text-cyber-pink flex items-center gap-1">
                        <XCircle className="w-2.5 h-2.5" /> MATCH
                      </span>
                    ) : p.available ? (
                      <span className="text-[10px] font-semibold text-cyber-green flex items-center gap-1">
                        <CheckCircle2 className="w-2.5 h-2.5" /> NO MATCH
                      </span>
                    ) : (
                      <span className="text-[10px] font-semibold text-cyber-yellow flex items-center gap-1">
                        <AlertTriangle className="w-2.5 h-2.5" /> {p.verdict}
                      </span>
                    )}
                  </div>
                  {p.categories?.length > 0 && (
                    <p className="text-[10px] text-cyber-muted truncate">Type: {p.categories.join(', ')}</p>
                  )}
                  <p className="text-[10px] text-cyber-muted font-mono">{p.latency_ms}ms latency</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </GlassCard>

      {/* Visualizers row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2">
          <ThreatTrendsChart type="intel" threats={threats} />
        </div>
        <div>
          <ScanDistributionChart type="intel" threats={threats} />
        </div>
      </div>

      {/* Live Threat Intelligence Feed */}
      <GlassCard className="w-full" hoverEffect={false}>
        <div className="flex items-center justify-between border-b border-cyber-inner-border pb-4 mb-6">
          <div className="flex items-center gap-2.5">
            <div className="relative">
              <span className="absolute inset-0 bg-cyber-pink/20 rounded-full blur-[4px] animate-ping"></span>
              <Radio className="w-5 h-5 text-cyber-pink relative z-10 animate-pulse" />
            </div>
            <h3 className="text-sm font-semibold text-cyber-text font-cyber tracking-wide">
              Live Threat Intelligence Feed
            </h3>
          </div>
          <span className="text-[10px] uppercase font-bold tracking-widest text-cyber-pink px-2.5 py-0.5 bg-cyber-pink/10 rounded-full border border-cyber-pink/20">
            Realtime Active
          </span>
        </div>

        {/* Live List Scrollbox */}
        <div className="space-y-3 max-h-[480px] overflow-y-auto pr-1 custom-scrollbar">
          {threats.map((threat) => (
            <div
              key={threat.id}
              className="p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border hover:border-cyber-pink/20 transition-all duration-300 flex items-center justify-between gap-4 animate-in slide-in-from-top-3 duration-300"
            >
              <div className="flex items-center gap-3 overflow-hidden">
                <ShieldAlert className="w-4 h-4 text-cyber-pink shrink-0" />
                <div className="space-y-0.5 overflow-hidden">
                  <span className="text-xs font-medium text-cyber-text truncate block max-w-sm sm:max-w-md lg:max-w-2xl" title={threat.url}>
                    {threat.url}
                  </span>
                  <span className="text-[10px] text-cyber-muted">
                    Category: <strong className="text-cyber-text font-normal">{threat.category}</strong>
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-4 shrink-0">
                <StatusBadge type={threat.severity} />
                
                <span className="text-[10px] text-cyber-muted font-light whitespace-nowrap min-w-[70px] text-right">
                  {getRelativeTime(threat.timestamp)}
                </span>
                
                <button
                  onClick={() => handleDeleteThreat(threat.id)}
                  className="p-1.5 rounded-lg bg-cyber-inner border border-cyber-inner-border text-cyber-muted hover:text-red-400 hover:bg-red-500/10 cursor-pointer transition"
                  title="Remove threat alert"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
          {threats.length === 0 && (
            <div className="text-center py-12 px-4 space-y-3">
              <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mx-auto text-cyber-green">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <div className="space-y-1">
                <h4 className="text-sm font-semibold text-cyber-text font-cyber">No Active Threats Detected</h4>
                <p className="text-xs text-cyber-muted max-w-md mx-auto font-light">
                  All monitored domain and URL telemetry is verified clean. Identified high-risk URLs and multi-source provider confirmations will appear here in real time.
                </p>
              </div>
            </div>
          )}
        </div>
      </GlassCard>
    </div>
  );
};
export default ThreatIntelPage;
