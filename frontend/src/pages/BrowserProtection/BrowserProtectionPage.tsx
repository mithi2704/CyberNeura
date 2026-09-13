import React, { useState, useEffect } from 'react';
import { GlassCard } from '../../components/ui/GlassCard';
import { StatusBadge } from '../../components/ui/StatusBadge';
import { realtimeService } from '../../services/realtimeService';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  ExternalLink, 
  RefreshCw, 
  Laptop, 
  Activity, 
  Info 
} from 'lucide-react';

interface ExtensionEventItem {
  id: string;
  scan_id?: string;
  url: string;
  decision: 'ALLOW' | 'WARN' | 'BLOCK';
  risk_score: number;
  prediction: string;
  threat_category?: string;
  user_override?: boolean;
  timestamp: string;
  browser?: string;
  installation_id?: string;
}

interface ExtensionStats {
  total_events: number;
  blocked: number;
  warned: number;
  allowed: number;
  overrides: number;
  active_installations: number;
}

export const BrowserProtectionPage: React.FC = () => {
  const [events, setEvents] = useState<ExtensionEventItem[]>([]);
  const [stats, setStats] = useState<ExtensionStats>({
    total_events: 0,
    blocked: 0,
    warned: 0,
    allowed: 0,
    overrides: 0,
    active_installations: 1,
  });
  const [loading, setLoading] = useState<boolean>(true);
  const [backendOnline, setBackendOnline] = useState<boolean>(true);

  const fetchExtensionData = async () => {
    try {
      const [eventsRes, statsRes] = await Promise.all([
        fetch('http://localhost:8000/api/v1/extension/events?limit=20').then((r) => r.json()),
        fetch('http://localhost:8000/api/v1/extension/stats').then((r) => r.json()),
      ]);

      if (eventsRes?.events) {
        setEvents(eventsRes.events);
      }
      if (statsRes) {
        setStats(statsRes);
      }
      setBackendOnline(true);
    } catch (err) {
      console.warn('Could not fetch extension data from backend:', err);
      setBackendOnline(false);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchExtensionData();

    // Subscribe to Phase 5 Realtime scan events
    const unsub = realtimeService.subscribeToScans((scan) => {
      const newEvent: ExtensionEventItem = {
        id: scan.id || String(Date.now()),
        scan_id: scan.id,
        url: scan.url || 'Unknown URL',
        decision: scan.riskScore >= 70 ? 'BLOCK' : scan.riskScore >= 30 ? 'WARN' : 'ALLOW',
        risk_score: scan.riskScore || 0,
        prediction: scan.prediction?.toUpperCase() || 'SAFE',
        threat_category: scan.threatCategory,
        user_override: false,
        timestamp: scan.scannedAt || new Date().toISOString(),
        browser: 'chrome',
      };

      setEvents((prev) => [newEvent, ...prev.filter((e) => e.id !== newEvent.id)].slice(0, 30));
      setStats((prev) => ({
        ...prev,
        total_events: prev.total_events + 1,
        blocked: newEvent.decision === 'BLOCK' ? prev.blocked + 1 : prev.blocked,
        warned: newEvent.decision === 'WARN' ? prev.warned + 1 : prev.warned,
        allowed: newEvent.decision === 'ALLOW' ? prev.allowed + 1 : prev.allowed,
      }));
    });

    return () => {
      unsub();
    };
  }, []);

  const formatTime = (isoString: string) => {
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return isoString;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 bg-cyber-inner border border-cyber-inner-border p-6 rounded-2xl">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-cyber-blue/15 text-cyber-blue border border-cyber-blue/30 flex items-center justify-center">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-cyber-text tracking-wide font-cyber flex items-center gap-3">
              Browser Protection
              <span className={`text-xs px-2.5 py-0.5 rounded-full font-sans font-semibold border ${
                backendOnline 
                  ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' 
                  : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
              }`}>
                {backendOnline ? '● Protection Active' : '○ Standby Mode'}
              </span>
            </h1>
            <p className="text-xs text-cyber-muted mt-1">
              Real-time Chrome Extension telemetry, active interception metrics, and live security policy enforcement.
            </p>
          </div>
        </div>

        <button
          onClick={fetchExtensionData}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-cyber-card border border-cyber-inner-border text-xs text-cyber-text hover:text-cyber-blue transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh Status
        </button>
      </div>

      {/* KPI Metrics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <GlassCard hoverEffect={false}>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/20">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-semibold tracking-wider text-cyber-muted">
                Inspected URLs
              </span>
              <p className="text-2xl font-bold font-cyber text-cyber-text mt-0.5">
                {stats.total_events}
              </p>
            </div>
          </div>
        </GlassCard>

        <GlassCard hoverEffect={false}>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-semibold tracking-wider text-cyber-muted">
                Threats Blocked
              </span>
              <p className="text-2xl font-bold font-cyber text-rose-400 mt-0.5">
                {stats.blocked}
              </p>
            </div>
          </div>
        </GlassCard>

        <GlassCard hoverEffect={false}>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-semibold tracking-wider text-cyber-muted">
                Warnings Issued
              </span>
              <p className="text-2xl font-bold font-cyber text-amber-400 mt-0.5">
                {stats.warned}
              </p>
            </div>
          </div>
        </GlassCard>

        <GlassCard hoverEffect={false}>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-cyber-pink/10 text-cyber-pink border border-cyber-pink/20">
              <Laptop className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-semibold tracking-wider text-cyber-muted">
                User Overrides
              </span>
              <p className="text-2xl font-bold font-cyber text-cyber-pink mt-0.5">
                {stats.overrides}
              </p>
            </div>
          </div>
        </GlassCard>
      </div>

      {/* Main Content Grid: Live Feed & Installation Guide */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Live Feed Table (2 cols) */}
        <div className="lg:col-span-2">
          <GlassCard hoverEffect={false}>
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-cyber-inner-border">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-cyber-blue" />
                <h3 className="text-sm font-semibold text-cyber-text font-cyber tracking-wide">
                  Live Browser Security Stream
                </h3>
              </div>
              <span className="text-[10px] text-cyber-muted font-mono">
                {events.length} recent events
              </span>
            </div>

            {loading ? (
              <div className="text-center py-12 text-cyber-muted text-xs">
                Synchronizing extension activity...
              </div>
            ) : events.length === 0 ? (
              <div className="text-center py-12 text-cyber-muted text-xs">
                No recent browser protection events recorded. Browse the web with CyberNeura extension enabled to stream detections live.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-light">
                  <thead>
                    <tr className="border-b border-cyber-inner-border text-cyber-muted font-medium">
                      <th className="pb-3 pr-4">URL</th>
                      <th className="pb-3 pr-4">Risk</th>
                      <th className="pb-3 pr-4">Decision</th>
                      <th className="pb-3 pr-4">Threat</th>
                      <th className="pb-3 pr-4">Override</th>
                      <th className="pb-3 text-right">Time</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 text-cyber-text">
                    {events.map((e) => (
                      <tr key={e.id} className="hover:bg-cyber-inner transition">
                        <td className="py-3 pr-4 font-medium truncate max-w-xs" title={e.url}>
                          {e.url}
                        </td>
                        <td className="py-3 pr-4">
                          <span className={`font-mono font-bold text-[11px] ${
                            e.risk_score >= 70 ? 'text-rose-400' : e.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'
                          }`}>
                            {e.risk_score}
                          </span>
                        </td>
                        <td className="py-3 pr-4">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase border ${
                            e.decision === 'BLOCK'
                              ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                              : e.decision === 'WARN'
                              ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                              : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                          }`}>
                            {e.decision}
                          </span>
                        </td>
                        <td className="py-3 pr-4 font-mono text-[11px] text-cyber-muted">
                          {e.threat_category || 'Safe'}
                        </td>
                        <td className="py-3 pr-4 font-mono text-[10px]">
                          {e.user_override ? (
                            <span className="text-amber-400 font-bold">YES</span>
                          ) : (
                            <span className="text-cyber-muted">NO</span>
                          )}
                        </td>
                        <td className="py-3 text-right font-mono text-[11px] text-cyber-muted">
                          {formatTime(e.timestamp)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </GlassCard>
        </div>

        {/* Installation & Configuration Card (1 col) */}
        <div className="space-y-6">
          <GlassCard hoverEffect={false}>
            <div className="flex items-center gap-2 pb-4 mb-4 border-b border-cyber-inner-border">
              <Info className="w-4 h-4 text-cyber-blue" />
              <h3 className="text-sm font-semibold text-cyber-text font-cyber tracking-wide">
                Chrome Extension Setup
              </h3>
            </div>

            <div className="space-y-4 text-xs text-cyber-muted leading-relaxed">
              <p>
                The CyberNeura Manifest V3 Chrome Extension is built and ready to load as an unpacked extension.
              </p>
              
              <div className="bg-cyber-input p-3 rounded-lg border border-cyber-inner-border font-mono text-[11px] text-cyber-text space-y-1.5">
                <div>1. Open <span className="text-cyber-blue">chrome://extensions</span></div>
                <div>2. Enable <span className="text-cyber-blue">Developer mode</span></div>
                <div>3. Click <span className="text-cyber-blue">Load unpacked</span></div>
                <div>4. Select directory:</div>
                <div className="text-cyber-pink font-semibold truncate">CyberNeura/extension/dist</div>
              </div>

              <div className="border-t border-cyber-inner-border pt-4">
                <h4 className="text-xs font-semibold text-cyber-text mb-1">Authoritative Backend URL</h4>
                <p className="font-mono text-[11px] text-cyber-blue">http://localhost:8000</p>
              </div>

              <div className="border-t border-cyber-inner-border pt-4">
                <h4 className="text-xs font-semibold text-cyber-text mb-1">Privacy Guarantee</h4>
                <p className="text-[11px]">
                  Operates under zero-surveillance rules: no passwords, DOM contents, cookies, or history are inspected.
                </p>
              </div>
            </div>
          </GlassCard>
        </div>
      </div>
    </div>
  );
};
