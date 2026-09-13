import React, { useEffect, useState, useMemo } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { GlassCard } from '../ui/GlassCard';
import type { URLScan, ThreatLog } from '../../types';
import { aiClient } from '../../lib/api/aiService';

interface ScanDistributionChartProps {
  type?: 'dashboard' | 'intel';
  scans?: URLScan[];
  threats?: ThreatLog[];
}

export const ScanDistributionChart: React.FC<ScanDistributionChartProps> = ({
  type = 'dashboard',
  scans,
  threats,
}) => {
  const isDashboard = type === 'dashboard';
  const [remoteData, setRemoteData] = useState<{ name: string; value: number; color?: string }[]>([]);

  // Fetch backend distribution on mount
  useEffect(() => {
    let isMounted = true;
    async function loadDistribution() {
      try {
        const res = await aiClient.get('/dashboard/distribution');
        if (isMounted && res.data && Array.isArray(res.data.data)) {
          setRemoteData(res.data.data);
        }
      } catch {
        // Fallback to local computed data
      }
    }
    loadDistribution();
    return () => {
      isMounted = false;
    };
  }, []);

  // Compute live data from props
  const data = useMemo(() => {
    if (isDashboard) {
      if (scans && scans.length > 0) {
        const safe = scans.filter((s) => s.prediction === 'safe').length;
        const suspicious = scans.filter((s) => s.prediction === 'suspicious').length;
        const malicious = scans.filter((s) => s.prediction === 'malicious').length;

        const items = [
          { name: 'Safe', value: safe, color: '#10b981' },
          { name: 'Suspicious', value: suspicious, color: '#f59e0b' },
          { name: 'Malicious', value: malicious, color: '#ff007f' },
        ];
        return items.filter((item) => item.value > 0 || scans.length === 0);
      }

      if (remoteData.length > 0) {
        return remoteData.filter((item) => item.value > 0);
      }

      return remoteData.filter((item) => item.value > 0);
    } else {
      // Threat Intelligence Detection Breakdown
      if (threats && threats.length > 0) {
        const categories: Record<string, { count: number; color: string }> = {
          Phishing: { count: 0, color: '#ff007f' },
          Malware: { count: 0, color: '#f59e0b' },
          Suspicious: { count: 0, color: '#7c3aed' },
        };

        threats.forEach((t) => {
          const cat = t.category || 'Phishing';
          if (!categories[cat]) {
            categories[cat] = { count: 0, color: '#00d4ff' };
          }
          categories[cat].count += 1;
        });

        return Object.entries(categories)
          .map(([name, meta]) => ({
            name,
            value: meta.count,
            color: meta.color,
          }))
          .filter((item) => item.value > 0);
      }

      return [];
    }
  }, [isDashboard, scans, threats, remoteData]);

  const total = data.reduce((acc, curr) => acc + curr.value, 0);

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const item = payload[0].payload;
      return (
        <div className="bg-[#0b1122]/90 border border-cyber-inner-border p-2.5 rounded-lg shadow-xl font-sans text-xs">
          <p className="font-semibold text-cyber-text mb-0.5">{item.name}</p>
          <p style={{ color: item.color }} className="font-light">
            Volume: <span className="font-semibold">{item.value}</span> ({total > 0 ? ((item.value / total) * 100).toFixed(1) : 0}%)
          </p>
        </div>
      );
    }
    return null;
  };

  const displayData = data.length > 0 
    ? data 
    : [{ name: isDashboard ? 'No Scans' : 'All Clear', value: 1, color: 'rgba(255,255,255,0.08)' }];

  return (
    <GlassCard className="w-full flex flex-col h-[320px]" hoverEffect={false}>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-cyber-text font-cyber tracking-wide">
          {isDashboard ? 'Scan Results Distribution' : 'Detection Breakdown'}
        </h3>
        <span className="text-[10px] uppercase font-bold tracking-widest text-cyber-green px-2 py-0.5 bg-cyber-green/10 rounded-full border border-cyber-green/20">
          Live
        </span>
      </div>

      <div className="flex-1 flex flex-col sm:flex-row items-center justify-center gap-6 relative">
        <div className="w-44 h-44 relative shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              {data.length > 0 && <Tooltip content={<CustomTooltip />} />}
              <Pie
                data={displayData}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={75}
                paddingAngle={data.length > 1 ? 3 : 0}
                dataKey="value"
              >
                {displayData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(255,255,255,0.05)" strokeWidth={1} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          
          {/* Central absolute statistics */}
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-[10px] text-cyber-muted uppercase tracking-widest font-medium">Total</span>
            <span className="text-2xl font-bold font-cyber text-cyber-text tracking-tight">{total}</span>
          </div>
        </div>

        {/* Legend */}
        <div className="space-y-2.5 w-full sm:w-auto shrink-0 text-xs">
          {data.map((item, idx) => (
            <div key={idx} className="flex items-center justify-between sm:justify-start gap-4">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }}></span>
                <span className="text-cyber-muted font-light">{item.name}</span>
              </div>
              <span className="text-cyber-text font-semibold font-cyber pl-2">{item.value}</span>
            </div>
          ))}
          {data.length === 0 && (
            <div className="text-center sm:text-left space-y-1">
              <p className="text-xs text-cyber-green font-medium">
                {isDashboard ? 'No active scans recorded' : 'Zero Threats Detected'}
              </p>
              <p className="text-[10px] text-cyber-muted font-light">
                {isDashboard ? 'Submit a URL to initiate real-time inspection.' : 'All analyzed traffic is verified safe.'}
              </p>
            </div>
          )}
        </div>
      </div>
    </GlassCard>
  );
};
export default ScanDistributionChart;
