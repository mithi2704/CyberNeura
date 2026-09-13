import React, { useEffect, useState, useMemo } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  LineChart,
  Line,
  Legend,
} from 'recharts';
import { GlassCard } from '../ui/GlassCard';
import type { URLScan, ThreatLog } from '../../types';
import { aiClient } from '../../lib/api/aiService';

interface ThreatTrendsChartProps {
  type?: 'dashboard' | 'intel';
  scans?: URLScan[];
  threats?: ThreatLog[];
}

export const ThreatTrendsChart: React.FC<ThreatTrendsChartProps> = ({
  type = 'dashboard',
  scans,
  threats,
}) => {
  const isDashboard = type === 'dashboard';
  const [remoteTrends, setRemoteTrends] = useState<any[]>([]);

  // Fetch backend trends
  useEffect(() => {
    let isMounted = true;
    async function loadTrends() {
      try {
        const res = await aiClient.get('/dashboard/trends');
        if (isMounted && res.data && Array.isArray(res.data.data)) {
          setRemoteTrends(res.data.data);
        }
      } catch {
        // Fallback to local computation
      }
    }
    loadTrends();
    return () => {
      isMounted = false;
    };
  }, []);

  // Compute live data
  const data = useMemo(() => {
    const days = 7;
    const now = new Date();

    if (isDashboard) {
      if (scans && scans.length > 0) {
        // Build map of last 7 days
        const dateMap: Record<string, { name: string; count: number; threats: number }> = {};
        for (let i = days - 1; i >= 0; i--) {
          const d = new Date(now.getTime() - i * 24 * 3600000);
          const key = d.toISOString().slice(0, 10);
          const monthName = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
          dateMap[key] = { name: monthName, count: 0, threats: 0 };
        }

        scans.forEach((s) => {
          const dKey = (s.scannedAt || '').slice(0, 10);
          if (dateMap[dKey]) {
            dateMap[dKey].count += 1;
            if (s.prediction !== 'safe') {
              dateMap[dKey].threats += 1;
            }
          } else {
            // Attribute to today
            const todayKey = now.toISOString().slice(0, 10);
            if (dateMap[todayKey]) {
              dateMap[todayKey].count += 1;
              if (s.prediction !== 'safe') {
                dateMap[todayKey].threats += 1;
              }
            }
          }
        });

        return Object.values(dateMap);
      }

      if (remoteTrends.length > 0) {
        return remoteTrends.map((t) => ({
          name: t.name || t.date?.slice(5) || 'Day',
          count: t.count ?? (t.safe + t.suspicious + t.malicious),
        }));
      }

      // Authentic 7-day default buckets (zero counts if no scans recorded)
      const emptyDays = [];
      for (let i = days - 1; i >= 0; i--) {
        const d = new Date(now.getTime() - i * 24 * 3600000);
        emptyDays.push({
          name: d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
          count: 0,
        });
      }
      return emptyDays;
    } else {
      // Threat Intelligence daily trends
      const intelMap: Record<string, { name: string; phishing: number; malware: number; suspicious: number }> = {};
      const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

      for (let i = days - 1; i >= 0; i--) {
        const d = new Date(now.getTime() - i * 24 * 3600000);
        const key = d.toISOString().slice(0, 10);
        intelMap[key] = {
          name: dayNames[d.getDay()],
          phishing: 0,
          malware: 0,
          suspicious: 0,
        };
      }

      const activeThreats = threats && threats.length > 0 ? threats : [];
      activeThreats.forEach((t) => {
        const dKey = (t.timestamp || '').slice(0, 10);
        const cat = (t.category || '').toLowerCase();
        const target = intelMap[dKey] || intelMap[now.toISOString().slice(0, 10)];
        if (target) {
          if (cat.includes('phish')) target.phishing += 1;
          else if (cat.includes('malware')) target.malware += 1;
          else target.suspicious += 1;
        }
      });

      return Object.values(intelMap);
    }
  }, [isDashboard, scans, threats, remoteTrends]);

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-[#0b1122]/90 border border-cyber-inner-border p-3 rounded-lg shadow-xl font-sans text-xs">
          <p className="font-semibold text-white mb-1">{label}</p>
          {payload.map((item: any, index: number) => (
            <p key={index} style={{ color: item.color }} className="font-light">
              <span className="capitalize">{item.name}</span>: <span className="font-semibold">{item.value}</span>
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <GlassCard className="w-full flex flex-col h-[320px]" hoverEffect={false}>
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-sm font-semibold text-white font-cyber tracking-wide">
          {isDashboard ? 'Threats & Scans Over Time' : 'Threat Trends (Last 7 Days)'}
        </h3>
        <span className="text-[10px] uppercase font-bold tracking-widest text-cyber-blue px-2 py-0.5 bg-cyber-blue/10 rounded-full border border-cyber-blue/20">
          Realtime Active
        </span>
      </div>

      <div className="flex-1 w-full text-[10px] text-cyber-muted font-mono">
        <ResponsiveContainer width="100%" height="100%">
          {isDashboard ? (
            <AreaChart data={data as any[]} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#7c3aed" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
              <XAxis dataKey="name" stroke="#6b7280" tickLine={false} axisLine={false} />
              <YAxis stroke="#6b7280" tickLine={false} axisLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area
                type="monotone"
                dataKey="count"
                name="Total Scans"
                stroke="url(#colorCount)"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorCount)"
                activeDot={{ r: 6, stroke: '#00d4ff', strokeWidth: 1, fill: '#080c18' }}
              />
            </AreaChart>
          ) : (
            <LineChart data={data as any[]} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
              <XAxis dataKey="name" stroke="#6b7280" tickLine={false} axisLine={false} />
              <YAxis stroke="#6b7280" tickLine={false} axisLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Legend
                verticalAlign="bottom"
                height={36}
                iconType="circle"
                iconSize={6}
                wrapperStyle={{ paddingTop: '10px' }}
              />
              <Line
                name="phishing"
                type="monotone"
                dataKey="phishing"
                stroke="#ff007f"
                strokeWidth={2}
                dot={{ r: 3 }}
                activeDot={{ r: 5 }}
              />
              <Line
                name="malware"
                type="monotone"
                dataKey="malware"
                stroke="#f59e0b"
                strokeWidth={2}
                dot={{ r: 3 }}
                activeDot={{ r: 5 }}
              />
              <Line
                name="suspicious"
                type="monotone"
                dataKey="suspicious"
                stroke="#7c3aed"
                strokeWidth={2}
                dot={{ r: 3 }}
                activeDot={{ r: 5 }}
              />
            </LineChart>
          )}
        </ResponsiveContainer>
      </div>
    </GlassCard>
  );
};
export default ThreatTrendsChart;
