import React from 'react';
import { GlassCard } from './GlassCard';
import type { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  trendDirection?: 'up' | 'down' | 'neutral';
  trendLabel?: string;
  iconColor?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  icon: Icon,
  trend,
  trendDirection = 'neutral',
  trendLabel = 'from yesterday',
  iconColor = 'text-cyber-blue',
}) => {
  return (
    <GlassCard hoverEffect={true} className="flex items-center justify-between">
      <div className="space-y-2">
        <span className="text-xs text-cyber-muted font-light">{title}</span>
        <h3 className="text-3xl font-bold font-cyber text-cyber-text tracking-tight">{value}</h3>
        {trend && (
          <div className="flex items-center gap-1.5 text-[11px]">
            <span
              className={`font-semibold ${
                trendDirection === 'up'
                  ? 'text-cyber-green'
                  : trendDirection === 'down'
                  ? 'text-cyber-pink'
                  : 'text-cyber-muted'
              }`}
            >
              {trend}
            </span>
            <span className="text-cyber-muted font-light">{trendLabel}</span>
          </div>
        )}
      </div>

      <div className="w-12 h-12 rounded-xl bg-cyber-inner border border-cyber-inner-border flex items-center justify-center relative group">
        <Icon className={`w-6 h-6 ${iconColor}`} />
        <div className="absolute inset-0 bg-cyber-blue/10 rounded-xl blur opacity-0 group-hover:opacity-40 transition-opacity duration-300"></div>
      </div>
    </GlassCard>
  );
};
export default StatCard;
