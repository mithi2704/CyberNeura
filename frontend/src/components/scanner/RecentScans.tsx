import React from 'react';
import type { URLScan } from '../../types';
import { CheckCircle2, XCircle, AlertCircle, Clock } from 'lucide-react';
import { GlassCard } from '../ui/GlassCard';

interface RecentScansProps {
  scans: URLScan[];
  onSelectScan: (scan: URLScan) => void;
  activeScanId?: string;
}

export const RecentScans: React.FC<RecentScansProps> = ({
  scans,
  onSelectScan,
  activeScanId,
}) => {
  const getIcon = (pred: 'safe' | 'suspicious' | 'malicious') => {
    switch (pred) {
      case 'safe':
        return <CheckCircle2 className="w-4 h-4 text-cyber-green shrink-0" />;
      case 'malicious':
        return <XCircle className="w-4 h-4 text-cyber-pink shrink-0" />;
      case 'suspicious':
        return <AlertCircle className="w-4 h-4 text-cyber-yellow shrink-0" />;
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

  return (
    <GlassCard className="w-full space-y-4" hoverEffect={false}>
      <h3 className="text-sm font-semibold text-cyber-text font-cyber tracking-wide">
        Recent Scans
      </h3>

      <div className="space-y-2 max-h-[300px] overflow-y-auto custom-scrollbar pr-1">
        {scans.slice(0, 5).map((scan) => (
          <div
            key={scan.id}
            onClick={() => onSelectScan(scan)}
            className={`p-3 rounded-xl border flex items-center justify-between gap-3 cursor-pointer transition-all duration-300 ${
              activeScanId === scan.id
                ? 'bg-cyber-inner border-cyber-blue/30'
                : 'bg-cyber-inner border-cyber-inner-border hover:border-cyber-inner-border'
            }`}
          >
            <div className="flex items-center gap-2.5 overflow-hidden">
              {getIcon(scan.prediction)}
              <span className="text-xs text-cyber-text truncate max-w-[170px]" title={scan.url}>
                {scan.url.replace(/^https?:\/\//i, '')}
              </span>
            </div>
            
            <div className="flex items-center gap-1 text-[10px] text-cyber-muted shrink-0">
              <Clock className="w-3 h-3" />
              <span>{getRelativeTime(scan.scannedAt)}</span>
            </div>
          </div>
        ))}
        {scans.length === 0 && (
          <p className="text-xs text-cyber-muted text-center py-4">No recent scans</p>
        )}
      </div>
    </GlassCard>
  );
};
export default RecentScans;
