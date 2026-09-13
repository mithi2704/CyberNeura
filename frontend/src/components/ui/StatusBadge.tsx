import React from 'react';

type BadgeType = 'blocked' | 'allowed' | 'flagged' | 'critical' | 'high' | 'medium' | 'low' | 'active' | 'resolved';

interface StatusBadgeProps {
  type: BadgeType | string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ type }) => {
  const getBadgeStyle = (t: string) => {
    const formatted = t.toLowerCase();
    switch (formatted) {
      case 'blocked':
        return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'allowed':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      case 'flagged':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/30 font-bold';
      case 'high':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      case 'medium':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
      case 'low':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
      case 'active':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      case 'resolved':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      default:
        return 'bg-gray-500/10 text-cyber-muted border-gray-500/20';
    }
  };

  return (
    <span
      className={`px-2.5 py-1 text-[10px] font-semibold tracking-wider uppercase rounded-full border ${getBadgeStyle(
        type
      )}`}
    >
      {type}
    </span>
  );
};
export default StatusBadge;
