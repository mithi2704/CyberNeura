import React from 'react';

interface RiskBarProps {
  score: number;
  showLabel?: boolean;
}

export const RiskBar: React.FC<RiskBarProps> = ({ score, showLabel = false }) => {
  const getRiskColor = (s: number) => {
    if (s <= 30) return 'from-emerald-500 to-green-400';
    if (s <= 70) return 'from-amber-500 to-yellow-400';
    return 'from-rose-600 to-cyber-pink';
  };

  const getRiskBg = (s: number) => {
    if (s <= 30) return 'bg-emerald-500/10';
    if (s <= 70) return 'bg-amber-500/10';
    return 'bg-rose-500/10';
  };

  return (
    <div className="w-full space-y-1">
      {showLabel && (
        <div className="flex justify-between text-xs font-semibold">
          <span className="text-cyber-muted">Risk Assessment</span>
          <span
            className={
              score <= 30
                ? 'text-cyber-green'
                : score <= 70
                ? 'text-cyber-yellow'
                : 'text-cyber-pink'
            }
          >
            {score}/100
          </span>
        </div>
      )}
      <div className={`w-full h-2 rounded-full overflow-hidden ${getRiskBg(score)} border border-cyber-inner-border`}>
        <div
          className={`h-full bg-gradient-to-r ${getRiskColor(score)} rounded-full shadow-glow transition-all duration-1000 ease-out`}
          style={{ width: `${score}%` }}
        ></div>
      </div>
    </div>
  );
};
export default RiskBar;
