import React from 'react';

interface GlassCardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  glow?: 'blue' | 'purple' | 'none';
  hoverEffect?: boolean;
}

export const GlassCard: React.FC<GlassCardProps> = ({
  children,
  glow = 'none',
  hoverEffect = true,
  className = '',
  ...props
}) => {
  const glowClasses = {
    blue: 'glass-panel-glow-blue',
    purple: 'glass-panel-glow-purple',
    none: 'glass-panel',
  };

  return (
    <div
      className={`rounded-2xl p-6 ${glowClasses[glow]} transition-all duration-300 ${
        hoverEffect ? 'hover:scale-[1.01] hover:border-cyber-blue/30' : ''
      } ${className}`}
      {...props}
    >
      {children}
    </div>
  );
};
export default GlassCard;
