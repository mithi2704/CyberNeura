import React from 'react';

interface CyberButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  glow?: boolean;
  loading?: boolean;
  children: React.ReactNode;
}

export const CyberButton: React.FC<CyberButtonProps> = ({
  variant = 'primary',
  size = 'md',
  glow = true,
  loading = false,
  children,
  className = '',
  disabled,
  ...props
}) => {
  const getVariantStyles = () => {
    switch (variant) {
      case 'primary':
        return 'bg-gradient-to-r from-cyber-blue to-cyber-purple text-[#050814] font-bold border border-white/20 hover:brightness-110';
      case 'secondary':
        return 'bg-cyber-inner text-cyber-text border border-cyber-border hover:bg-black/5 dark:hover:bg-white/10';
      case 'outline':
        return 'bg-transparent text-cyber-blue border border-cyber-blue/30 hover:bg-cyber-blue/5 hover:border-cyber-blue/60';
      case 'danger':
        return 'bg-rose-500/10 text-rose-400 border border-rose-500/20 hover:bg-rose-500/20';
      default:
        return '';
    }
  };

  const getSizeStyles = () => {
    switch (size) {
      case 'sm':
        return 'px-3 py-1.5 text-xs rounded-lg';
      case 'md':
        return 'px-5 py-2.5 text-sm rounded-xl';
      case 'lg':
        return 'px-7 py-3 text-base rounded-2xl';
      default:
        return '';
    }
  };

  const getGlowStyles = () => {
    if (!glow || disabled || loading) return '';
    switch (variant) {
      case 'primary':
        return 'hover:shadow-glow';
      case 'outline':
        return 'hover:shadow-[0_0_12px_rgba(0,212,255,0.2)]';
      case 'danger':
        return 'hover:shadow-[0_0_12px_rgba(239,68,68,0.2)]';
      default:
        return '';
    }
  };

  return (
    <button
      className={`inline-flex items-center justify-center gap-2 cursor-pointer font-medium transition-all duration-300 transform active:scale-95 disabled:opacity-50 disabled:pointer-events-none ${getVariantStyles()} ${getSizeStyles()} ${getGlowStyles()} ${className}`}
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <span className="w-4 h-4 rounded-full border-2 border-current border-t-transparent animate-spin"></span>
      )}
      {children}
    </button>
  );
};
export default CyberButton;
