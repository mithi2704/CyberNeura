import React, { forwardRef } from 'react';
import type { LucideIcon } from 'lucide-react';

interface CyberInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  icon?: LucideIcon;
  error?: string;
}

export const CyberInput = forwardRef<HTMLInputElement, CyberInputProps>(
  ({ icon: Icon, error, className = '', ...props }, ref) => {
    return (
      <div className="w-full space-y-1.5">
        <div className="relative">
          {Icon && (
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-cyber-muted">
              <Icon className="w-5 h-5" />
            </div>
          )}
          <input
            ref={ref}
            className={`w-full bg-cyber-input border ${
              error ? 'border-red-500/50 focus:border-red-500 focus:ring-red-500/25' : 'border-cyber-border focus:border-cyber-blue/50 focus:ring-cyber-blue/20'
            } rounded-xl py-3 ${
              Icon ? 'pl-11' : 'px-4'
            } pr-4 text-sm text-cyber-text placeholder:text-cyber-muted focus:outline-none focus:ring-4 transition-all duration-300 ${className}`}
            {...props}
          />
        </div>
        {error && <p className="text-xs text-red-400 font-medium pl-1">{error}</p>}
      </div>
    );
  }
);

CyberInput.displayName = 'CyberInput';
export default CyberInput;
