import React from 'react';
import { Toggle } from '../ui/Toggle';
import { GlassCard } from '../ui/GlassCard';
import { useSettings } from '../../contexts/ThemeContext';
import { ShieldCheck } from 'lucide-react';

export const SafeBrowsingToggle: React.FC = () => {
  const { settings, updateSettings } = useSettings();

  const handleToggle = (checked: boolean) => {
    updateSettings({ realTimeProtection: checked });
  };

  return (
    <GlassCard className="w-full" hoverEffect={false}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyber-blue/10 border border-cyber-blue/20 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-cyber-blue" />
          </div>
          <div>
            <h4 className="text-xs font-semibold text-cyber-text">Safe Browsing Protection</h4>
            <p className="text-[10px] text-cyber-muted mt-0.5">Real-time threat detection</p>
          </div>
        </div>
        
        <Toggle
          checked={settings?.realTimeProtection ?? true}
          onChange={handleToggle}
        />
      </div>
    </GlassCard>
  );
};
export default SafeBrowsingToggle;
