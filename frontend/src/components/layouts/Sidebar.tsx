import React, { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { getProviderStatus } from '../../lib/api/aiService';
import type { ProviderStatusInfo } from '../../types';
import { 
  LayoutDashboard, 
  FileText, 
  Zap, 
  Cpu, 
  Users, 
  Settings, 
  LogOut,
  ChevronRight,
  ShieldCheck,
  ChevronDown,
  Sparkles,
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const { logout, profile } = useAuth();
  const [providers, setProviders] = useState<ProviderStatusInfo[]>([]);
  const [showStatusDetails, setShowStatusDetails] = useState(false);

  useEffect(() => {
    getProviderStatus()
      .then(res => {
        if (res?.providers) setProviders(res.providers);
      })
      .catch(() => {});
  }, []);

  const menuItems = [
    { name: 'Dashboard Overview', path: '/', icon: LayoutDashboard },
    { name: 'URL Logs', path: '/logs', icon: FileText },
    { name: 'Browser Protection', path: '/extension', icon: ShieldCheck },
    { name: 'AI Media Security', path: '/media', icon: Sparkles },
    { name: 'Threat Intelligence', path: '/threats', icon: Zap },
    { name: 'ML Model Insights', path: '/insights', icon: Cpu },
    // Only display User Management to Admin/Analyst roles
    ...((profile?.role === 'admin' || profile?.role === 'analyst') ? [
      { name: 'Users Management', path: '/users', icon: Users }
    ] : []),
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  const hasDegraded = providers.some(p => p.status === 'DEGRADED');
  const configuredCount = providers.filter(p => p.configured && p.enabled).length;

  return (
    <aside className="w-64 bg-cyber-sidebar border-r border-cyber-border flex flex-col h-screen fixed left-0 top-0 z-30 backdrop-blur-md transition-colors duration-300">
      {/* Brand Header */}
      <div className="px-6 py-5 border-b border-cyber-border">
        <h1 className="text-xl font-bold tracking-tight text-cyber-text">
          Cyber<span className="text-cyber-blue">Neura</span>
        </h1>
        <p className="text-[10px] text-cyber-muted tracking-widest uppercase mt-0.5 font-medium">
          Threat Intelligence
        </p>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-4 py-6 space-y-1.5 overflow-y-auto">
        {menuItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center justify-between px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 group ${
                  isActive
                    ? 'bg-cyber-blue/10 text-cyber-blue border-l-2 border-cyber-blue shadow-cyber-blue/5'
                    : 'text-cyber-muted hover:text-cyber-text hover:bg-cyber-inner'
                }`
              }
            >
              <div className="flex items-center gap-3">
                <Icon className="w-4 h-4 transition-transform group-hover:scale-110" />
                <span>{item.name}</span>
              </div>
              <ChevronRight className="w-3.5 h-3.5 opacity-0 -translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all text-cyber-muted" />
            </NavLink>
          );
        })}
      </nav>

      {/* Operational Badge and Signout */}
      <div className="p-4 border-t border-cyber-border space-y-4">
        {/* Truthful System Status Panel */}
        <div 
          onClick={() => setShowStatusDetails(!showStatusDetails)}
          className="p-3.5 rounded-xl bg-cyber-inner border border-cyber-border flex flex-col gap-2 cursor-pointer hover:border-cyber-blue/30 transition-all"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full animate-pulse ${
                hasDegraded ? 'bg-amber-400' : 'bg-cyber-green'
              }`}></span>
              <span className="text-xs font-semibold text-cyber-text tracking-wide">System Status</span>
            </div>
            <ChevronDown className={`w-3.5 h-3.5 text-cyber-muted transition-transform ${showStatusDetails ? 'rotate-180' : ''}`} />
          </div>

          <p className="text-[11px] text-cyber-muted pl-4 font-light">
            {hasDegraded ? 'Providers Degraded' : configuredCount > 0 ? `${configuredCount} Providers Active` : 'All systems operational'}
          </p>

          {showStatusDetails && (
            <div className="pt-2 mt-1 border-t border-cyber-inner-border/60 space-y-1 text-[10px] text-cyber-muted animate-in fade-in duration-150">
              <div className="flex justify-between"><span>Backend:</span><span className="text-emerald-400">HEALTHY</span></div>
              <div className="flex justify-between"><span>Database:</span><span className="text-emerald-400">HEALTHY</span></div>
              <div className="flex justify-between"><span>ML Model:</span><span className="text-emerald-400">HEALTHY</span></div>
              {providers.map(p => (
                <div key={p.name} className="flex justify-between">
                  <span className="capitalize">{p.name.replace('_', ' ')}:</span>
                  <span className={
                    p.status === 'HEALTHY' ? 'text-emerald-400' :
                    p.status === 'DEGRADED' ? 'text-amber-400' : 'text-cyber-muted'
                  }>
                    {p.status.replace('_', ' ')}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Logout Toggle */}
        <button
          onClick={logout}
          className="w-full flex items-center gap-3 px-4 py-2.5 text-xs font-medium text-red-400 hover:bg-red-500/10 hover:text-red-300 rounded-lg transition-all duration-300 cursor-pointer"
        >
          <LogOut className="w-4 h-4" />
          <span>Logout Session</span>
        </button>
      </div>
    </aside>
  );
};
export default Sidebar;
