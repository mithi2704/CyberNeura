import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { fetchNotifications, markNotificationAsRead, markAllNotificationsAsRead } from '../../services/notificationService';
import type { Notification } from '../../types';
import { Bell, User, Check, ShieldAlert, Sun, Moon } from 'lucide-react';
import { useLocation } from 'react-router-dom';
import { realtimeService } from '../../services/realtimeService';
import type { ConnectionStatus } from '../../realtime/eventTypes';
import { useSettings } from '../../contexts/ThemeContext';

export const Header: React.FC = () => {
  const { profile, user } = useAuth();
  const { theme, toggleTheme } = useSettings();
  const location = useLocation();
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [showDropdown, setShowDropdown] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('CONNECTING');

  // Derive header title from active pathname
  const getHeaderTitle = () => {
    switch (location.pathname) {
      case '/':
        return 'Dashboard Overview';
      case '/logs':
        return 'URL Logs';
      case '/threats':
        return 'Threat Intelligence';
      case '/insights':
        return 'ML Model Insights';
      case '/users':
        return 'Users Management';
      case '/settings':
        return 'Settings';
      default:
        return 'CyberNeura Secure Core';
    }
  };

  const loadNotifications = async () => {
    const list = await fetchNotifications();
    setNotifications(list);
  };

  useEffect(() => {
    loadNotifications();

    // Initialize realtime service with authenticated user
    realtimeService.initialize(user?.uid);

    // Track connection state
    const unsubStatus = realtimeService.onConnectionStatusChange((status) => {
      setConnectionStatus(status);
    });

    // Subscribe to live notification & alert events
    const unsubNotifs = realtimeService.subscribeToNotifications((alert) => {
      const notifType = alert.severity === 'CRITICAL'
        ? 'critical_alert'
        : alert.severity === 'HIGH'
        ? 'threat_alert'
        : 'system_update';
      const newNotif: Notification = {
        id: `notif-${Date.now()}`,
        userId: user?.uid || 'user',
        title: alert.title,
        body: alert.message,
        type: notifType,
        isRead: false,
        createdAt: new Date().toISOString(),
      };
      setNotifications((prev) => [newNotif, ...prev]);
    });

    return () => {
      unsubStatus();
      unsubNotifs();
    };
  }, [user]);

  const unreadCount = notifications.filter(n => !n.isRead).length;

  const handleMarkAsRead = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    await markNotificationAsRead(id);
    await loadNotifications();
  };

  const handleMarkAllRead = async () => {
    await markAllNotificationsAsRead();
    await loadNotifications();
  };

  const renderConnectionBadge = () => {
    switch (connectionStatus) {
      case 'CONNECTED':
        return (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="font-mono text-[11px] font-medium tracking-wide">Live</span>
          </div>
        );
      case 'RECONNECTING':
        return (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs">
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span>
            <span className="font-mono text-[11px] font-medium tracking-wide">Reconnecting...</span>
          </div>
        );
      case 'CONNECTING':
        return (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            <span className="font-mono text-[11px] font-medium tracking-wide">Connecting</span>
          </div>
        );
      case 'DEGRADED':
        return (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs" title="Using 30s polling fallback">
            <span className="w-2 h-2 rounded-full bg-blue-400"></span>
            <span className="font-mono text-[11px] font-medium tracking-wide">Polling (30s)</span>
          </div>
        );
      case 'DISCONNECTED':
      default:
        return (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-gray-500/10 border border-gray-500/20 text-gray-400 text-xs">
            <span className="w-2 h-2 rounded-full bg-gray-400"></span>
            <span className="font-mono text-[11px] font-medium tracking-wide">Offline</span>
          </div>
        );
    }
  };

  return (
    <header className="h-20 bg-cyber-bg/40 border-b border-cyber-border flex items-center justify-between px-8 backdrop-blur-md sticky top-0 z-20 transition-colors duration-300">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-cyber-text font-cyber">{getHeaderTitle()}</h2>
        <p className="text-xs text-cyber-muted font-light mt-0.5">Real-time threat monitoring and analysis</p>
      </div>

      <div className="flex items-center gap-4">
        {/* Real-time Connection Status Indicator */}
        {renderConnectionBadge()}

        {/* Theme Toggler */}
        <button
          onClick={toggleTheme}
          className="w-10 h-10 rounded-xl bg-cyber-inner border border-cyber-border flex items-center justify-center text-cyber-muted hover:text-cyber-blue hover:border-cyber-blue/30 transition-all duration-300 cursor-pointer"
          title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
        >
          {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
        </button>

        {/* Notification Bell Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowDropdown(!showDropdown)}
            className="w-10 h-10 rounded-xl bg-cyber-inner border border-cyber-border flex items-center justify-center text-cyber-muted hover:text-cyber-blue hover:border-cyber-blue/30 transition-all duration-300 relative cursor-pointer"
          >
            <Bell className="w-5 h-5" />
            {unreadCount > 0 && (
              <span className="absolute top-2 right-2.5 w-2 h-2 bg-cyber-pink rounded-full shadow-glow-pink animate-pulse"></span>
            )}
          </button>

          {showDropdown && (
            <>
              <div className="fixed inset-0 z-30" onClick={() => setShowDropdown(false)}></div>
              <div className="absolute right-0 mt-3 w-80 glass-panel rounded-xl border border-cyber-inner-border shadow-2xl p-4 z-40 animate-in fade-in slide-in-from-top-3 duration-200">
                <div className="flex items-center justify-between border-b border-cyber-inner-border pb-2 mb-2">
                  <span className="text-xs font-semibold text-cyber-text">Notifications ({unreadCount} new)</span>
                  {unreadCount > 0 && (
                    <button
                      onClick={handleMarkAllRead}
                      className="text-[10px] text-cyber-blue hover:underline flex items-center gap-1 cursor-pointer"
                    >
                      <Check className="w-3 h-3" /> Mark all read
                    </button>
                  )}
                </div>

                <div className="space-y-2 max-h-60 overflow-y-auto custom-scrollbar pr-1">
                  {notifications.length === 0 ? (
                    <p className="text-xs text-cyber-muted text-center py-4">No recent notifications</p>
                  ) : (
                    notifications.map((notif) => (
                      <div
                        key={notif.id}
                        onClick={(e) => handleMarkAsRead(notif.id, e)}
                        className={`p-2.5 rounded-lg border transition-all duration-200 cursor-pointer ${
                          notif.isRead 
                            ? 'bg-cyber-inner border-cyber-inner-border opacity-60' 
                            : 'bg-cyber-inner border-cyber-inner-border hover:border-cyber-blue/30'
                        }`}
                      >
                        <div className="flex gap-2">
                          <ShieldAlert className={`w-4 h-4 mt-0.5 shrink-0 ${notif.type === 'critical_alert' ? 'text-cyber-pink' : 'text-cyber-blue'}`} />
                          <div className="flex-1">
                            <h4 className="text-xs font-medium text-cyber-text">{notif.title}</h4>
                            <p className="text-[10px] text-cyber-muted mt-0.5 leading-relaxed">{notif.body}</p>
                            <span className="text-[9px] text-cyber-muted mt-1 block">
                              {new Date(notif.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                            </span>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </>
          )}
        </div>

        {/* User Account Details */}
        <div className="flex items-center gap-3 pl-4 border-l border-cyber-border">
          <div className="text-right hidden sm:block">
            <h4 className="text-xs font-medium text-cyber-text">{profile?.displayName || 'Analyst'}</h4>
            <span className="text-[9px] uppercase tracking-wider text-cyber-blue font-bold px-1.5 py-0.5 bg-cyber-blue/10 rounded border border-cyber-blue/20 mt-1 inline-block">
              {profile?.role || 'user'}
            </span>
          </div>

          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyber-blue/25 to-cyber-purple/25 border border-cyber-border flex items-center justify-center shadow-inner relative group">
            {profile?.avatarUrl ? (
              <img src={profile.avatarUrl} alt="Avatar" className="w-full h-full rounded-xl object-cover" />
            ) : (
              <User className="w-5 h-5 text-cyber-text" />
            )}
            <span className="absolute bottom-0 right-0 w-2.5 h-2.5 bg-cyber-green rounded-full border border-cyber-bg"></span>
          </div>
        </div>
      </div>
    </header>
  );
};
