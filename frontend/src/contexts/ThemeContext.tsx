import React, { createContext, useContext, useEffect, useState } from 'react';
import { useAuth } from './AuthContext';
import { aiClient } from '../lib/api/aiService';
import type { SystemSettings } from '../types';

interface SettingsContextType {
  settings: SystemSettings | null;
  updateSettings: (newSettings: Partial<SystemSettings>) => Promise<void>;
  resetSettings: () => Promise<void>;
  loading: boolean;
  theme: 'light' | 'dark';
  toggleTheme: () => void;
}

const SettingsContext = createContext<SettingsContextType | undefined>(undefined);

const defaultSettings = (userId: string = 'demo-user'): SystemSettings => ({
  id: 'default-settings-id',
  userId,
  realTimeProtection: true,
  autoBlock: true,
  emailScanning: false,
  browserProtection: true,
  apiAccess: false,
  notificationPreferences: {
    criticalAlerts: true,
    dailyReports: true,
    weeklyAnalytics: true,
    systemUpdates: false,
    newFeatures: false,
  },
  licenseKey: 'CNEU-2024-XXXX-XXXX',
  licenseValidUntil: '2026-12-31',
  apiUsageLimit: 50000,
  apiUsageCount: 10000,
  updatedAt: new Date().toISOString(),
});

export const SettingsProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user } = useAuth();
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const saved = localStorage.getItem('cyberneura_theme');
    if (saved === 'light' || saved === 'dark') return saved;
    return 'dark';
  });

  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    localStorage.setItem('cyberneura_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));
  };

  // Sync settings via backend API
  useEffect(() => {
    if (!user) {
      setSettings(null);
      setLoading(false);
      return;
    }

    const loadSettings = async () => {
      try {
        const res = await aiClient.get('/settings');
        if (res.data) {
          setSettings(res.data as SystemSettings);
        } else {
          setSettings(defaultSettings(user.uid));
        }
      } catch (err) {
        console.warn('Could not sync system settings from backend, loading fallback settings:', err);
        // Offline fallback
        const cached = localStorage.getItem(`cyberneura_settings_${user.uid}`);
        if (cached) {
          setSettings(JSON.parse(cached));
        } else {
          setSettings(defaultSettings(user.uid));
        }
      } finally {
        setLoading(false);
      }
    };

    loadSettings();
  }, [user]);

  const updateSettings = async (newSettings: Partial<SystemSettings>) => {
    if (!settings || !user) return;

    const updated = {
      ...settings,
      ...newSettings,
      updatedAt: new Date().toISOString(),
    };

    setSettings(updated);
    localStorage.setItem(`cyberneura_settings_${user.uid}`, JSON.stringify(updated));

    try {
      await aiClient.put('/settings', newSettings);
    } catch (err) {
      console.warn('Failed to persist settings changes to backend:', err);
    }
  };

  const resetSettings = async () => {
    if (!user) return;
    const initial = defaultSettings(user.uid);
    setSettings(initial);
    localStorage.setItem(`cyberneura_settings_${user.uid}`, JSON.stringify(initial));

    try {
      await aiClient.post('/settings/reset');
    } catch (err) {
      console.warn('Failed to reset settings in backend:', err);
    }
  };

  return (
    <SettingsContext.Provider value={{ settings, updateSettings, resetSettings, loading, theme, toggleTheme }}>
      {children}
    </SettingsContext.Provider>
  );
};

export const useSettings = () => {
  const context = useContext(SettingsContext);
  if (context === undefined) {
    throw new Error('useSettings must be used within a SettingsProvider');
  }
  return context;
};
