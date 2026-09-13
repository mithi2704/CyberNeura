import React from 'react';
import { useSettings } from '../../contexts/ThemeContext';
import { aiClient } from '../../lib/api/aiService';
import { GlassCard } from '../../components/ui/GlassCard';
import { Toggle } from '../../components/ui/Toggle';
import { CyberButton } from '../../components/ui/CyberButton';
import { Shield, Bell, Key, AlertTriangle } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';

export const SettingsPage: React.FC = () => {
  const { settings, updateSettings, resetSettings } = useSettings();
  const { logout } = useAuth();

  const handleSecurityToggle = (key: 'realTimeProtection' | 'autoBlock' | 'emailScanning' | 'browserProtection' | 'apiAccess', checked: boolean) => {
    updateSettings({ [key]: checked });
  };

  const handleNotificationCheckbox = (key: 'criticalAlerts' | 'dailyReports' | 'weeklyAnalytics' | 'systemUpdates' | 'newFeatures', checked: boolean) => {
    if (!settings) return;
    updateSettings({
      notificationPreferences: {
        ...settings.notificationPreferences,
        [key]: checked,
      },
    });
  };

  const handleClearLogs = async () => {
    if (window.confirm('Are you absolutely sure you want to permanently clear all URL scan history? This action is irreversible.')) {
      try {
        await aiClient.post('/settings/clear-logs');
        alert('All URL logs have been purged successfully.');
      } catch (err) {
        alert('Failed to purge URL logs.');
      }
    }
  };

  const handleDeactivate = async () => {
    if (window.confirm('Are you sure you want to deactivate your operator session?')) {
      await logout();
    }
  };

  const apiQuotaPercentage = settings ? (settings.apiUsageCount / settings.apiUsageLimit) * 100 : 20;

  return (
    <div className="space-y-8 max-w-4xl">
      {/* 1. Security Settings */}
      <GlassCard hoverEffect={false}>
        <div className="flex items-center gap-2.5 border-b border-cyber-inner-border pb-4 mb-6">
          <Shield className="w-5 h-5 text-cyber-blue" />
          <h3 className="text-sm font-semibold text-cyber-text font-cyber tracking-wide">
            Security Settings
          </h3>
        </div>

        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h4 className="text-xs font-semibold text-cyber-text">Real-time Protection</h4>
              <p className="text-[10px] text-cyber-muted mt-0.5">Monitor URLs in real-time</p>
            </div>
            <Toggle
              checked={settings?.realTimeProtection ?? true}
              onChange={(checked) => handleSecurityToggle('realTimeProtection', checked)}
            />
          </div>

          <div className="flex items-center justify-between border-t border-cyber-inner-border pt-4">
            <div>
              <h4 className="text-xs font-semibold text-cyber-text">Auto-block Malicious Links</h4>
              <p className="text-[10px] text-cyber-muted mt-0.5">Automatically block detected threats</p>
            </div>
            <Toggle
              checked={settings?.autoBlock ?? true}
              onChange={(checked) => handleSecurityToggle('autoBlock', checked)}
            />
          </div>

          <div className="flex items-center justify-between border-t border-cyber-inner-border pt-4">
            <div>
              <h4 className="text-xs font-semibold text-cyber-text">Email Scanning</h4>
              <p className="text-[10px] text-cyber-muted mt-0.5">Scan email attachments and links</p>
            </div>
            <Toggle
              checked={settings?.emailScanning ?? false}
              onChange={(checked) => handleSecurityToggle('emailScanning', checked)}
            />
          </div>

          <div className="flex items-center justify-between border-t border-cyber-inner-border pt-4">
            <div>
              <h4 className="text-xs font-semibold text-cyber-text">Browser Extension</h4>
              <p className="text-[10px] text-cyber-muted mt-0.5">Enable browser protection</p>
            </div>
            <Toggle
              checked={settings?.browserProtection ?? true}
              onChange={(checked) => handleSecurityToggle('browserProtection', checked)}
            />
          </div>

          <div className="flex items-center justify-between border-t border-cyber-inner-border pt-4">
            <div>
              <h4 className="text-xs font-semibold text-cyber-text">API Access</h4>
              <p className="text-[10px] text-cyber-muted mt-0.5">Allow third-party integrations</p>
            </div>
            <Toggle
              checked={settings?.apiAccess ?? false}
              onChange={(checked) => handleSecurityToggle('apiAccess', checked)}
            />
          </div>
        </div>
      </GlassCard>

      {/* 2. Notification Preferences & Account Info Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* Notification Preferences */}
        <GlassCard hoverEffect={false}>
          <div className="flex items-center gap-2.5 border-b border-cyber-inner-border pb-4 mb-6">
            <Bell className="w-5 h-5 text-cyber-blue" />
            <h3 className="text-sm font-semibold text-cyber-text font-cyber tracking-wide">
              Notification Preferences
            </h3>
          </div>

          <div className="space-y-4 text-xs font-light text-cyber-text">
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={settings?.notificationPreferences.criticalAlerts ?? true}
                onChange={(e) => handleNotificationCheckbox('criticalAlerts', e.target.checked)}
                className="rounded border-cyber-inner-border bg-cyber-input text-cyber-blue focus:ring-0 w-4 h-4 cursor-pointer"
              />
              <span>Critical Threat Alerts</span>
            </label>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={settings?.notificationPreferences.dailyReports ?? true}
                onChange={(e) => handleNotificationCheckbox('dailyReports', e.target.checked)}
                className="rounded border-cyber-inner-border bg-cyber-input text-cyber-blue focus:ring-0 w-4 h-4 cursor-pointer"
              />
              <span>Daily Security Reports</span>
            </label>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={settings?.notificationPreferences.weeklyAnalytics ?? true}
                onChange={(e) => handleNotificationCheckbox('weeklyAnalytics', e.target.checked)}
                className="rounded border-cyber-inner-border bg-cyber-input text-cyber-blue focus:ring-0 w-4 h-4 cursor-pointer"
              />
              <span>Weekly Analytics Summary</span>
            </label>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={settings?.notificationPreferences.systemUpdates ?? false}
                onChange={(e) => handleNotificationCheckbox('systemUpdates', e.target.checked)}
                className="rounded border-cyber-inner-border bg-cyber-input text-cyber-blue focus:ring-0 w-4 h-4 cursor-pointer"
              />
              <span>System Updates</span>
            </label>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={settings?.notificationPreferences.newFeatures ?? false}
                onChange={(e) => handleNotificationCheckbox('newFeatures', e.target.checked)}
                className="rounded border-cyber-inner-border bg-cyber-input text-cyber-blue focus:ring-0 w-4 h-4 cursor-pointer"
              />
              <span>New Feature Announcements</span>
            </label>
          </div>
        </GlassCard>

        {/* Account Info & License */}
        <GlassCard hoverEffect={false}>
          <div className="flex items-center gap-2.5 border-b border-cyber-inner-border pb-4 mb-6">
            <Key className="w-5 h-5 text-cyber-blue" />
            <h3 className="text-sm font-semibold text-cyber-text font-cyber tracking-wide">
              Account Information
            </h3>
          </div>

          <div className="space-y-4 text-xs">
            <div className="flex justify-between items-center">
              <span className="text-cyber-muted">Account Type</span>
              <span className="text-cyber-blue font-bold font-cyber">Enterprise Premium</span>
            </div>

            <div className="flex justify-between items-center border-t border-cyber-inner-border pt-3">
              <span className="text-cyber-muted">License Key</span>
              <span className="text-cyber-text font-mono">{settings?.licenseKey || 'CNEU-2024-XXXX-XXXX'}</span>
            </div>

            <div className="flex justify-between items-center border-t border-cyber-inner-border pt-3">
              <span className="text-cyber-muted">Subscription Valid Until</span>
              <span className="text-cyber-text font-medium">December 31, 2026</span>
            </div>

            <div className="border-t border-cyber-inner-border pt-3 space-y-2">
              <div className="flex justify-between text-cyber-muted">
                <span>API Quota</span>
                <span className="text-cyber-text font-semibold">
                  {settings?.apiUsageCount.toLocaleString()} / {settings?.apiUsageLimit.toLocaleString()} requests
                </span>
              </div>
              <div className="w-full h-2 bg-cyber-inner border border-cyber-inner-border rounded-full overflow-hidden">
                <div 
                  className="h-full bg-gradient-to-r from-cyber-blue to-cyber-purple rounded-full shadow-glow"
                  style={{ width: `${apiQuotaPercentage}%` }}
                ></div>
              </div>
            </div>
          </div>
        </GlassCard>
      </div>

      {/* 3. Danger Zone */}
      <GlassCard className="border border-red-500/20" hoverEffect={false}>
        <div className="flex items-center gap-2.5 border-b border-red-500/10 pb-4 mb-6">
          <AlertTriangle className="w-5 h-5 text-red-400" />
          <h3 className="text-sm font-semibold text-red-400 font-cyber tracking-wide">
            Danger Zone
          </h3>
        </div>

        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
            <div>
              <h4 className="text-xs font-semibold text-cyber-text">Reset All Settings</h4>
              <p className="text-[10px] text-cyber-muted mt-0.5">Restore default platform security configuration</p>
            </div>
            <CyberButton
              variant="danger"
              size="sm"
              onClick={resetSettings}
              className="w-full sm:w-auto"
            >
              Reset Settings
            </CyberButton>
          </div>

          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-t border-cyber-inner-border pt-4">
            <div>
              <h4 className="text-xs font-semibold text-cyber-text">Clear All Logs</h4>
              <p className="text-[10px] text-cyber-muted mt-0.5">Permanently delete all URL scan audit history</p>
            </div>
            <CyberButton
              variant="danger"
              size="sm"
              onClick={handleClearLogs}
              className="w-full sm:w-auto"
            >
              Clear All Logs
            </CyberButton>
          </div>

          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-t border-cyber-inner-border pt-4">
            <div>
              <h4 className="text-xs font-semibold text-cyber-text">Deactivate Account</h4>
              <p className="text-[10px] text-cyber-muted mt-0.5">Temporarily disable your operator account session</p>
            </div>
            <CyberButton
              variant="danger"
              size="sm"
              onClick={handleDeactivate}
              className="w-full sm:w-auto"
            >
              Deactivate Account
            </CyberButton>
          </div>
        </div>
      </GlassCard>
    </div>
  );
};
export default SettingsPage;
