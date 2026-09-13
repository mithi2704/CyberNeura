import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from './contexts/AuthContext';
import { SettingsProvider } from './contexts/ThemeContext';
import { ProtectedRoute } from './routes/ProtectedRoute';
import { AdminRoute } from './routes/AdminRoute';
import { DashboardLayout } from './components/layouts/DashboardLayout';

// Import Pages
import LoginPage from './pages/Login/LoginPage';
import DashboardPage from './pages/Dashboard/DashboardPage';
import URLLogsPage from './pages/URLLogs/URLLogsPage';
import ThreatIntelPage from './pages/ThreatIntel/ThreatIntelPage';
import MLInsightsPage from './pages/MLInsights/MLInsightsPage';
import UsersPage from './pages/Users/UsersPage';
import SettingsPage from './pages/Settings/SettingsPage';
import { BrowserProtectionPage } from './pages/BrowserProtection/BrowserProtectionPage';
import { MediaSecurityPage } from './pages/MediaSecurity/MediaSecurityPage';

// Initialize React Query Client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <SettingsProvider>
          <BrowserRouter>
            <Routes>
              {/* Authenticated dashboard layouts */}
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <DashboardLayout />
                  </ProtectedRoute>
                }
              >
                <Route index element={<DashboardPage />} />
                <Route path="logs" element={<URLLogsPage />} />
                <Route path="extension" element={<BrowserProtectionPage />} />
                <Route path="media" element={<MediaSecurityPage />} />
                <Route path="threats" element={<ThreatIntelPage />} />
                <Route path="insights" element={<MLInsightsPage />} />
                
                {/* Admin/Analyst Restricted Route */}
                <Route
                  path="users"
                  element={
                    <AdminRoute>
                      <UsersPage />
                    </AdminRoute>
                  }
                />
                
                <Route path="settings" element={<SettingsPage />} />
              </Route>

              {/* Public/Authentication Routes */}
              <Route path="/login" element={<LoginPage />} />
              
              {/* Catch-all fallback */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </BrowserRouter>
        </SettingsProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
};
export default App;
