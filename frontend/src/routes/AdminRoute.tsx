import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export const AdminRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { profile, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-cyber-bg flex items-center justify-center">
        <div className="relative w-16 h-16">
          <div className="absolute inset-0 rounded-full border-t-2 border-r-2 border-cyber-blue animate-spin shadow-glow"></div>
        </div>
      </div>
    );
  }

  const isAdminOrAnalyst = profile?.role === 'admin' || profile?.role === 'analyst';

  if (!isAdminOrAnalyst) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
};
