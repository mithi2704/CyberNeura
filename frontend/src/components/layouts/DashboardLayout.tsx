import React from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';

export const DashboardLayout: React.FC = () => {
  return (
    <div className="min-h-screen bg-cyber-bg text-cyber-text relative flex transition-colors duration-300">
      {/* Cyber Grid Background Overlays */}
      <div className="absolute inset-0 cyber-grid pointer-events-none opacity-45"></div>
      
      {/* Dynamic Glowing Accents */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-cyber-blue/10 rounded-full blur-[150px] pointer-events-none"></div>
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-cyber-purple/10 rounded-full blur-[150px] pointer-events-none"></div>

      {/* Sidebar Frame */}
      <Sidebar />

      {/* Main Layout Area */}
      <div className="flex-1 pl-64 flex flex-col min-h-screen relative z-10">
        <Header />
        
        {/* Content Area */}
        <main className="flex-1 p-8 overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
export default DashboardLayout;
