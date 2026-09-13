import React, { useState } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import { Shield, Mail, Lock, Eye, EyeOff } from 'lucide-react';
import { CyberInput } from '../../components/ui/CyberInput';
import { CyberButton } from '../../components/ui/CyberButton';

export const LoginPage: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  
  const [email, setEmail] = useState('admin@cyberneura.ai');
  const [password, setPassword] = useState('password');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(email, password);
      navigate('/');
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-cyber-bg flex flex-col items-center justify-between py-12 px-4 relative overflow-hidden transition-colors duration-300">
      {/* Cyber Grid Background Overlays */}
      <div className="absolute inset-0 cyber-grid opacity-35 pointer-events-none"></div>
      
      {/* Dynamic Glowing Accents */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-cyber-blue/5 rounded-full blur-[180px] pointer-events-none"></div>
      
      {/* Spacing Offset */}
      <div></div>
 
      {/* Main Login Card */}
      <div className="w-full max-w-[440px] bg-cyber-card backdrop-blur-xl border border-cyber-border rounded-2xl p-8 relative z-10 shadow-2xl transition-all duration-300 text-cyber-text">
        <div className="flex flex-col items-center text-center mb-8">
          <div className="relative mb-4">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyber-blue to-cyber-purple flex items-center justify-center border border-cyber-border shadow-glow">
              <Shield className="w-9 h-9 text-cyber-text animate-pulse" />
            </div>
            <div className="absolute -inset-1 bg-gradient-to-tr from-cyber-blue to-cyber-purple rounded-2xl blur opacity-30"></div>
          </div>
          
          <h2 className="text-2xl font-bold tracking-tight text-cyber-text font-cyber">
            Cyber<span className="text-cyber-blue">Neura</span>
          </h2>
          <p className="text-xs text-cyber-muted font-light mt-1">AI-Powered Security Platform</p>
        </div>

        {error && (
          <div className="mb-5 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-xs text-red-400 text-center font-medium">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-cyber-muted">Email Address</label>
            <CyberInput
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              icon={Mail}
              placeholder="admin@cyberneura.ai"
              required
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-cyber-muted">Password</label>
            <div className="relative">
              <CyberInput
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                icon={Lock}
                placeholder="••••••••"
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-cyber-muted hover:text-cyber-text cursor-pointer"
              >
                {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between text-xs pt-1">
            <label className="flex items-center gap-2 text-cyber-muted cursor-pointer">
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="rounded border-cyber-inner-border bg-cyber-input text-cyber-blue focus:ring-0 w-4 h-4 cursor-pointer"
              />
              <span>Remember me</span>
            </label>
            <a href="#" className="text-cyber-blue hover:underline">Forgot password?</a>
          </div>

          <CyberButton
            type="submit"
            loading={loading}
            className="w-full py-3 mt-4 text-sm font-semibold shadow-glow cursor-pointer"
          >
            {loading ? 'Authenticating...' : 'Sign In'}
          </CyberButton>
        </form>

        <div className="mt-6 p-3.5 rounded-xl bg-cyber-inner border border-cyber-border text-center">
          <p className="text-[11px] text-cyber-muted font-light">
            Demo: Use any email and password to login
          </p>
        </div>

        <div className="mt-8 text-center">
          <p className="text-[10px] text-cyber-muted uppercase tracking-widest font-semibold">
            Protected by <span className="text-cyber-blue font-bold">CyberNeura AI</span>
          </p>
        </div>
      </div>

      {/* Footer Stats Bar */}
      <div className="w-full max-w-[800px] grid grid-cols-3 gap-6 relative z-10 border-t border-cyber-border pt-8 mt-12">
        <div className="text-center space-y-1">
          <h4 className="text-xl font-bold font-cyber text-cyber-blue tracking-tight">99.8%</h4>
          <p className="text-[10px] text-cyber-muted uppercase tracking-wider font-medium">Detection Rate</p>
        </div>
        <div className="text-center space-y-1 border-x border-cyber-border">
          <h4 className="text-xl font-bold font-cyber text-cyber-text tracking-tight">24/7</h4>
          <p className="text-[10px] text-cyber-muted uppercase tracking-wider font-medium">Protection</p>
        </div>
        <div className="text-center space-y-1">
          <h4 className="text-xl font-bold font-cyber text-cyber-purple tracking-tight">1M+</h4>
          <p className="text-[10px] text-cyber-muted uppercase tracking-wider font-medium">Threats Blocked</p>
        </div>
      </div>
    </div>
  );
};
export default LoginPage;
