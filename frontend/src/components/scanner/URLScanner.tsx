import React, { useState } from 'react';
import { Search } from 'lucide-react';
import { CyberInput } from '../ui/CyberInput';
import { CyberButton } from '../ui/CyberButton';
import { GlassCard } from '../ui/GlassCard';

interface URLScannerProps {
  onScan: (url: string) => Promise<void>;
  loading: boolean;
}

export const URLScanner: React.FC<URLScannerProps> = ({ onScan, loading }) => {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (!url) {
      setError('Please provide a URL to scan.');
      return;
    }
    
    // Quick regex validation for basic URL shape
    const urlPattern = /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*\/?$/i;
    if (!urlPattern.test(url) && !url.includes('.')) {
      setError('Please provide a valid website domain or URL.');
      return;
    }

    try {
      await onScan(url);
    } catch (err: any) {
      setError(err.message || 'Scan process encountered an error.');
    }
  };

  return (
    <GlassCard className="w-full relative overflow-hidden" hoverEffect={false}>
      {/* Background neon effect */}
      <div className="absolute top-0 right-0 w-24 h-24 bg-cyber-blue/10 rounded-full blur-2xl pointer-events-none"></div>
      
      <div className="space-y-4">
        <h3 className="text-md font-semibold text-cyber-text font-cyber tracking-wide">
          URL Security Scanner
        </h3>
        
        <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1">
            <CyberInput
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              icon={Search}
              placeholder="Paste suspicious URL here..."
              disabled={loading}
              error={error}
              className="py-3.5 rounded-xl border-cyber-inner-border focus:border-cyber-blue/40"
            />
          </div>
          
          <CyberButton
            type="submit"
            loading={loading}
            className="sm:w-36 h-12 py-0 text-sm font-semibold cursor-pointer shadow-glow whitespace-nowrap"
          >
            {loading ? 'Scanning...' : 'Scan Now'}
          </CyberButton>
        </form>
      </div>
    </GlassCard>
  );
};
export default URLScanner;
