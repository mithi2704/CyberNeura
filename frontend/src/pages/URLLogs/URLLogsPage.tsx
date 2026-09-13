import React, { useState, useEffect } from 'react';
import { fetchURLScans, deleteURLScan } from '../../services/urlScanService';
import { exportScansToCSV } from '../../services/reportService';
import type { URLScan } from '../../types';
import { GlassCard } from '../../components/ui/GlassCard';
import { RiskBar } from '../../components/ui/RiskBar';
import { StatusBadge } from '../../components/ui/StatusBadge';
import { CyberButton } from '../../components/ui/CyberButton';
import { CyberInput } from '../../components/ui/CyberInput';
import { Search, Download, Trash2, ShieldAlert, ArrowUpDown, ChevronLeft, ChevronRight, Check } from 'lucide-react';
import { aiClient } from '../../lib/api/aiService';
import { realtimeService } from '../../services/realtimeService';

export const URLLogsPage: React.FC = () => {
  const [scans, setScans] = useState<URLScan[]>([]);
  const [search, setSearch] = useState('');
  const [sortField, setSortField] = useState<keyof URLScan>('scannedAt');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 8;

  const loadLogs = async () => {
    const list = await fetchURLScans();
    setScans(list);
  };

  useEffect(() => {
    loadLogs();

    const unsubScans = realtimeService.subscribeToScans((scanPayload) => {
      const newScan: URLScan = {
        id: scanPayload.id,
        url: scanPayload.url,
        riskScore: scanPayload.riskScore,
        prediction: scanPayload.prediction,
        confidence: scanPayload.confidence,
        threatCategory: scanPayload.threatCategory || (scanPayload.prediction === 'safe' ? 'Safe' : 'Phishing'),
        ipAddress: scanPayload.ipAddress,
        sslStatus: scanPayload.sslStatus,
        scannedAt: scanPayload.scannedAt,
        severity: scanPayload.severity,
        summary: scanPayload.summary,
      };
      setScans((prev) => [newScan, ...prev.filter((s) => s.id !== newScan.id)]);
    });

    const unsubResync = realtimeService.onResync(() => {
      loadLogs();
    });

    return () => {
      unsubScans();
      unsubResync();
    };
  }, []);

  // Sort and filter logic
  const handleSort = (field: keyof URLScan) => {
    const order = sortField === field && sortOrder === 'desc' ? 'asc' : 'desc';
    setSortField(field);
    setSortOrder(order);
  };

  const handleDelete = async (id: string) => {
    const success = await deleteURLScan(id);
    if (success) {
      loadLogs();
    }
  };

  const handleMarkSafe = async (scan: URLScan) => {
    // Optimistically update prediction to safe and riskScore to 5
    setScans(prev => 
      prev.map(item => 
        item.id === scan.id 
          ? { ...item, prediction: 'safe', riskScore: 5, threatCategory: 'Safe' } 
          : item
      )
    );

    try {
      await aiClient.patch(`/scans/${scan.id}`, {
        prediction: 'safe',
        riskScore: 5,
        threatCategory: 'Safe',
      });
    } catch (e) {
      console.warn('Could not update scan status via backend:', e);
    }
  };

  const filteredScans = scans.filter(s => 
    s.url.toLowerCase().includes(search.toLowerCase()) ||
    (s.ipAddress && s.ipAddress.includes(search)) ||
    s.prediction.toLowerCase().includes(search.toLowerCase())
  );

  const sortedScans = [...filteredScans].sort((a, b) => {
    let valA = a[sortField];
    let valB = b[sortField];
    
    if (typeof valA === 'string' && typeof valB === 'string') {
      return sortOrder === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
    }
    if (typeof valA === 'number' && typeof valB === 'number') {
      return sortOrder === 'asc' ? valA - valB : valB - valA;
    }
    return 0;
  });

  // Pagination
  const totalPages = Math.ceil(sortedScans.length / itemsPerPage);
  const paginatedScans = sortedScans.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  const formatTimestamp = (isoString: string) => {
    try {
      const date = new Date(isoString);
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    } catch (e) {
      return isoString;
    }
  };

  const renderMiniProviderBadge = (label: string, name: string, res?: any) => {
    if (!res || !res.available) {
      return (
        <span
          className="w-5 h-5 rounded flex items-center justify-center text-[9px] font-bold bg-gray-800/60 text-cyber-muted border border-gray-700/50"
          title={`${name}: Unconfigured or Unavailable`}
        >
          {label}
        </span>
      );
    }
    if (res.matched) {
      return (
        <span
          className="w-5 h-5 rounded flex items-center justify-center text-[9px] font-bold bg-cyber-pink/20 text-cyber-pink border border-cyber-pink/40 animate-pulse"
          title={`${name}: MATCH (${res.categories?.join(', ') || 'Threat detected'})`}
        >
          {label}
        </span>
      );
    }
    return (
      <span
        className="w-5 h-5 rounded flex items-center justify-center text-[9px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/25"
        title={`${name}: NO MATCH (Clean)`}
      >
        {label}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Top Filter and Actions panel */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-cyber-inner border border-cyber-inner-border p-4 rounded-xl">
        <div className="w-full md:w-80">
          <CyberInput
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setCurrentPage(1);
            }}
            icon={Search}
            placeholder="Search by URL, IP address or prediction..."
            className="py-2.5 text-xs rounded-xl"
          />
        </div>

        <CyberButton
          variant="outline"
          size="sm"
          onClick={() => exportScansToCSV(sortedScans)}
          className="flex items-center gap-2 cursor-pointer w-full md:w-auto"
        >
          <Download className="w-4 h-4" /> Export CSV
        </CyberButton>
      </div>

      {/* Main Table Card */}
      <GlassCard className="w-full overflow-hidden" hoverEffect={false}>
        <div className="flex items-center gap-2 mb-6">
          <ShieldAlert className="w-5 h-5 text-cyber-blue" />
          <h3 className="text-sm font-semibold text-cyber-text font-cyber tracking-wide">
            Complete URL Activity Log
          </h3>
        </div>

        {/* Responsive Table Scroll container */}
        <div className="overflow-x-auto w-full">
          <table className="w-full border-collapse text-left text-xs font-light">
            <thead>
              <tr className="border-b border-cyber-inner-border text-cyber-muted font-medium">
                <th className="pb-4 pr-4 pl-2 cursor-pointer select-none" onClick={() => handleSort('url')}>
                  <div className="flex items-center gap-1">
                    URL <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="pb-4 pr-4 cursor-pointer select-none w-32" onClick={() => handleSort('riskScore')}>
                  <div className="flex items-center gap-1">
                    Risk <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="pb-4 pr-4 cursor-pointer select-none w-24" onClick={() => handleSort('prediction')}>
                  <div className="flex items-center gap-1">
                    Status <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="pb-4 pr-4 select-none w-20">
                  Decision
                </th>
                <th className="pb-4 pr-4 select-none w-24">
                  Source
                </th>
                <th className="pb-4 pr-4 select-none w-16">
                  Override
                </th>
                <th className="pb-4 pr-4 select-none w-28">
                  Category
                </th>
                <th className="pb-4 pr-4 cursor-pointer select-none w-24" onClick={() => handleSort('confidence')}>
                  <div className="flex items-center gap-1">
                    Confidence <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="pb-4 pr-4 select-none w-36">
                  Intel & Evidence
                </th>
                <th className="pb-4 pr-4 cursor-pointer select-none w-36" onClick={() => handleSort('scannedAt')}>
                  <div className="flex items-center gap-1">
                    Timestamp <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="pb-4 pr-2 text-right w-20">Actions</th>
              </tr>
            </thead>
            
            <tbody className="divide-y divide-white/5 text-cyber-text font-light">
              {paginatedScans.map((scan) => (
                <tr key={scan.id} className="hover:bg-cyber-inner transition duration-200">
                  <td className="py-4 pr-4 pl-2 font-medium text-cyber-text max-w-xs truncate" title={scan.url}>
                    {scan.url}
                  </td>
                  <td className="py-4 pr-4">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold font-cyber text-[10px] w-5 shrink-0">{scan.riskScore}</span>
                      <RiskBar score={scan.riskScore} />
                    </div>
                  </td>
                  <td className="py-4 pr-4">
                    <StatusBadge type={scan.prediction === 'safe' ? 'allowed' : scan.prediction === 'suspicious' ? 'flagged' : 'blocked'} />
                  </td>
                  <td className="py-4 pr-4">
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase ${
                      (scan.decision === 'BLOCK' || scan.riskScore >= 70)
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : (scan.decision === 'WARN' || scan.riskScore >= 30)
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    }`}>
                      {scan.decision || (scan.riskScore >= 70 ? 'BLOCK' : scan.riskScore >= 30 ? 'WARN' : 'ALLOW')}
                    </span>
                  </td>
                  <td className="py-4 pr-4">
                    <span className="text-[10px] font-mono text-cyber-muted bg-cyber-input px-1.5 py-0.5 rounded border border-cyber-inner-border">
                      {scan.source || 'Dashboard'}
                    </span>
                  </td>
                  <td className="py-4 pr-4 font-mono text-[10px]">
                    {scan.userOverride ? (
                      <span className="text-amber-400 font-bold">YES</span>
                    ) : (
                      <span className="text-cyber-muted">NO</span>
                    )}
                  </td>
                  <td className="py-4 pr-4 font-mono text-[11px] text-cyber-text truncate max-w-[110px]">
                    {scan.threatCategory || (scan.prediction === 'safe' ? 'Safe' : 'Phishing')}
                  </td>
                  <td className="py-4 pr-4 font-mono text-cyber-text font-semibold text-[11px]">
                    {Math.round(scan.confidence)}%
                  </td>
                  <td className="py-4 pr-4">
                    <div className="flex items-center gap-1.5">
                      <div className="flex items-center gap-1">
                        {renderMiniProviderBadge('G', 'Google Web Risk', scan.threatIntelligence?.google_webrisk)}
                        {renderMiniProviderBadge('P', 'PhishTank', scan.threatIntelligence?.phishtank)}
                        {renderMiniProviderBadge('U', 'URLhaus', scan.threatIntelligence?.urlhaus)}
                      </div>
                      <span className="text-[10px] text-cyber-muted font-mono bg-cyber-input px-1.5 py-0.5 rounded border border-cyber-inner-border">
                        {scan.evidenceCount ?? scan.evidence?.length ?? 0} ev
                      </span>
                    </div>
                  </td>
                  <td className="py-4 pr-4 font-mono text-[11px] text-cyber-muted">
                    {formatTimestamp(scan.scannedAt)}
                  </td>
                  <td className="py-4 pr-2 text-right">
                    <div className="flex justify-end items-center gap-2">
                      {scan.prediction !== 'safe' && (
                        <button
                          onClick={() => handleMarkSafe(scan)}
                          className="p-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 hover:text-emerald-300 border border-emerald-500/10 cursor-pointer transition"
                          title="Mark Safe / Allow"
                        >
                          <Check className="w-3.5 h-3.5" />
                        </button>
                      )}
                      <button
                        onClick={() => handleDelete(scan.id)}
                        className="p-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 hover:text-red-300 border border-red-500/10 cursor-pointer transition"
                        title="Delete Log"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {paginatedScans.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-cyber-muted">
                    No activity logs matched the search criteria
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>


        {/* Pagination footer */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between border-t border-cyber-inner-border pt-4 mt-4">
            <span className="text-[10px] text-cyber-muted font-light">
              Showing {(currentPage - 1) * itemsPerPage + 1} - {Math.min(currentPage * itemsPerPage, filteredScans.length)} of {filteredScans.length} logs
            </span>
            
            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                disabled={currentPage === 1}
                className="p-1.5 rounded-lg bg-cyber-inner border border-cyber-inner-border text-cyber-muted disabled:opacity-30 disabled:pointer-events-none hover:text-cyber-text cursor-pointer"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              
              <span className="text-xs font-semibold text-cyber-text px-2">
                Page {currentPage} of {totalPages}
              </span>
              
              <button
                onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                disabled={currentPage === totalPages}
                className="p-1.5 rounded-lg bg-cyber-inner border border-cyber-inner-border text-cyber-muted disabled:opacity-30 disabled:pointer-events-none hover:text-cyber-text cursor-pointer"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </GlassCard>
    </div>
  );
};
export default URLLogsPage;
