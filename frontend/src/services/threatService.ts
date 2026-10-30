import { supabase, isSupabaseConfigured } from '../lib/supabase/client';
import { aiClient } from '../lib/api/aiService';
import type { ThreatLog } from '../types';

export async function fetchThreatLogs(pageSize: number = 100): Promise<ThreatLog[]> {
  try {
    const res = await aiClient.get(`/threats?page=1&page_size=${pageSize}`);
    if (res.data && Array.isArray(res.data.items)) {
      return res.data.items.map((t: any) => ({
        id: t.id,
        url: t.url,
        severity: t.severity ?? 'high',
        category: t.category ?? 'Phishing',
        sourceIp: t.sourceIp ?? t.source_ip ?? '192.168.1.1',
        country: t.country ?? 'Unknown',
        timestamp: t.timestamp ?? new Date().toISOString(),
        status: t.status ?? 'blocked',
      }));
    }
    return [];
  } catch (err) {
    console.warn('Backend /threats unreachable:', err);
    return [];
  }
}

export async function deleteThreatLog(id: string): Promise<boolean> {
  try {
    await aiClient.delete(`/threats/${id}`);
    return true;
  } catch (err) {
    console.warn('Backend delete threat error:', err);
    return false;
  }
}

import { realtimeService } from './realtimeService';

export function subscribeToLiveThreats(callback: (threat: ThreatLog) => void) {
  return realtimeService.subscribeToThreats((t) => {
    callback({
      id: `threat-${t.scan_id}-${Date.now()}`,
      url: t.url,
      severity: (t.severity.toLowerCase() as any) || 'high',
      category: t.threat_category || 'Malicious',
      sourceIp: 'Threat Feed',
      country: 'Global',
      timestamp: new Date().toISOString(),
      status: 'blocked',
    });
  });
}
