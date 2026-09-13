/**
 * Real-time service facade for CyberNeura React components.
 * Unifies client management, subscription dispatch, and resynchronization.
 */

import { realtimeClient } from '../realtime/realtimeClient';
import { subscriptionManager } from '../realtime/subscriptions';
import { connectionManager } from '../realtime/connectionManager';
import { aiClient } from '../lib/api/aiService';
import type { 
  ConnectionStatus, 
  ScanPayload, 
  RiskAssessmentPayload, 
  ThreatDetectedPayload, 
  AgentEventPayload, 
  SecurityAlertPayload 
} from '../realtime/eventTypes';

export const realtimeService = {
  initialize(userId?: string | null): void {
    realtimeClient.initialize(userId);
  },

  disconnect(): void {
    realtimeClient.disconnect();
  },

  getConnectionStatus(): ConnectionStatus {
    return connectionManager.getStatus();
  },

  onConnectionStatusChange(listener: (status: ConnectionStatus) => void): () => void {
    return connectionManager.onStatusChange(listener);
  },

  onResync(callback: () => Promise<void> | void): () => void {
    return connectionManager.onResync(callback);
  },

  subscribeToScans(onScan: (scan: ScanPayload) => void): () => void {
    return subscriptionManager.subscribeToScans(onScan);
  },

  subscribeToRiskAssessments(onAssessment: (assessment: RiskAssessmentPayload) => void): () => void {
    return subscriptionManager.subscribeToRiskAssessments(onAssessment);
  },

  subscribeToThreats(onThreat: (threat: ThreatDetectedPayload) => void): () => void {
    return subscriptionManager.subscribeToThreats(onThreat);
  },

  subscribeToAgent(sessionId: string, onAgentEvent: (event: AgentEventPayload) => void): () => void {
    return subscriptionManager.subscribeToAgent(sessionId, onAgentEvent);
  },

  subscribeToNotifications(onNotification: (notif: SecurityAlertPayload) => void): () => void {
    return subscriptionManager.subscribeToNotifications(onNotification);
  },

  async fetchMissedEvents(since?: string): Promise<any[]> {
    try {
      const url = since ? `/realtime/events?since=${encodeURIComponent(since)}` : '/realtime/events';
      const res = await aiClient.get(url);
      return res.data?.events || [];
    } catch (err) {
      console.warn('Failed to fetch missed events:', err);
      return [];
    }
  },

  async checkHealth(): Promise<any> {
    try {
      const res = await aiClient.get('/realtime/health');
      return res.data;
    } catch (err) {
      return { status: 'DEGRADED', realtime: 'UNAVAILABLE' };
    }
  },
};
