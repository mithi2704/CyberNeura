/**
 * Subscription Manager for CyberNeura Realtime.
 * Consolidates component listeners to prevent channel proliferation.
 */

import { realtimeClient } from './realtimeClient';
import { eventDeduplicator } from './handlers';
import type { 
  RealtimeEvent, 
  ScanPayload, 
  RiskAssessmentPayload, 
  ThreatDetectedPayload, 
  AgentEventPayload, 
  SecurityAlertPayload 
} from './eventTypes';

export class SubscriptionManager {
  /**
   * Listen to real-time URL scan lifecycle events.
   */
  public subscribeToScans(onScan: (scan: ScanPayload) => void): () => void {
    // 1. Listen to Postgres table changes on url_scans
    const unsubTable = realtimeClient.subscribeToTable('url_scans', (payload) => {
      if (payload.eventType === 'INSERT' || payload.eventType === 'UPDATE') {
        const item = payload.new;
        if (item) {
          const scanPayload: ScanPayload = {
            id: item.id,
            url: item.url,
            riskScore: item.risk_score ?? item.riskScore ?? 0,
            prediction: (item.prediction || 'safe').toLowerCase(),
            confidence: item.confidence ?? 95,
            threatCategory: item.threat_category ?? item.threatCategory,
            ipAddress: item.ip_address ?? item.ipAddress,
            sslStatus: item.ssl_status ?? item.sslStatus,
            scannedAt: item.scanned_at ?? item.scannedAt ?? new Date().toISOString(),
            severity: item.severity,
            summary: item.summary,
          };
          onScan(scanPayload);
        }
      }
    });

    // 2. Also listen to realtime_events table for SCAN_COMPLETED
    const unsubEvents = realtimeClient.subscribeToTable('realtime_events', (payload) => {
      if (payload.eventType === 'INSERT' && payload.new?.event_type === 'SCAN_COMPLETED') {
        const event: RealtimeEvent<ScanPayload> = {
          event_id: payload.new.id,
          event_type: payload.new.event_type,
          entity_type: payload.new.entity_type,
          entity_id: payload.new.entity_id,
          user_id: payload.new.user_id,
          timestamp: payload.new.created_at,
          payload: payload.new.payload,
        };
        if (eventDeduplicator.shouldProcess(event) && event.payload?.url) {
          onScan(event.payload);
        }
      }
    });

    return () => {
      unsubTable();
      unsubEvents();
    };
  }

  /**
   * Listen to real-time risk assessment updates.
   */
  public subscribeToRiskAssessments(
    onAssessment: (assessment: RiskAssessmentPayload) => void
  ): () => void {
    return realtimeClient.subscribeToTable('realtime_events', (payload) => {
      if (
        payload.eventType === 'INSERT' &&
        payload.new?.event_type === 'RISK_ASSESSMENT_COMPLETED'
      ) {
        const event: RealtimeEvent<RiskAssessmentPayload> = {
          event_id: payload.new.id,
          event_type: payload.new.event_type,
          entity_type: payload.new.entity_type,
          entity_id: payload.new.entity_id,
          user_id: payload.new.user_id,
          timestamp: payload.new.created_at,
          payload: payload.new.payload,
        };
        if (eventDeduplicator.shouldProcess(event)) {
          onAssessment(event.payload);
        }
      }
    });
  }

  /**
   * Listen to confirmed threat intelligence events.
   */
  public subscribeToThreats(
    onThreat: (threat: ThreatDetectedPayload) => void
  ): () => void {
    const unsubTable = realtimeClient.subscribeToTable('threat_intelligence', (payload) => {
      if (payload.eventType === 'INSERT' && payload.new?.matched) {
        const item = payload.new;
        onThreat({
          scan_id: item.scan_id,
          url: item.indicator,
          provider: item.provider,
          threat_category: item.threat_type || 'Malicious',
          severity: 'HIGH',
        });
      }
    });

    const unsubEvents = realtimeClient.subscribeToTable('realtime_events', (payload) => {
      if (
        payload.eventType === 'INSERT' &&
        payload.new?.event_type === 'THREAT_DETECTED'
      ) {
        const event: RealtimeEvent<ThreatDetectedPayload> = {
          event_id: payload.new.id,
          event_type: payload.new.event_type,
          entity_type: payload.new.entity_type,
          entity_id: payload.new.entity_id,
          user_id: payload.new.user_id,
          timestamp: payload.new.created_at,
          payload: payload.new.payload,
        };
        if (eventDeduplicator.shouldProcess(event)) {
          onThreat(event.payload);
        }
      }
    });

    return () => {
      unsubTable();
      unsubEvents();
    };
  }

  /**
   * Listen to live Phase 4 AI Agent tool activity and session progression.
   */
  public subscribeToAgent(
    sessionId: string,
    onAgentEvent: (event: AgentEventPayload) => void
  ): () => void {
    return realtimeClient.subscribeToTable('agent_events', (payload) => {
      if (payload.eventType === 'INSERT' && payload.new?.session_id === sessionId) {
        onAgentEvent({
          session_id: payload.new.session_id,
          tool_name: payload.new.tool_name,
          summary: payload.new.output_summary || payload.new.input_summary,
          status: payload.new.status,
          duration_ms: payload.new.duration_ms,
        });
      }
    });
  }

  /**
   * Listen to real-time notification alerts.
   */
  public subscribeToNotifications(
    onNotification: (notif: SecurityAlertPayload) => void
  ): () => void {
    const unsubNotifs = realtimeClient.subscribeToTable('notifications', (payload) => {
      if (payload.eventType === 'INSERT') {
        const item = payload.new;
        onNotification({
          title: item.title,
          message: item.message,
          severity: (item.type || 'INFO').toUpperCase() as any,
          scan_id: item.scan_id,
        });
      }
    });

    const unsubAlerts = realtimeClient.subscribeToTable('realtime_events', (payload) => {
      if (
        payload.eventType === 'INSERT' &&
        (payload.new?.event_type === 'SECURITY_ALERT_CREATED' ||
         payload.new?.event_type === 'NOTIFICATION_CREATED')
      ) {
        const event: RealtimeEvent<SecurityAlertPayload> = {
          event_id: payload.new.id,
          event_type: payload.new.event_type,
          entity_type: payload.new.entity_type,
          entity_id: payload.new.entity_id,
          user_id: payload.new.user_id,
          timestamp: payload.new.created_at,
          payload: payload.new.payload,
        };
        if (eventDeduplicator.shouldProcess(event)) {
          onNotification(event.payload);
        }
      }
    });

    return () => {
      unsubNotifs();
      unsubAlerts();
    };
  }
}

export const subscriptionManager = new SubscriptionManager();
