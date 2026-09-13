/**
 * Real-time event types and typed payload contracts for CyberNeura frontend.
 */

export type RealtimeEventType =
  | 'SCAN_CREATED'
  | 'SCAN_STARTED'
  | 'SCAN_COMPLETED'
  | 'SCAN_FAILED'
  | 'RISK_ASSESSMENT_STARTED'
  | 'RISK_ASSESSMENT_COMPLETED'
  | 'RISK_SCORE_CHANGED'
  | 'THREAT_INTEL_STARTED'
  | 'THREAT_INTEL_UPDATED'
  | 'THREAT_DETECTED'
  | 'EVIDENCE_CREATED'
  | 'EVIDENCE_UPDATED'
  | 'FINDING_CREATED'
  | 'AGENT_STARTED'
  | 'AGENT_TOOL_STARTED'
  | 'AGENT_TOOL_COMPLETED'
  | 'AGENT_COMPLETED'
  | 'AGENT_FAILED'
  | 'SECURITY_ALERT_CREATED'
  | 'NOTIFICATION_CREATED'
  | 'SYSTEM_STATUS_CHANGED'
  | 'EXTENSION_SCAN_STARTED'
  | 'EXTENSION_SCAN_COMPLETED'
  | 'EXTENSION_WARNING_SHOWN'
  | 'EXTENSION_BLOCKED'
  | 'EXTENSION_OVERRIDE'
  | 'EXTENSION_REPORT_SUBMITTED';

export type EntityType =
  | 'url_scan'
  | 'risk_assessment'
  | 'threat_intelligence'
  | 'evidence'
  | 'correlated_finding'
  | 'agent_session'
  | 'agent_event'
  | 'notification'
  | 'security_alert'
  | 'extension_event'
  | 'system';

export interface RealtimeEvent<T = Record<string, any>> {
  event_id: string;
  event_type: RealtimeEventType;
  entity_type: EntityType;
  entity_id: string;
  user_id?: string | null;
  timestamp: string;
  version?: number;
  payload: T;
}

export type ConnectionStatus =
  | 'CONNECTED'
  | 'CONNECTING'
  | 'RECONNECTING'
  | 'DISCONNECTED'
  | 'DEGRADED';

// Specific payload shapes
export interface ScanPayload {
  id: string;
  url: string;
  riskScore: number;
  prediction: 'safe' | 'suspicious' | 'malicious';
  confidence: number;
  threatCategory?: string;
  ipAddress?: string;
  sslStatus?: 'valid' | 'invalid' | 'expired' | 'none';
  scannedAt: string;
  severity?: string;
  summary?: string;
}

export interface RiskAssessmentPayload {
  assessment_id: string;
  scan_id: string;
  url: string;
  risk_score: number;
  prediction: string;
  confidence: number;
  threat_category?: string;
  severity: string;
  summary?: string;
}

export interface ThreatDetectedPayload {
  scan_id: string;
  url: string;
  provider: string;
  threat_category: string;
  severity: string;
}

export interface AgentEventPayload {
  session_id: string;
  tool_name?: string;
  summary?: string;
  status: string;
  duration_ms?: number;
}

export interface SecurityAlertPayload {
  title: string;
  message: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  scan_id?: string;
  url?: string;
}

export type RealtimeEventHandler<T = any> = (event: RealtimeEvent<T>) => void;
