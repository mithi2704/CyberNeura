/**
 * API Request & Response Contracts for CyberNeura Chrome Extension.
 */

import { ExtensionDecision } from '../security/decision';

export interface ExtensionAnalyzePayload {
  url: string;
  tab_id?: number;
  navigation_id?: string;
  timestamp?: string;
  extension_version: string;
  browser: string;
  installation_id: string;
}

export interface ExtensionAnalyzeResponseData {
  request_id: string;
  url: string;
  decision: ExtensionDecision;
  risk_score: number;
  prediction: string;
  confidence: number;
  threat_category?: string;
  severity?: string;
  summary: string;
  reasons: string[];
  recommendations: string[];
  cached: boolean;
  analysis_timestamp: string;
  policy_version: string;
  risk_engine_version: string;
  allow_override: boolean;
  scan_id?: string;
}

export interface ExtensionOverridePayload {
  scan_id: string;
  url: string;
  installation_id: string;
  original_decision: ExtensionDecision;
  override_action: string;
  timestamp?: string;
}

export interface ExtensionReportPayload {
  scan_id: string;
  url: string;
  installation_id: string;
  report_type: 'false_positive' | 'false_negative' | 'other';
  feedback: string;
  timestamp?: string;
}

export interface ExtensionStatusData {
  service: string;
  status: string;
  policy_version: string;
  strict_mode: boolean;
  fallback_policy: string;
  timeout_seconds: number;
  rate_limit_per_minute: number;
  cache_ttl_seconds: number;
  timestamp: string;
}

export interface ExtensionChatPayload {
  url: string;
  question: string;
  risk_score?: number;
  decision?: string;
  threat_category?: string;
  page_title?: string;
  has_password_inputs?: boolean;
  has_card_inputs?: boolean;
  history?: Array<{ role: string; content: string }>;
}

export interface ExtensionChatResponseData {
  reply: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'THREAT';
  risk_score: number;
  key_findings: string[];
  recommendations: string[];
  timestamp: string;
}

