export interface UserProfile {
  id: string; // matches Firebase UID
  email: string;
  displayName?: string;
  avatarUrl?: string;
  role: 'admin' | 'analyst' | 'viewer' | 'user';
  createdAt: string;
  updatedAt: string;
}

export type UserRole = 'admin' | 'analyst' | 'viewer' | 'user';

export interface Permission {
  id: string;
  role: UserRole;
  resource: string;
  action: 'create' | 'read' | 'update' | 'delete' | '*';
}

export interface URLScan {
  id: string;
  url: string;
  riskScore: number; // 0-100
  prediction: 'safe' | 'suspicious' | 'malicious';
  confidence: number; // 0-100 (percentage)
  threatCategory: string;
  explanation?: string;
  probability?: number;
  domainAge?: string;
  hostingProvider?: string;
  ipAddress?: string;
  country?: string;
  sslStatus?: 'valid' | 'invalid' | 'expired' | 'none';
  whoisRecord?: string;
  dnsRecords?: string;
  recommendations?: string[];
  scannedBy?: string; // profile uuid
  scannedAt: string;
  threatIntelligence?: Record<string, any>;
  evidence?: ScanEvidenceItem[];
  independentConfirmations?: number;
  evidenceCount?: number;
  severity?: string;
  summary?: string;
  primaryThreatSource?: string;
  riskAssessment?: SecurityAssessment;
  riskFactors?: RiskFactor[];
  correlatedFindings?: CorrelatedFinding[];
  detailedRecommendations?: DetailedRecommendation[];
  source?: 'Dashboard' | 'Extension' | 'API';
  decision?: 'ALLOW' | 'WARN' | 'BLOCK';
  userOverride?: boolean;
}


export interface ScanReport {
  id: string;
  scanId: string;
  pdfUrl?: string;
  threatScreenshotUrl?: string;
  csvExportUrl?: string;
  createdAt: string;
}

export interface ThreatLog {
  id: string;
  url: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  sourceIp: string;
  country: string;
  timestamp: string;
  status: 'active' | 'blocked' | 'flagged' | 'resolved';
}

export interface Notification {
  id: string;
  title: string;
  body: string;
  type: 'critical_alert' | 'daily_report' | 'weekly_report' | 'threat_alert' | 'system_update';
  isRead: boolean;
  userId?: string;
  createdAt: string;
}

export interface ThreatCategory {
  id: string;
  name: string;
  code: string;
  description: string;
  count: number;
}

export interface MLModelMetrics {
  id: string;
  version: string;
  algorithm: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  trainingSamples: number;
  lastTrainingDate: string;
  deploymentStatus: 'production' | 'staging' | 'deprecated';
}

export interface SystemSettings {
  id: string;
  userId: string;
  realTimeProtection: boolean;
  autoBlock: boolean;
  emailScanning: boolean;
  browserProtection: boolean;
  apiAccess: boolean;
  notificationPreferences: {
    criticalAlerts: boolean;
    dailyReports: boolean;
    weeklyAnalytics: boolean;
    systemUpdates: boolean;
    newFeatures: boolean;
  };
  licenseKey?: string;
  licenseValidUntil?: string;
  apiUsageLimit: number;
  apiUsageCount: number;
  updatedAt: string;
}

export interface ActivityLog {
  id: string;
  userId: string;
  userEmail: string;
  action: string;
  description: string;
  ipAddress: string;
  timestamp: string;
}

export interface APIUsage {
  id: string;
  userId: string;
  endpoint: string;
  requestCount: number;
  timestamp: string;
}

export interface Feedback {
  id: string;
  userId: string;
  scanId: string;
  isCorrect: boolean;
  comments?: string;
  createdAt: string;
}

export interface ChatTimelineStep {
  step: string;
  status: 'completed' | 'running' | 'failed';
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  scanId?: string; // optional reference to a scanned URL
  sessionId?: string;
  risk?: number;
  confidence?: number;
  threatCategory?: string;
  recommendations?: string[];
  toolsUsed?: string[];
  timeline?: ChatTimelineStep[];
  evidence?: any[];
}

export interface ThreatIntelResult {
  provider: string;
  indicator: string;
  indicator_type: string;
  available: boolean;
  matched: boolean;
  verdict: 'MATCH' | 'NO_MATCH' | 'UNAVAILABLE' | 'ERROR' | 'RATE_LIMITED';
  categories: string[];
  confidence?: number;
  checked_at: string;
  expires_at?: string;
  error?: string;
  latency_ms: number;
  metadata?: Record<string, any>;
}

export interface ScanEvidenceItem {
  source: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
  matched: boolean;
  value?: any;
}

export interface ProviderStatusInfo {
  name: string;
  enabled: boolean;
  configured: boolean;
  status: 'HEALTHY' | 'DEGRADED' | 'NOT_CONFIGURED';
  lastSuccessfulCheck?: string;
  lastError?: string;
}

export interface RiskFactor {
  id: string;
  scan_id?: string;
  factor_type: string;
  factor_name: string;
  raw_value?: any;
  normalized_value: number;
  weight: number;
  contribution: number;
  max_contribution: number;
  direction: 'RISK_INCREASING' | 'RISK_DECREASING' | 'NEUTRAL';
  description: string;
  created_at: string;
}

export interface CorrelatedFinding {
  id: string;
  scan_id?: string;
  finding_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: number;
  description: string;
  sources: string[];
  evidence_ids?: string[];
  rule_id?: string;
  created_at: string;
}

export interface DetailedRecommendation {
  id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  reason: string;
  action: string;
}

export interface SecurityAssessment {
  id: string;
  scan_id: string;
  url: string;
  risk_score: number;
  prediction: 'safe' | 'suspicious' | 'malicious';
  confidence: number;
  threat_category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  summary: string;
  evidence_count: number;
  critical_evidence_count: number;
  supporting_evidence_count: number;
  contradicting_evidence_count: number;
  evidence: any[];
  correlated_findings: CorrelatedFinding[];
  risk_factors: RiskFactor[];
  recommendations: DetailedRecommendation[];
  explanation: string;
  risk_engine_version: string;
  config_version: string;
  created_at: string;
}

export interface RiskConfig {
  id: string;
  name: string;
  version: string;
  weights: Record<string, number>;
  thresholds: Record<string, number>;
  enabled: boolean;
  created_at: string;
  updated_at?: string;
}

export interface AgentFinding {
  id: string;
  session_id: string;
  finding_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  statement: string;
  evidence_ids: string[];
  confidence: number;
  created_at: string;
}

export interface ReasoningStep {
  step: number;
  observation: string;
  evidence_ids: string[];
  inference: string;
  confidence: number;
}

export interface AgentInvestigationReport {
  session_id: string;
  user_id?: string;
  scan_id?: string;
  url: string;
  objective: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'STOPPED';
  started_at: string;
  completed_at?: string;
  final_assessment: Record<string, any>;
  key_findings: AgentFinding[];
  evidence_summary: any[];
  reasoning_summary: ReasoningStep[];
  uncertainties: string[];
  recommendations: string[];
  tools_used: string[];
  total_steps: number;
  total_tool_calls: number;
  created_at: string;
}

export interface AgentEvent {
  id: string;
  session_id: string;
  user_id?: string;
  event_type: string;
  tool_name?: string;
  input_summary?: string;
  output_summary?: string;
  status: string;
  duration_ms: number;
  created_at: string;
}


