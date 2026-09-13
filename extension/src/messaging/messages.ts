/**
 * Typed Internal Message Protocols for CyberNeura Chrome Extension.
 * Connects Background Service Worker, Popup, Options, and Interstitial Warning Pages.
 */

export type ExtensionMessageType =
  | 'GET_TAB_STATUS'
  | 'TRIGGER_RESCAN'
  | 'RECORD_OVERRIDE'
  | 'SUBMIT_REPORT'
  | 'GET_SETTINGS'
  | 'SAVE_SETTINGS'
  | 'CHECK_BACKEND_STATUS'
  | 'ASK_AI_AGENT';

export interface ExtensionMessage<T = any> {
  type: ExtensionMessageType;
  payload?: T;
}

export interface TabStatusResponse {
  tabId?: number;
  url?: string;
  isInspected: boolean;
  decision?: 'ALLOW' | 'WARN' | 'BLOCK';
  riskScore?: number;
  prediction?: string;
  confidence?: number;
  threatCategory?: string;
  summary?: string;
  reasons?: string[];
  recommendations?: string[];
  scanId?: string;
  isCached?: boolean;
}
