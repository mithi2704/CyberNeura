/**
 * HTTP Client communicating authoritatively with CyberNeura FastAPI Backend.
 * Features strict timeouts (8000ms), automatic fallback on network drop,
 * and zero embedding of API keys or service role secrets.
 */

import {
  ExtensionAnalyzePayload,
  ExtensionAnalyzeResponseData,
  ExtensionOverridePayload,
  ExtensionReportPayload,
  ExtensionStatusData,
  ExtensionChatPayload,
  ExtensionChatResponseData,
} from './types';
import { storageManager } from '../storage/storage';

const REQUEST_TIMEOUT_MS = 8000;

export class CyberNeuraApiClient {
  private static instance: CyberNeuraApiClient;

  public static getInstance(): CyberNeuraApiClient {
    if (!CyberNeuraApiClient.instance) {
      CyberNeuraApiClient.instance = new CyberNeuraApiClient();
    }
    return CyberNeuraApiClient.instance;
  }

  private async getBaseUrl(): Promise<string> {
    const settings = await storageManager.getSettings();
    return (settings.backendUrl || 'http://localhost:8000').replace(/\/+$/, '');
  }

  private async getHeaders(): Promise<Record<string, string>> {
    const settings = await storageManager.getSettings();
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };
    if (settings.authToken) {
      headers['Authorization'] = `Bearer ${settings.authToken}`;
    }
    return headers;
  }

  /**
   * Dispatches URL for authoritative analysis by CyberNeura backend.
   */
  async analyzeUrl(payload: ExtensionAnalyzePayload): Promise<ExtensionAnalyzeResponseData> {
    const baseUrl = await this.getBaseUrl();
    const headers = await this.getHeaders();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch(`${baseUrl}/api/v1/extension/analyze`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`CyberNeura backend HTTP ${response.status}: ${response.statusText}`);
      }

      const data: ExtensionAnalyzeResponseData = await response.json();
      return data;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Queries backend health and policy status.
   */
  async getStatus(): Promise<ExtensionStatusData> {
    const baseUrl = await this.getBaseUrl();
    const headers = await this.getHeaders();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);

    try {
      const response = await fetch(`${baseUrl}/api/v1/extension/status`, {
        method: 'GET',
        headers,
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return await response.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Reports user override ("Continue Anyway") to backend.
   */
  async recordOverride(payload: ExtensionOverridePayload): Promise<boolean> {
    const baseUrl = await this.getBaseUrl();
    const headers = await this.getHeaders();
    try {
      const response = await fetch(`${baseUrl}/api/v1/extension/override`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
      });
      return response.ok;
    } catch (err) {
      console.warn('CyberNeura API: override record failed:', err);
      return false;
    }
  }

  /**
   * Sends user false-positive/negative feedback to backend.
   */
  async submitReport(payload: ExtensionReportPayload): Promise<boolean> {
    const baseUrl = await this.getBaseUrl();
    const headers = await this.getHeaders();
    try {
      const response = await fetch(`${baseUrl}/api/v1/extension/report`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
      });
      return response.ok;
    } catch (err) {
      console.warn('CyberNeura API: feedback report failed:', err);
      return false;
    }
  }

  /**
   * Interactively queries CyberNeura AI Security Agent about active website.
   */
  async chat(payload: ExtensionChatPayload): Promise<ExtensionChatResponseData> {
    const baseUrl = await this.getBaseUrl();
    const headers = await this.getHeaders();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch(`${baseUrl}/api/v1/extension/chat`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`CyberNeura backend chat HTTP ${response.status}`);
      }

      return await response.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

export const apiClient = CyberNeuraApiClient.getInstance();

