/**
 * Local Storage and Cache Manager for CyberNeura Chrome Extension.
 * Uses Chrome Storage API with short TTL (300s) to guarantee high performance
 * while ensuring backend freshness remains authoritative.
 */

import { ExtensionDecision } from '../security/decision';

export interface ExtensionSettings {
  protectionEnabled: boolean;
  strictMode: boolean;
  notificationsEnabled: boolean;
  backendUrl: string;
  authToken: string | null;
  userEmail: string | null;
}

export interface CachedAnalysis {
  url: string;
  decision: ExtensionDecision;
  riskScore: number;
  prediction: string;
  confidence: number;
  threatCategory?: string;
  summary: string;
  reasons: string[];
  recommendations: string[];
  timestamp: number;
  expiresAt: number;
  scanId?: string;
  allowOverride: boolean;
}

const DEFAULT_SETTINGS: ExtensionSettings = {
  protectionEnabled: true,
  strictMode: false,
  notificationsEnabled: true,
  backendUrl: 'http://localhost:8000',
  authToken: null,
  userEmail: null,
};

const CACHE_TTL_MS = 300 * 1000; // 300 seconds (5 minutes)

export class StorageManager {
  private static instance: StorageManager;

  public static getInstance(): StorageManager {
    if (!StorageManager.instance) {
      StorageManager.instance = new StorageManager();
    }
    return StorageManager.instance;
  }

  /**
   * Retrieves or initializes anonymous device installation identifier.
   */
  async getInstallationId(): Promise<string> {
    try {
      const data = await chrome.storage.local.get(['installation_id']);
      if (data && data.installation_id) {
        return data.installation_id;
      }
      const newId = `inst-${crypto.randomUUID()}`;
      await chrome.storage.local.set({ installation_id: newId });
      return newId;
    } catch {
      return 'inst-fallback-default';
    }
  }

  /**
   * Loads user extension configuration settings.
   */
  async getSettings(): Promise<ExtensionSettings> {
    try {
      const data = await chrome.storage.local.get(['settings']);
      return { ...DEFAULT_SETTINGS, ...(data?.settings || {}) };
    } catch {
      return DEFAULT_SETTINGS;
    }
  }

  /**
   * Persists updated configuration settings.
   */
  async saveSettings(updates: Partial<ExtensionSettings>): Promise<ExtensionSettings> {
    const current = await this.getSettings();
    const merged = { ...current, ...updates };
    await chrome.storage.local.set({ settings: merged });
    return merged;
  }

  /**
   * Checks local URL cache for fresh security decision.
   */
  async getCachedAnalysis(normalizedUrl: string): Promise<CachedAnalysis | null> {
    try {
      const cacheKey = `cache:${normalizedUrl}`;
      const data = await chrome.storage.local.get([cacheKey]);
      const entry: CachedAnalysis | undefined = data?.[cacheKey];

      if (!entry) return null;

      const now = Date.now();
      if (now > entry.expiresAt) {
        // Expired entry
        await chrome.storage.local.remove([cacheKey]);
        return null;
      }

      return entry;
    } catch {
      return null;
    }
  }

  /**
   * Stores security decision in local cache with short TTL.
   */
  async setCachedAnalysis(
    normalizedUrl: string,
    analysis: Omit<CachedAnalysis, 'timestamp' | 'expiresAt' | 'url'>
  ): Promise<void> {
    try {
      const now = Date.now();
      const cacheKey = `cache:${normalizedUrl}`;
      const entry: CachedAnalysis = {
        ...analysis,
        url: normalizedUrl,
        timestamp: now,
        expiresAt: now + CACHE_TTL_MS,
      };
      await chrome.storage.local.set({ [cacheKey]: entry });
    } catch (err) {
      console.warn('CyberNeura Storage: cache save error:', err);
    }
  }

  /**
   * Clears all cached security analyses.
   */
  async clearCache(): Promise<void> {
    try {
      const all = await chrome.storage.local.get(null);
      const cacheKeys = Object.keys(all).filter((k) => k.startsWith('cache:'));
      if (cacheKeys.length > 0) {
        await chrome.storage.local.remove(cacheKeys);
      }
    } catch (err) {
      console.warn('CyberNeura Storage: clearCache error:', err);
    }
  }
}

export const storageManager = StorageManager.getInstance();
