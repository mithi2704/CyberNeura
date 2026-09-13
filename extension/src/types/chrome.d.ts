/**
 * Chrome Extension Manifest V3 TypeScript Type Declarations for CyberNeura.
 */
declare namespace chrome {
  export namespace runtime {
    export const id: string;
    export function getURL(path: string): string;
    export function getManifest(): any;
    export const onInstalled: {
      addListener(callback: (details: { reason: string; previousVersion?: string }) => void): void;
    };
    export const onMessage: {
      addListener(
        callback: (
          message: any,
          sender: { tab?: chrome.tabs.Tab; frameId?: number; id?: string; url?: string },
          sendResponse: (response?: any) => void
        ) => boolean | void
      ): void;
    };
    export function sendMessage(message: any, responseCallback?: (response: any) => void): Promise<any>;
    export function openOptionsPage(callback?: () => void): Promise<void> | void;
    export const lastError: { message?: string } | undefined;
  }

  export namespace storage {
    export interface StorageArea {
      get(keys?: string | string[] | Record<string, any> | null): Promise<Record<string, any>>;
      set(items: Record<string, any>): Promise<void>;
      remove(keys: string | string[]): Promise<void>;
      clear(): Promise<void>;
    }
    export const local: StorageArea;
    export const sync: StorageArea;
  }

  export namespace tabs {
    export interface Tab {
      id?: number;
      index: number;
      windowId: number;
      highlighted: boolean;
      active: boolean;
      pinned: boolean;
      url?: string;
      title?: string;
      favIconUrl?: string;
      status?: string;
      incognito: boolean;
    }
    export function query(queryInfo: { active?: boolean; currentWindow?: boolean; url?: string | string[] }): Promise<Tab[]>;
    export function get(tabId: number): Promise<Tab>;
    export function update(tabId: number, updateProperties: { url?: string; active?: boolean }): Promise<Tab>;
    export function create(createProperties: { url?: string; active?: boolean }): Promise<Tab>;
    export function remove(tabId: number): Promise<void>;
    export const onUpdated: {
      addListener(callback: (tabId: number, changeInfo: { status?: string; url?: string }, tab: Tab) => void): void;
    };
    export const onRemoved: {
      addListener(callback: (tabId: number, removeInfo: { windowId: number; isWindowClosing: boolean }) => void): void;
    };
  }

  export namespace webNavigation {
    export interface NavigationDetails {
      tabId: number;
      url: string;
      processId?: number;
      frameId: number;
      parentFrameId?: number;
      timeStamp: number;
      navigationId?: string;
    }
    export const onBeforeNavigate: {
      addListener(
        callback: (details: NavigationDetails) => void,
        filters?: { url: Array<{ hostEquals?: string; schemes?: string[]; urlMatches?: string }> }
      ): void;
    };
    export const onCommitted: {
      addListener(callback: (details: NavigationDetails) => void): void;
    };
    export const onCompleted: {
      addListener(callback: (details: NavigationDetails) => void): void;
    };
  }

  export namespace notifications {
    export interface NotificationOptions {
      type: 'basic' | 'image' | 'list' | 'progress';
      iconUrl: string;
      title: string;
      message: string;
      priority?: number;
      eventTime?: number;
      buttons?: Array<{ title: string; iconUrl?: string }>;
    }
    export function create(notificationId: string, options: NotificationOptions): Promise<string>;
    export function clear(notificationId: string): Promise<boolean>;
  }

  export namespace action {
    export function setBadgeText(details: { text: string; tabId?: number }): Promise<void>;
    export function setBadgeBackgroundColor(details: { color: string | [number, number, number, number]; tabId?: number }): Promise<void>;
    export function setTitle(details: { title: string; tabId?: number }): Promise<void>;
    export function openPopup(): Promise<void>;
  }
}
