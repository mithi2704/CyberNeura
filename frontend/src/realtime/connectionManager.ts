/**
 * Connection lifecycle manager with exponential backoff reconnection,
 * health status reporting, missed-event recovery, and polling fallback.
 */

import type { ConnectionStatus } from './eventTypes';

export type StatusListener = (status: ConnectionStatus) => void;
export type ResyncCallback = () => Promise<void> | void;

export class ConnectionManager {
  private status: ConnectionStatus = 'DISCONNECTED';
  private listeners: Set<StatusListener> = new Set();
  private resyncCallbacks: Set<ResyncCallback> = new Set();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectTimer: any = null;
  private pollingTimer: any = null;
  private fallbackIntervalMs = 30000; // 30 seconds default
  private isFallbackActive = false;

  public getStatus(): ConnectionStatus {
    return this.status;
  }

  public onStatusChange(listener: StatusListener): () => void {
    this.listeners.add(listener);
    listener(this.status);
    return () => this.listeners.delete(listener);
  }

  public onResync(callback: ResyncCallback): () => void {
    this.resyncCallbacks.add(callback);
    return () => this.resyncCallbacks.delete(callback);
  }

  public setStatus(newStatus: ConnectionStatus): void {
    if (this.status === newStatus) return;
    this.status = newStatus;
    this.listeners.forEach(fn => {
      try { fn(newStatus); } catch { /* ignore */ }
    });

    if (newStatus === 'CONNECTED') {
      this.reconnectAttempts = 0;
      this.stopFallbackPolling();
      // Trigger missed event resynchronization upon reconnect
      this.triggerResync();
    } else if (newStatus === 'DISCONNECTED' || newStatus === 'DEGRADED') {
      this.startFallbackPolling();
    }
  }

  public handleDisconnect(reconnectFn: () => void): void {
    if (this.status === 'RECONNECTING') return;

    this.setStatus('RECONNECTING');
    this.scheduleReconnect(reconnectFn);
  }

  private scheduleReconnect(reconnectFn: () => void): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.setStatus('DISCONNECTED');
      this.startFallbackPolling();
      return;
    }

    this.reconnectAttempts++;
    // Exponential backoff: 1s, 2s, 4s, 8s... capped at 30s
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts - 1), 30000);

    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => {
      try {
        reconnectFn();
      } catch (err) {
        this.scheduleReconnect(reconnectFn);
      }
    }, delay);
  }

  public startFallbackPolling(): void {
    if (this.isFallbackActive) return;
    this.isFallbackActive = true;

    // Run first poll shortly, then interval
    this.pollingTimer = setInterval(() => {
      this.triggerResync();
    }, this.fallbackIntervalMs);
  }

  public stopFallbackPolling(): void {
    this.isFallbackActive = false;
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = null;
    }
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private async triggerResync(): Promise<void> {
    for (const callback of this.resyncCallbacks) {
      try {
        await callback();
      } catch (err) {
        console.warn('Resync callback failed:', err);
      }
    }
  }

  public reset(): void {
    this.stopFallbackPolling();
    this.reconnectAttempts = 0;
    this.status = 'DISCONNECTED';
  }
}

export const connectionManager = new ConnectionManager();
