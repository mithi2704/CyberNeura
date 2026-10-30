/**
 * Centralized Supabase Realtime client singleton.
 * Manages active channels, authenticates subscriptions, and coordinates connection states.
 */

import { supabase, isSupabaseConfigured } from '../lib/supabase/client';
import { connectionManager } from './connectionManager';
import { eventDeduplicator } from './handlers';
import { aiClient } from '../lib/api/aiService';
import type { RealtimeEvent, RealtimeEventHandler } from './eventTypes';

class RealtimeClient {
  private channels: Map<string, any> = new Map();
  private isInitialized = false;
  private currentUserId: string | null = null;

  public initialize(userId?: string | null): void {
    if (this.isInitialized && this.currentUserId === userId) return;

    this.currentUserId = userId || null;
    this.isInitialized = true;

    if (!isSupabaseConfigured) {
      // In offline/mock mode, mark as DEGRADED and start controlled polling
      connectionManager.setStatus('DEGRADED');
      return;
    }

    connectionManager.setStatus('CONNECTING');

    aiClient.get('/realtime/health').then((res) => {
      if (res.data?.realtime === 'FALLBACK_IN_MEMORY' || res.data?.database === 'MOCK_OR_DISCONNECTED') {
        connectionManager.setStatus('DEGRADED');
      }
    }).catch(() => {
      connectionManager.setStatus('DEGRADED');
    });
  }

  /**
   * Subscribe to Postgres Changes on a specific table.
   */
  public subscribeToTable(
    table: string,
    onEvent: (payload: any) => void
  ): () => void {
    if (!isSupabaseConfigured) return () => {};

    const channelKey = `table:${table}`;
    if (this.channels.has(channelKey)) {
      return () => {};
    }

    try {
      const channel = supabase
        .channel(channelKey)
        .on(
          'postgres_changes',
          { event: '*', schema: 'public', table },
          (payload) => {
            onEvent(payload);
          }
        )
        .subscribe((status) => {
          if (status === 'SUBSCRIBED') {
            connectionManager.setStatus('CONNECTED');
          } else if (status === 'CLOSED' || status === 'CHANNEL_ERROR') {
            connectionManager.setStatus('DEGRADED');
          }
        });

      this.channels.set(channelKey, channel);

      return () => {
        try {
          supabase.removeChannel(channel);
          this.channels.delete(channelKey);
        } catch { /* ignore */ }
      };
    } catch (err) {
      console.warn(`Failed to subscribe to table ${table}:`, err);
      connectionManager.handleDisconnect(() => this.reconnect());
      return () => {};
    }
  }

  /**
   * Subscribe to broadcast events on a specific channel topic.
   */
  public subscribeToBroadcast<T = any>(
    channelName: string,
    eventName: string,
    handler: RealtimeEventHandler<T>
  ): () => void {
    if (!isSupabaseConfigured) return () => {};

    const channelKey = `broadcast:${channelName}`;
    let channel = this.channels.get(channelKey);

    if (!channel) {
      channel = supabase.channel(channelName);
      this.channels.set(channelKey, channel);
    }

    channel.on('broadcast', { event: eventName }, (response: any) => {
      const event = response?.payload as RealtimeEvent<T>;
      if (event && eventDeduplicator.shouldProcess(event)) {
        handler(event);
      }
    });

    channel.subscribe((status: string) => {
      if (status === 'SUBSCRIBED') {
        connectionManager.setStatus('CONNECTED');
      } else if (status === 'CLOSED' || status === 'CHANNEL_ERROR') {
        connectionManager.handleDisconnect(() => this.reconnect());
      }
    });

    return () => {
      // Unsubscribe when component unmounts
      try {
        supabase.removeChannel(channel);
        this.channels.delete(channelKey);
      } catch { /* ignore */ }
    };
  }

  public reconnect(): void {
    if (!isSupabaseConfigured) return;
    this.unsubscribeAll();
    connectionManager.setStatus('CONNECTING');
  }

  public unsubscribeAll(): void {
    this.channels.forEach((channel) => {
      try {
        supabase.removeChannel(channel);
      } catch { /* ignore */ }
    });
    this.channels.clear();
    eventDeduplicator.clear();
  }

  public disconnect(): void {
    this.unsubscribeAll();
    this.isInitialized = false;
    this.currentUserId = null;
    connectionManager.reset();
  }
}

export const realtimeClient = new RealtimeClient();
