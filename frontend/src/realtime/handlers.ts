/**
 * Event deduplication and out-of-order protection engine.
 * Ensures the UI never processes the same event_id twice and enforces latest timestamp validity.
 */

import type { RealtimeEvent } from './eventTypes';

class EventDeduplicator {
  private seenEventIds = new Set<string>();
  private maxCapacity = 500;
  private entityTimestamps = new Map<string, string>();

  /**
   * Evaluates whether an event should be processed.
   * Returns true if event is fresh, unique, and sequential.
   */
  public shouldProcess(event: RealtimeEvent): boolean {
    if (!event || !event.event_id) return false;

    // 1. Check idempotency: Have we already processed this event_id?
    if (this.seenEventIds.has(event.event_id)) {
      return false;
    }

    // 2. Check out-of-order delivery for the same entity:
    // If we already saw an event for entity_id with a newer timestamp, ignore stale event.
    if (event.entity_id && event.timestamp) {
      const lastTs = this.entityTimestamps.get(event.entity_id);
      if (lastTs && event.timestamp < lastTs) {
        // Stale out-of-order event, ignore
        return false;
      }
      this.entityTimestamps.set(event.entity_id, event.timestamp);
    }

    // 3. Mark event_id as processed
    this.seenEventIds.add(event.event_id);

    // Prevent unbounded memory growth by clearing oldest if capacity exceeded
    if (this.seenEventIds.size > this.maxCapacity) {
      const firstEntries = Array.from(this.seenEventIds).slice(0, 100);
      firstEntries.forEach(id => this.seenEventIds.delete(id));
    }

    return true;
  }

  public clear(): void {
    this.seenEventIds.clear();
    this.entityTimestamps.clear();
  }
}

export const eventDeduplicator = new EventDeduplicator();
