import { DestroyRef, Injectable, NgZone, inject, signal } from '@angular/core';

import type { LiveEvent } from './models';

/**
 * Live subscribes to the server's event stream.
 *
 * Server-Sent Events rather than a WebSocket: the traffic is one-directional,
 * it survives proxies that mangle upgrades, and the browser reconnects on its
 * own. The session cookie authenticates the stream, so there is nothing to
 * attach beyond `withCredentials`.
 */
@Injectable({ providedIn: 'root' })
export class Live {
  private readonly zone = inject(NgZone);
  private readonly destroyRef = inject(DestroyRef);

  /** The most recent events, newest first, capped so a long-lived tab does
   *  not accumulate without bound. */
  readonly recent = signal<LiveEvent[]>([]);
  readonly connected = signal(false);

  private source?: EventSource;
  private subscribers = 0;

  constructor() {
    this.destroyRef.onDestroy(() => this.close());
  }

  /**
   * Attaches to the stream, opening it on the first caller. The returned
   * function detaches; the stream closes when the last caller lets go.
   */
  attach(): () => void {
    this.subscribers++;
    this.open();

    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.subscribers--;
      if (this.subscribers <= 0) this.close();
    };
  }

  private open(): void {
    if (this.source) return;

    const source = new EventSource('/api/v1/events/stream', { withCredentials: true });
    this.source = source;

    source.onopen = () => this.zone.run(() => this.connected.set(true));

    source.onerror = () => {
      // EventSource reconnects on its own; reflect the gap rather than
      // tearing the stream down and losing that behaviour.
      this.zone.run(() => this.connected.set(false));
    };

    // Events carry a `type`, so a named listener per type would mean knowing
    // the whole list up front. Listening to the default `message` channel is
    // not enough — the server names each event — so every known type is
    // handled through one generic listener attached below.
    source.onmessage = (ev) => this.push(ev.data);

    for (const type of KNOWN_EVENTS) {
      source.addEventListener(type, (ev) => this.push((ev as MessageEvent).data));
    }
  }

  private push(raw: string): void {
    let parsed: LiveEvent;
    try {
      parsed = JSON.parse(raw) as LiveEvent;
    } catch {
      return; // a malformed frame is not worth breaking the stream over
    }

    this.zone.run(() => {
      this.recent.update((list) => [parsed, ...list].slice(0, 200));
    });
  }

  private close(): void {
    this.source?.close();
    this.source = undefined;
    this.connected.set(false);
  }
}

/**
 * The event names the server emits. Kept in step with internal/events by the
 * `/api/v1/events/types` endpoint, which the settings screen renders from.
 */
const KNOWN_EVENTS = [
  'key.created', 'key.revoked', 'key.expiring', 'key.deployed',
  'deploy.failed', 'rotation.started', 'rotation.staged', 'rotation.verified',
  'rotation.soaking', 'rotation.completed', 'rotation.failed', 'rotation.aborted',
  'drift.detected', 'verification.failed', 'job.failed', 'backup.completed',
  'discovery.unmanaged_key',
];
