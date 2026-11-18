import { nowIso } from '../src/core/util.js';

/** How often a comment line is written to keep intermediaries from closing an idle stream. */
export const HEARTBEAT_MS = 15000;

const EVENT_NAME_RE = /[^a-z0-9:_-]/gi;

/**
 * In-process pub/sub hub for dashboard live updates.
 *
 * The CLI owns the engine and feeds the bus with `publish(event)`; connected browsers get a
 * Server-Sent Events stream. Events are plain objects with at least a `type`; the bus also keeps a
 * small amount of derived engine state so a newly connected client can render immediately.
 */
export class EventBus {
  constructor() {
    this.startedAt = nowIso();
    this.clients = new Set();
    this.lastEvent = null;
    this.engine = {
      running: false,
      runId: null,
      engagementId: null,
      phase: null,
      module: null,
      updatedAt: null
    };
  }

  /**
   * Register a listener for every published event.
   * @param {(event: object) => void} listener
   * @returns {() => boolean} unsubscribe
   */
  subscribe(listener) {
    this.clients.add(listener);
    return () => this.clients.delete(listener);
  }

  /**
   * Publish one event to every connected stream.
   * @param {object} event event payload; `type` is required, everything else is passed through
   * @returns {object} the stamped event
   */
  publish(event) {
    const record = { ts: nowIso(), ...(event && typeof event === 'object' ? event : { type: String(event) }) };
    this.#trackState(record);
    this.lastEvent = record;
    for (const listener of this.clients) {
      try {
        listener(record);
      } catch {
        // A broken SSE client must never break the assessment that published the event.
      }
    }
    return record;
  }

  /** Derived state for the `hello` frame and `/api/health`. */
  status() {
    return {
      startedAt: this.startedAt,
      engine: { ...this.engine },
      lastEvent: this.lastEvent ? { type: this.lastEvent.type ?? null, ts: this.lastEvent.ts ?? null } : null
    };
  }

  #trackState(event) {
    const engine = this.engine;
    switch (event?.type) {
      case 'run:start':
        engine.running = true;
        engine.runId = event.runId ?? null;
        engine.engagementId = event.engagementId ?? engine.engagementId;
        engine.phase = null;
        engine.module = null;
        break;
      case 'module:start':
        engine.running = true;
        engine.runId = event.runId ?? engine.runId;
        engine.engagementId = event.engagementId ?? engine.engagementId;
        engine.phase = event.phase ?? engine.phase;
        engine.module = event.module?.id ?? null;
        break;
      case 'module:done':
        engine.module = null;
        break;
      case 'run:done':
        engine.running = false;
        engine.runId = event.runId ?? engine.runId;
        engine.engagementId = event.engagementId ?? engine.engagementId;
        engine.phase = null;
        engine.module = null;
        break;
      case 'engine:state':
        engine.running = Boolean(event.running);
        engine.runId = event.runId ?? null;
        engine.engagementId = event.engagementId ?? null;
        engine.phase = event.phase ?? null;
        engine.module = event.module ?? null;
        break;
      default:
        return;
    }
    engine.updatedAt = event.ts;
  }
}

/**
 * Does this event belong to the engagement a stream filtered on?
 * Engine events are forwarded as-is; the CLI is expected to stamp `engagementId` on them. Events
 * without any engagement identity are treated as server-global and are forwarded to everyone.
 * @param {object} event
 * @param {string|null} filter
 */
export function eventMatchesEngagement(event, filter) {
  if (!filter) return true;
  const candidates = [event?.engagementId, event?.run?.engagementId, event?.engagement?.id];
  for (const candidate of candidates) {
    if (candidate != null) return String(candidate) === filter;
  }
  return true;
}

/**
 * Long-lived SSE response handler. Writes `hello`, forwards bus events, heartbeats, and cleans up
 * every timer and subscription when the client goes away.
 *
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {{bus: EventBus, url: URL, logger?: object}} opts
 */
export function handleEvents(req, res, { bus, url, logger = null }) {
  if (req.method !== 'GET') {
    res.writeHead(405, { Allow: 'GET', 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'Method not allowed', code: 'method.not_allowed' }));
    return;
  }

  const filter = url.searchParams.get('engagementId');
  const busInstance = bus instanceof EventBus ? bus : new EventBus();
  let heartbeat = null;
  let unsubscribe = () => {};
  let cleaned = false;

  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    if (heartbeat) clearInterval(heartbeat);
    heartbeat = null;
    unsubscribe();
    if (!res.writableEnded) {
      try {
        res.end();
      } catch {
        // The socket may already be gone; nothing left to release.
      }
    }
  };

  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-store, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.write('retry: 3000\n\n');

  const write = (type, data) => {
    if (cleaned || res.writableEnded) return;
    const name = String(type).replace(EVENT_NAME_RE, '_');
    try {
      res.write(`event: ${name}\ndata: ${JSON.stringify(data)}\n\n`);
    } catch {
      cleanup();
    }
  };

  write('hello', {
    ts: nowIso(),
    engagementId: filter,
    server: busInstance.status()
  });

  unsubscribe = busInstance.subscribe((event) => {
    if (filter && !eventMatchesEngagement(event, filter)) return;
    write(event?.type ?? 'message', event);
  });

  heartbeat = setInterval(() => {
    if (cleaned || res.writableEnded) {
      cleanup();
      return;
    }
    try {
      res.write(`: heartbeat ${nowIso()}\n\n`);
    } catch {
      cleanup();
    }
  }, HEARTBEAT_MS);
  heartbeat.unref?.();

  req.on('close', cleanup);
  res.on('close', cleanup);
  res.on('error', cleanup);
  logger?.debug?.(`sse client connected${filter ? ` (engagement ${filter})` : ''}`);
}
