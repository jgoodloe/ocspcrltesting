/**
 * Live run event stream: WebSocket first, SSE (EventSource) fallback.
 *
 * - Tracks the last received event `seq` and resumes from `after_seq` on
 *   every reconnect.
 * - Reconnects with exponential backoff (500ms .. 10s).
 * - Stops permanently when a `run_status` event carries a terminal status.
 * - The returned function tears everything down (call on unmount).
 */
import { apiUrl, wsUrl } from './base';
import { isTerminalStatus, type StreamEvent } from './api';

export type StreamTransport = 'ws' | 'sse';
export type StreamConnectionState = 'connecting' | 'open' | 'closed' | 'ended';

export interface StreamHandlers {
  onEvent: (event: StreamEvent) => void;
  onStateChange?: (state: StreamConnectionState, transport: StreamTransport) => void;
}

export interface StreamHandle {
  close: () => void;
}

const MAX_BACKOFF_MS = 10_000;
const BASE_BACKOFF_MS = 500;

export function connectRunStream(
  runId: string,
  afterSeq: number,
  handlers: StreamHandlers,
): StreamHandle {
  let lastSeq = afterSeq;
  let stopped = false;
  let attempts = 0;
  let useSse = typeof WebSocket === 'undefined';
  let ws: WebSocket | null = null;
  let es: EventSource | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  const notify = (state: StreamConnectionState) => {
    handlers.onStateChange?.(state, useSse ? 'sse' : 'ws');
  };

  const handleMessage = (raw: string): void => {
    let event: StreamEvent;
    try {
      event = JSON.parse(raw) as StreamEvent;
    } catch {
      return; // ignore malformed frames
    }
    if (typeof event.seq === 'number' && event.seq > lastSeq) {
      lastSeq = event.seq;
    }
    attempts = 0; // healthy stream: reset backoff
    handlers.onEvent(event);
    if (event.type === 'run_status' && isTerminalStatus(event.data.status)) {
      // Terminal run_status is always the last event; stop for good.
      stopped = true;
      teardown();
      notify('ended');
    }
  };

  const teardown = (): void => {
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    if (ws) {
      ws.onmessage = null;
      ws.onopen = null;
      ws.onerror = null;
      ws.onclose = null;
      try {
        ws.close();
      } catch {
        /* already closed */
      }
      ws = null;
    }
    if (es) {
      es.onmessage = null;
      es.onerror = null;
      es.onopen = null;
      es.close();
      es = null;
    }
  };

  const scheduleReconnect = (): void => {
    if (stopped || reconnectTimer !== null) return;
    const delay = Math.min(BASE_BACKOFF_MS * 2 ** attempts, MAX_BACKOFF_MS);
    attempts += 1;
    notify('closed');
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connect();
    }, delay);
  };

  const connectWebSocket = (): void => {
    let opened = false;
    const socket = new WebSocket(
      wsUrl(`/test-runs/${encodeURIComponent(runId)}/stream?after_seq=${lastSeq}`),
    );
    ws = socket;
    socket.onopen = () => {
      opened = true;
      notify('open');
    };
    socket.onmessage = (msg: MessageEvent) => {
      if (typeof msg.data === 'string') handleMessage(msg.data);
    };
    socket.onclose = () => {
      if (stopped) return;
      if (!opened) {
        // Handshake failed (proxy without WS support, auth, etc.) -> SSE.
        useSse = true;
      }
      ws = null;
      scheduleReconnect();
    };
    socket.onerror = () => {
      // onclose always follows onerror; nothing else to do here.
    };
  };

  const connectSse = (): void => {
    const source = new EventSource(
      apiUrl(`/test-runs/${encodeURIComponent(runId)}/stream/sse?after_seq=${lastSeq}`),
    );
    es = source;
    source.onopen = () => notify('open');
    source.onmessage = (msg: MessageEvent) => {
      if (typeof msg.data === 'string') handleMessage(msg.data);
    };
    source.onerror = () => {
      if (stopped) return;
      // Recreate the source ourselves so ?after_seq resumes from lastSeq
      // even when the browser gives up on its built-in retry.
      source.close();
      if (es === source) es = null;
      scheduleReconnect();
    };
  };

  const connect = (): void => {
    if (stopped) return;
    notify('connecting');
    if (useSse) {
      connectSse();
    } else {
      connectWebSocket();
    }
  };

  connect();

  return {
    close: () => {
      stopped = true;
      teardown();
    },
  };
}
