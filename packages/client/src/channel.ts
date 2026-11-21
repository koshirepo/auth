/** What tabs tell each other. Tokens are never sent: each tab gets its own through the cookie. */
export type ChannelMessage = { type: 'signed-in' } | { type: 'signed-out' };

export interface ChannelLike {
  post(message: ChannelMessage): void;
  /** Registers the listener for messages from other tabs. A tab does not receive its own messages. */
  subscribe(listener: (message: ChannelMessage) => void): void;
  close(): void;
}

function isMessage(value: unknown): value is ChannelMessage {
  const type = (value as { type?: unknown } | null)?.type;
  return type === 'signed-in' || type === 'signed-out';
}

/** A `BroadcastChannel` between same-origin tabs, or null where the API does not exist. */
export function broadcastChannel(name: string): ChannelLike | null {
  if (typeof BroadcastChannel !== 'function') return null;
  const channel = new BroadcastChannel(name);
  // In Node an open channel keeps the process alive. Browsers have no `unref`.
  (channel as unknown as { unref?: () => void }).unref?.();
  return {
    post: (message) => channel.postMessage(message),
    subscribe: (listener) => {
      channel.onmessage = (event: MessageEvent) => {
        if (isMessage(event.data)) listener(event.data);
      };
    },
    close: () => channel.close(),
  };
}
