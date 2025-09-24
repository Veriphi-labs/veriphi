if (typeof (globalThis as any).self === 'undefined') {
  (globalThis as any).self = globalThis;
}

if (typeof (globalThis as any).addEventListener !== 'function') {
  const listeners = new Map<string, Set<(event: any) => void>>();
  (globalThis as any).addEventListener = (type: string, handler: (event: any) => void) => {
    if (!listeners.has(type)) listeners.set(type, new Set());
    listeners.get(type)!.add(handler);
  };
  (globalThis as any).removeEventListener = (type: string, handler: (event: any) => void) => {
    listeners.get(type)?.delete(handler);
  };
  (globalThis as any).dispatchEvent = (event: { type: string; data?: unknown }) => {
    listeners.get(event.type)?.forEach((handler) => handler({ data: event.data }));
  };
  (globalThis as any).postMessage = (data: unknown) => {
    (globalThis as any).dispatchEvent({ type: 'message', data });
  };
}
