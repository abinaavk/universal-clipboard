// In-memory fixed-window rate limiter. Single-process only (matches the single-file store).
export function createLimiter(enabled = true) {
  const hits = new Map();
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
  }, 60_000);
  sweep.unref?.();

  return {
    /** Count one hit. Returns 0 if allowed, otherwise the seconds until the window resets. */
    hit(key, max, windowMs) {
      if (!enabled) return 0;
      const now = Date.now();
      let e = hits.get(key);
      if (!e || e.reset <= now) hits.set(key, (e = { n: 0, reset: now + windowMs }));
      e.n++;
      return e.n > max ? Math.ceil((e.reset - now) / 1000) : 0;
    },
    /** Forget a key (e.g. after a successful login). */
    clear: (key) => hits.delete(key),
    stop: () => clearInterval(sweep),
  };
}
