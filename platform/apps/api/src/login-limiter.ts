// Local single-process guard. Replace with a shared atomic store before multi-instance deployment.
export class LoginAttemptLimiter {
  private attempts = new Map<string, { count: number; expires: number }>();
  constructor(private readonly limit = 5, private readonly windowMs = 15 * 60_000, private readonly maxEntries = 20_000) {}
  private entry(key: string, now: number) {
    const value = this.attempts.get(key);
    if (value && value.expires > now) return value;
    this.attempts.delete(key);
    return undefined;
  }
  blocked(keys: string[], now = Date.now()) {
    return keys.some(key => (this.entry(key, now)?.count ?? 0) >= this.limit);
  }
  failed(keys: string[], now = Date.now()) {
    // Prune expired records to bound memory even with many distinct login attempts.
    if (this.attempts.size >= this.maxEntries) {
      for (const [key, value] of this.attempts) if (value.expires <= now) this.attempts.delete(key);
      if (this.attempts.size >= this.maxEntries) this.attempts.delete(this.attempts.keys().next().value!);
    }
    for (const key of keys) {
      const current = this.entry(key, now);
      this.attempts.set(key, { count: (current?.count ?? 0) + 1, expires: current?.expires ?? now + this.windowMs });
    }
  }
  clear(key: string) { this.attempts.delete(key); }
  retryAfterSeconds(keys: string[], now = Date.now()) {
    return Math.max(1, ...keys.map(key => Math.ceil(((this.entry(key, now)?.expires ?? now) - now) / 1000)));
  }
}
