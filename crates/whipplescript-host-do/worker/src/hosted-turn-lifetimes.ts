/** Only this live Durable Object isolate can distinguish its drives from orphans. */
export class HostedTurnLifetimes {
  private readonly active = new Map<string, number>();

  async drive<T>(key: string, operation: () => Promise<T>): Promise<T> {
    this.active.set(key, (this.active.get(key) ?? 0) + 1);
    try {
      return await operation();
    } finally {
      const count = (this.active.get(key) ?? 1) - 1;
      if (count > 0) this.active.set(key, count);
      else this.active.delete(key);
    }
  }

  recoverIfIdle(key: string, operation: () => boolean): boolean {
    // Synchronous check + settlement: no await may admit a drive between them.
    return this.active.has(key) ? false : operation();
  }
}
