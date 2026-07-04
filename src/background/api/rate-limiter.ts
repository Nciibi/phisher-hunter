import { API_DEFAULTS } from '../../shared/constants'

interface RateLimitEntry {
  count: number
  windowStart: number
}

export class RateLimiter {
  private limits: Map<string, RateLimitEntry> = new Map()
  private readonly maxConcurrent: number = API_DEFAULTS.MAX_CONCURRENT
  private activeRequests: number = 0
  private queue: Array<() => void> = []

  constructor(
    private readonly maxRequests: number = 60,
    private readonly windowMs: number = 60000
  ) {}

  async acquire(key: string = 'default'): Promise<boolean> {
    const now = Date.now()
    let entry = this.limits.get(key)

    if (!entry || now - entry.windowStart > this.windowMs) {
      entry = { count: 0, windowStart: now }
      this.limits.set(key, entry)
    }

    if (entry.count >= this.maxRequests) {
      return false
    }

    entry.count++

    if (this.activeRequests >= this.maxConcurrent) {
      await new Promise<void>(resolve => {
        this.queue.push(resolve)
      })
    }

    this.activeRequests++
    return true
  }

  release(): void {
    this.activeRequests--
    if (this.queue.length > 0) {
      const next = this.queue.shift()
      next?.()
    }
  }

  async execute<T>(
    key: string,
    fn: () => Promise<T>
  ): Promise<T> {
    const acquired = await this.acquire(key)
    if (!acquired) {
      throw new Error('Rate limit exceeded')
    }

    try {
      return await fn()
    } finally {
      this.release()
    }
  }

  getRemainingRequests(key: string = 'default'): number {
    const entry = this.limits.get(key)
    if (!entry) return this.maxRequests
    if (Date.now() - entry.windowStart > this.windowMs) return this.maxRequests
    return Math.max(0, this.maxRequests - entry.count)
  }

  reset(): void {
    this.limits.clear()
    this.queue = []
    this.activeRequests = 0
  }
}
