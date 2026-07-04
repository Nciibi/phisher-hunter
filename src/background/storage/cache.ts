import { STORAGE_KEYS, CACHE_DEFAULTS } from '../../shared/constants'

interface CacheEntry<T> {
  data: T
  expiresAt: number
  createdAt: number
}

export class AnalysisCache {
  private cache: Map<string, CacheEntry<unknown>> = new Map()
  private maxSize: number = CACHE_DEFAULTS.MAX_SIZE
  private defaultTtl: number = CACHE_DEFAULTS.ANALYSIS_TTL

  constructor() {
    this.loadFromStorage()
  }

  get<T>(key: string): T | null {
    const entry = this.cache.get(key)
    if (!entry) return null

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key)
      return null
    }

    return entry.data as T
  }

  set<T>(key: string, data: T, ttl?: number): void {
    if (this.cache.size >= this.maxSize) {
      this.evictOldest()
    }

    this.cache.set(key, {
      data,
      expiresAt: Date.now() + (ttl ?? this.defaultTtl),
      createdAt: Date.now()
    })

    if (this.cache.size % 100 === 0) {
      this.persistToStorage()
    }
  }

  has(key: string): boolean {
    const entry = this.cache.get(key)
    if (!entry) return false
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key)
      return false
    }
    return true
  }

  delete(key: string): boolean {
    return this.cache.delete(key)
  }

  clear(): void {
    this.cache.clear()
    this.persistToStorage()
  }

  get size(): number {
    return this.cache.size
  }

  get entries(): number {
    return this.cache.size
  }

  private evictOldest(): void {
    let oldestKey: string | null = null
    let oldestTime = Infinity

    for (const [key, entry] of this.cache.entries()) {
      if (entry.createdAt < oldestTime) {
        oldestTime = entry.createdAt
        oldestKey = key
      }
    }

    if (oldestKey) {
      this.cache.delete(oldestKey)
    }
  }

  private async loadFromStorage(): Promise<void> {
    try {
      const result = await chrome.storage.local.get(STORAGE_KEYS.CACHE)
      const cached = result[STORAGE_KEYS.CACHE] as Record<string, CacheEntry<unknown>> | undefined
      if (cached) {
        const now = Date.now()
        for (const [key, entry] of Object.entries(cached)) {
          if (entry.expiresAt > now) {
            this.cache.set(key, entry)
          }
        }
      }
    } catch {
      // Storage unavailable - continue with in-memory cache
    }
  }

  private async persistToStorage(): Promise<void> {
    try {
      const serializable: Record<string, CacheEntry<unknown>> = {}
      const entries = Array.from(this.cache.entries()).slice(0, 1000)
      for (const [key, entry] of entries) {
        serializable[key] = entry
      }
      await chrome.storage.local.set({ [STORAGE_KEYS.CACHE]: serializable })
    } catch {
      // Storage quota exceeded or unavailable
    }
  }

  getStats(): { size: number; maxSize: number; utilization: number } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      utilization: this.cache.size / this.maxSize
    }
  }
}
