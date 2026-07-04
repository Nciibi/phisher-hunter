import { STORAGE_KEYS } from '../../shared/constants'
import type { ExtensionSettings, WhitelistEntry, BlacklistEntry } from '../../shared/types/settings'
import { DEFAULT_SETTINGS } from '../../shared/types/settings'

export class SettingsManager {
  private settings: ExtensionSettings = { ...DEFAULT_SETTINGS }
  private whitelist: Map<string, WhitelistEntry> = new Map()
  private blacklist: Map<string, BlacklistEntry> = new Map()
  private initialized = false

  async initialize(): Promise<void> {
    if (this.initialized) return

    try {
      const result = await chrome.storage.local.get([
        STORAGE_KEYS.SETTINGS,
        STORAGE_KEYS.WHITELIST,
        STORAGE_KEYS.BLACKLIST
      ])

      if (result[STORAGE_KEYS.SETTINGS]) {
        this.settings = this.mergeSettings(result[STORAGE_KEYS.SETTINGS])
      }

      if (result[STORAGE_KEYS.WHITELIST]) {
        const entries: WhitelistEntry[] = result[STORAGE_KEYS.WHITELIST]
        for (const entry of entries) {
          this.whitelist.set(entry.domain, entry)
        }
      }

      if (result[STORAGE_KEYS.BLACKLIST]) {
        const entries: BlacklistEntry[] = result[STORAGE_KEYS.BLACKLIST]
        for (const entry of entries) {
          this.blacklist.set(entry.domain, entry)
        }
      }

      this.initialized = true
    } catch (error) {
      console.error('[Seagles Shield] Failed to load settings:', error)
    }
  }

  getSettings(): ExtensionSettings {
    return { ...this.settings }
  }

  async updateSettings(updates: Partial<ExtensionSettings>): Promise<void> {
    this.settings = this.mergeSettings(updates)
    await this.persistSettings()
  }

  async resetSettings(): Promise<void> {
    this.settings = { ...DEFAULT_SETTINGS }
    await this.persistSettings()
  }

  async addToWhitelist(entry: WhitelistEntry): Promise<void> {
    this.whitelist.set(entry.domain, entry)
    await this.persistWhitelist()
  }

  async removeFromWhitelist(domain: string): Promise<void> {
    this.whitelist.delete(domain)
    await this.persistWhitelist()
  }

  isWhitelisted(domain: string): boolean {
    const entry = this.whitelist.get(domain)
    if (!entry) return false
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.whitelist.delete(domain)
      this.persistWhitelist()
      return false
    }
    return true
  }

  getWhitelist(): WhitelistEntry[] {
    return Array.from(this.whitelist.values())
  }

  async addToBlacklist(entry: BlacklistEntry): Promise<void> {
    this.blacklist.set(entry.domain, entry)
    await this.persistBlacklist()
  }

  async removeFromBlacklist(domain: string): Promise<void> {
    this.blacklist.delete(domain)
    await this.persistBlacklist()
  }

  isBlacklisted(domain: string): boolean {
    const entry = this.blacklist.get(domain)
    if (!entry) return false
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.blacklist.delete(domain)
      this.persistBlacklist()
      return false
    }
    return true
  }

  getBlacklist(): BlacklistEntry[] {
    return Array.from(this.blacklist.values())
  }

  private mergeSettings(updates: Partial<ExtensionSettings>): ExtensionSettings {
    return {
      ...this.settings,
      ...updates,
      general: { ...this.settings.general, ...(updates.general || {}) },
      engines: { ...this.settings.engines, ...(updates.engines || {}) },
      appearance: { ...this.settings.appearance, ...(updates.appearance || {}) },
      privacy: { ...this.settings.privacy, ...(updates.privacy || {}) },
      notifications: { ...this.settings.notifications, ...(updates.notifications || {}) },
      advanced: { ...this.settings.advanced, ...(updates.advanced || {}) }
    }
  }

  private async persistSettings(): Promise<void> {
    try {
      await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: this.settings })
    } catch (error) {
      console.error('[Seagles Shield] Failed to save settings:', error)
    }
  }

  private async persistWhitelist(): Promise<void> {
    try {
      await chrome.storage.local.set({
        [STORAGE_KEYS.WHITELIST]: Array.from(this.whitelist.values())
      })
    } catch (error) {
      console.error('[Seagles Shield] Failed to save whitelist:', error)
    }
  }

  private async persistBlacklist(): Promise<void> {
    try {
      await chrome.storage.local.set({
        [STORAGE_KEYS.BLACKLIST]: Array.from(this.blacklist.values())
      })
    } catch (error) {
      console.error('[Seagles Shield] Failed to save blacklist:', error)
    }
  }

  async clearAllData(): Promise<void> {
    this.whitelist.clear()
    this.blacklist.clear()
    this.settings = { ...DEFAULT_SETTINGS }
    try {
      await chrome.storage.local.remove([
        STORAGE_KEYS.SETTINGS,
        STORAGE_KEYS.WHITELIST,
        STORAGE_KEYS.BLACKLIST,
        STORAGE_KEYS.CACHE,
        STORAGE_KEYS.STATS
      ])
    } catch (error) {
      console.error('[Seagles Shield] Failed to clear data:', error)
    }
  }
}
