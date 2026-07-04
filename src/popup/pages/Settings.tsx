import { useState, useEffect } from 'react'
import type { ExtensionSettings, EngineWeightConfig } from '../../shared/types/settings'
import { DEFAULT_SETTINGS } from '../../shared/types/settings'
import { DEFAULT_ENGINE_WEIGHTS } from '../../shared/types/engines'

interface EngineStatus {
  id: string
  name: string
  enabled: boolean
  weight: number
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<ExtensionSettings>(DEFAULT_SETTINGS)
  const [engines, setEngines] = useState<EngineStatus[]>([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      const [settingsRes, enginesRes] = await Promise.all([
        chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }),
        chrome.runtime.sendMessage({ type: 'GET_ENGINE_STATUS' })
      ])
      if (settingsRes.success) setSettings(settingsRes.data)
      if (enginesRes.success) setEngines(enginesRes.data)
    } catch {
      // Use defaults
    } finally {
      setLoading(false)
    }
  }

  const saveSettings = async (updates: Partial<ExtensionSettings>) => {
    setSaving(true)
    setMessage('')
    try {
      await chrome.runtime.sendMessage({
        type: 'UPDATE_SETTINGS',
        payload: { settings: updates }
      })
      setSettings(prev => ({ ...prev, ...updates }))
      setMessage('Settings saved')
      setTimeout(() => setMessage(''), 2000)
    } catch {
      setMessage('Failed to save')
    } finally {
      setSaving(false)
    }
  }

  const toggleEngine = async (id: string, enabled: boolean) => {
    try {
      await chrome.runtime.sendMessage({
        type: 'SET_ENGINE_STATE',
        payload: { id, enabled }
      })
      setEngines(prev =>
        prev.map(e => e.id === id ? { ...e, enabled } : e)
      )
    } catch {
      console.error('Failed to toggle engine')
    }
  }

  const clearCache = async () => {
    try {
      await chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' })
      setMessage('Cache cleared')
      setTimeout(() => setMessage(''), 2000)
    } catch {
      setMessage('Failed to clear cache')
    }
  }

  const resetSettings = async () => {
    try {
      await chrome.runtime.sendMessage({ type: 'RESET_SETTINGS' })
      setSettings(DEFAULT_SETTINGS)
      setMessage('Settings reset')
      setTimeout(() => setMessage(''), 2000)
    } catch {
      setMessage('Failed to reset')
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[500px]">
        <div className="w-8 h-8 border-3 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <div className="flex flex-col min-h-[500px]">
      <div className="px-4 py-3 border-b border-[var(--border)] flex items-center gap-3">
        <a href="#/" className="text-blue-500 hover:underline text-sm">← Back</a>
        <h1 className="text-base font-semibold text-[var(--text-primary)]">Settings</h1>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
        {message && (
          <div className="px-3 py-2 bg-green-50 text-green-700 text-sm rounded-lg dark:bg-green-900/30 dark:text-green-400">
            {message}
          </div>
        )}

        <section>
          <h2 className="text-xs font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2">
            General
          </h2>
          <div className="bg-[var(--bg-secondary)] rounded-xl p-4 space-y-3">
            <ToggleRow
              label="Auto-scan pages"
              description="Automatically analyze every page you visit"
              checked={settings.general.autoScan}
              onChange={v => saveSettings({ general: { ...settings.general, autoScan: v } })}
            />
            <ToggleRow
              label="Show badge icon"
              description="Display risk level on extension icon"
              checked={settings.general.showBadge}
              onChange={v => saveSettings({ general: { ...settings.general, showBadge: v } })}
            />
            <ToggleRow
              label="Show notifications"
              description="Display warning notifications for threats"
              checked={settings.general.showNotifications}
              onChange={v => saveSettings({ general: { ...settings.general, showNotifications: v } })}
            />
          </div>
        </section>

        <section>
          <h2 className="text-xs font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2">
            Detection Engines
          </h2>
          <div className="bg-[var(--bg-secondary)] rounded-xl p-4 space-y-2">
            {engines.map(engine => (
              <div key={engine.id} className="flex items-center justify-between py-1">
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-[var(--text-primary)]">{engine.name}</div>
                  <div className="text-xs text-[var(--text-tertiary)]">Weight: {engine.weight}</div>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    className="sr-only peer"
                    checked={engine.enabled}
                    onChange={e => toggleEngine(engine.id, e.target.checked)}
                  />
                  <div className="w-9 h-5 bg-gray-300 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-500" />
                </label>
              </div>
            ))}
          </div>
        </section>

        <section>
          <h2 className="text-xs font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2">
            Privacy
          </h2>
          <div className="bg-[var(--bg-secondary)] rounded-xl p-4 space-y-3">
            <ToggleRow
              label="Anonymous statistics"
              description="Help improve detection by sending anonymous usage data"
              checked={settings.privacy.sendAnonymousStats}
              onChange={v => saveSettings({ privacy: { ...settings.privacy, sendAnonymousStats: v } })}
            />
            <ToggleRow
              label="Enable phishing feeds"
              description="Check URLs against known phishing databases"
              checked={settings.privacy.enableFeeds}
              onChange={v => saveSettings({ privacy: { ...settings.privacy, enableFeeds: v } })}
            />
            <ToggleRow
              label="Cache results"
              description="Cache analysis results for faster repeat visits"
              checked={settings.privacy.cacheResults}
              onChange={v => saveSettings({ privacy: { ...settings.privacy, cacheResults: v } })}
            />
          </div>
        </section>

        <section>
          <h2 className="text-xs font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2">
            Appearance
          </h2>
          <div className="bg-[var(--bg-secondary)] rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm text-[var(--text-primary)]">Theme</div>
                <div className="text-xs text-[var(--text-tertiary)]">Choose color scheme</div>
              </div>
              <select
                value={settings.appearance.theme}
                onChange={e => saveSettings({
                  appearance: { ...settings.appearance, theme: e.target.value as 'light' | 'dark' | 'system' }
                })}
                className="text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] rounded-lg px-2 py-1 text-[var(--text-primary)]"
              >
                <option value="light">Light</option>
                <option value="dark">Dark</option>
                <option value="system">System</option>
              </select>
            </div>
          </div>
        </section>

        <section>
          <h2 className="text-xs font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2">
            Maintenance
          </h2>
          <div className="bg-[var(--bg-secondary)] rounded-xl p-4 space-y-2">
            <button
              onClick={clearCache}
              className="w-full text-left px-3 py-2 text-sm bg-[var(--bg-primary)] rounded-lg hover:bg-[var(--bg-tertiary)] transition-colors"
            >
              Clear Cache
            </button>
            <button
              onClick={resetSettings}
              className="w-full text-left px-3 py-2 text-sm bg-[var(--bg-primary)] rounded-lg hover:bg-[var(--bg-tertiary)] transition-colors text-red-500"
            >
              Reset All Settings
            </button>
          </div>
        </section>
      </div>
    </div>
  )
}

function ToggleRow({
  label,
  description,
  checked,
  onChange
}: {
  label: string
  description: string
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex-1 min-w-0">
        <div className="text-sm text-[var(--text-primary)]">{label}</div>
        <div className="text-xs text-[var(--text-tertiary)]">{description}</div>
      </div>
      <label className="relative inline-flex items-center cursor-pointer ml-3">
        <input
          type="checkbox"
          className="sr-only peer"
          checked={checked}
          onChange={e => onChange(e.target.checked)}
        />
        <div className="w-9 h-5 bg-gray-300 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-500" />
      </label>
    </div>
  )
}
