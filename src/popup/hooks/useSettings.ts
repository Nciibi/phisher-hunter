import { useState, useEffect, useCallback } from 'react'
import type { ExtensionSettings } from '../../shared/types/settings'
import { DEFAULT_SETTINGS } from '../../shared/types/settings'

export function useSettings() {
  const [settings, setSettings] = useState<ExtensionSettings>(DEFAULT_SETTINGS)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadSettings()
  }, [])

  const loadSettings = async () => {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' })
      if (response.success && response.data) {
        setSettings(response.data)
      }
    } catch {
      // Use defaults
    } finally {
      setLoading(false)
    }
  }

  const updateSettings = useCallback(async (updates: Partial<ExtensionSettings>) => {
    try {
      await chrome.runtime.sendMessage({
        type: 'UPDATE_SETTINGS',
        payload: { settings: updates }
      })
      setSettings(prev => ({ ...prev, ...updates }))
    } catch (err) {
      console.error('Failed to update settings:', err)
    }
  }, [])

  return { settings, loading, updateSettings, refresh: loadSettings }
}
