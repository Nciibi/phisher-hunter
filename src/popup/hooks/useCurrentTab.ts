import { useState, useEffect } from 'react'

interface TabInfo {
  url: string
  title: string
  favIconUrl?: string
}

export function useCurrentTab(): TabInfo | null {
  const [tabInfo, setTabInfo] = useState<TabInfo | null>(null)

  useEffect(() => {
    async function getTab() {
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
        if (tab?.url) {
          setTabInfo({
            url: tab.url,
            title: tab.title || '',
            favIconUrl: tab.favIconUrl
          })
        }
      } catch {
        // Not in extension context
      }
    }
    getTab()
  }, [])

  return tabInfo
}
