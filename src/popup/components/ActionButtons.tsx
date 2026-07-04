import { useState } from 'react'

interface ActionButtonsProps {
  url: string
  domain: string
  isWhitelisted: boolean
  isBlacklisted: boolean
  onRefresh: () => void
}

export default function ActionButtons({ url, domain, isWhitelisted, isBlacklisted, onRefresh }: ActionButtonsProps) {
  const [whitelisted, setWhitelisted] = useState(isWhitelisted)
  const [showReport, setShowReport] = useState(false)
  const [reportSent, setReportSent] = useState(false)

  const handleWhitelist = async () => {
    try {
      if (whitelisted) {
        await chrome.runtime.sendMessage({
          type: 'REMOVE_WHITELIST',
          payload: domain
        })
        setWhitelisted(false)
      } else {
        await chrome.runtime.sendMessage({
          type: 'ADD_WHITELIST',
          payload: {
            entry: { domain, addedAt: Date.now(), reason: 'User whitelisted' }
          }
        })
        setWhitelisted(true)
      }
    } catch {
      console.error('Failed to update whitelist')
    }
  }

  const handleReport = async () => {
    setShowReport(true)
    try {
      await chrome.runtime.sendMessage({
        type: 'REPORT_PHISHING',
        payload: { url, source: 'popup' }
      })
      setReportSent(true)
    } catch {
      console.error('Failed to report')
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <button
          onClick={onRefresh}
          className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-medium rounded-lg bg-[var(--bg-tertiary)] text-[var(--text-primary)] hover:opacity-80 transition-opacity"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="23 4 23 10 17 10" />
            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
          </svg>
          Re-scan
        </button>
        <button
          onClick={handleWhitelist}
          className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
            whitelisted
              ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300'
              : 'bg-[var(--bg-tertiary)] text-[var(--text-primary)] hover:opacity-80'
          }`}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          {whitelisted ? 'Trusted' : 'Trust'}
        </button>
      </div>

      <div className="flex gap-2">
        <button
          onClick={handleReport}
          className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-medium rounded-lg bg-red-50 text-red-600 hover:bg-red-100 transition-colors dark:bg-red-900/30 dark:text-red-400"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
          {reportSent ? 'Reported ✓' : 'Report'}
        </button>
        <a
          href="#/whitelist"
          className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-sm font-medium rounded-lg bg-[var(--bg-tertiary)] text-[var(--text-primary)] hover:opacity-80 transition-opacity no-underline"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
          </svg>
          Manage
        </a>
      </div>
    </div>
  )
}
