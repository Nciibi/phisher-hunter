import { useState, useEffect } from 'react'
import type { WhitelistEntry, BlacklistEntry } from '../../shared/types/settings'

export default function WhitelistPage() {
  const [whitelist, setWhitelist] = useState<WhitelistEntry[]>([])
  const [blacklist, setBlacklist] = useState<BlacklistEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'whitelist' | 'blacklist'>('whitelist')

  useEffect(() => {
    loadLists()
  }, [])

  const loadLists = async () => {
    try {
      const [wResponse, bResponse] = await Promise.all([
        chrome.runtime.sendMessage({ type: 'GET_WHITELIST' }),
        chrome.runtime.sendMessage({ type: 'GET_BLACKLIST' })
      ])
      if (wResponse.success) setWhitelist(wResponse.data || [])
      if (bResponse.success) setBlacklist(bResponse.data || [])
    } catch {
      // Use empty lists
    } finally {
      setLoading(false)
    }
  }

  const removeFromWhitelist = async (domain: string) => {
    try {
      await chrome.runtime.sendMessage({ type: 'REMOVE_WHITELIST', payload: domain })
      setWhitelist(prev => prev.filter(e => e.domain !== domain))
    } catch {
      console.error('Failed to remove from whitelist')
    }
  }

  const removeFromBlacklist = async (domain: string) => {
    try {
      await chrome.runtime.sendMessage({ type: 'REMOVE_BLACKLIST', payload: domain })
      setBlacklist(prev => prev.filter(e => e.domain !== domain))
    } catch {
      console.error('Failed to remove from blacklist')
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[500px]">
        <div className="w-8 h-8 border-3 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  const entries = activeTab === 'whitelist' ? whitelist : blacklist

  return (
    <div className="flex flex-col min-h-[500px]">
      <div className="px-4 py-3 border-b border-[var(--border)] flex items-center gap-3">
        <a href="#/" className="text-blue-500 hover:underline text-sm">← Back</a>
        <h1 className="text-base font-semibold text-[var(--text-primary)]">Manage Lists</h1>
      </div>

      <div className="flex border-b border-[var(--border)]">
        <button
          onClick={() => setActiveTab('whitelist')}
          className={`flex-1 px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === 'whitelist'
              ? 'text-blue-500 border-b-2 border-blue-500'
              : 'text-[var(--text-tertiary)] hover:text-[var(--text-primary)]'
          }`}
        >
          Whitelist ({whitelist.length})
        </button>
        <button
          onClick={() => setActiveTab('blacklist')}
          className={`flex-1 px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === 'blacklist'
              ? 'text-red-500 border-b-2 border-red-500'
              : 'text-[var(--text-tertiary)] hover:text-[var(--text-primary)]'
          }`}
        >
          Blacklist ({blacklist.length})
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3">
        {entries.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <div className="text-4xl mb-3">{activeTab === 'whitelist' ? '🛡️' : '🚫'}</div>
            <p className="text-sm text-[var(--text-secondary)]">
              {activeTab === 'whitelist'
                ? 'No whitelisted domains yet.'
                : 'No blacklisted domains yet.'}
            </p>
            <p className="text-xs text-[var(--text-tertiary)] mt-1">
              {activeTab === 'whitelist'
                ? 'Use "Trust" button on any site to add it here.'
                : 'Report phishing sites to add them here.'}
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {entries.map(entry => (
              <div
                key={entry.domain}
                className="flex items-center justify-between bg-[var(--bg-secondary)] rounded-lg p-3"
              >
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-[var(--text-primary)] truncate">
                    {entry.domain}
                  </div>
                  <div className="text-xs text-[var(--text-tertiary)]">
                    Added {new Date(entry.addedAt).toLocaleDateString()}
                    {entry.reason && ` · ${entry.reason}`}
                  </div>
                </div>
                <button
                  onClick={() =>
                    activeTab === 'whitelist'
                      ? removeFromWhitelist(entry.domain)
                      : removeFromBlacklist(entry.domain)
                  }
                  className="ml-2 px-3 py-1.5 text-xs font-medium rounded-lg bg-red-50 text-red-600 hover:bg-red-100 transition-colors dark:bg-red-900/30 dark:text-red-400"
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
