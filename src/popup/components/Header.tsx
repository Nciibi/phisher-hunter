import { EXTENSION_NAME } from '../../shared/constants'

interface HeaderProps {
  domain: string
  favIcon?: string
}

export default function Header({ domain, favIcon }: HeaderProps) {
  const displayDomain = domain.replace(/^https?:\/\//, '').slice(0, 35)

  return (
    <div className="flex items-center gap-3 px-4 py-3 border-b border-[var(--border)] bg-[var(--bg-secondary)]">
      {favIcon ? (
        <img src={favIcon} alt="" className="w-5 h-5 rounded" />
      ) : (
        <div className="w-5 h-5 rounded bg-blue-500 flex items-center justify-center text-white text-xs font-bold">
          S
        </div>
      )}
      <div className="flex-1 min-w-0">
        <div className="text-xs font-medium text-[var(--text-primary)] truncate">
          {EXTENSION_NAME}
        </div>
        <div className="text-xs text-[var(--text-tertiary)] truncate">
          {displayDomain}
        </div>
      </div>
      <a
        href="#/settings"
        className="w-8 h-8 flex items-center justify-center rounded-full hover:bg-[var(--bg-tertiary)] transition-colors"
        title="Settings"
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="3" />
          <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
        </svg>
      </a>
    </div>
  )
}
