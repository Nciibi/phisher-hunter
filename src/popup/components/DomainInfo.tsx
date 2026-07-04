import { getTLD } from '../../shared/utils/url'
import { isSuspiciousTLD } from '../../shared/utils/url'

interface DomainInfoProps {
  domain: string
}

export default function DomainInfo({ domain }: DomainInfoProps) {
  const tld = getTLD(domain)
  const isSuspicious = isSuspiciousTLD(tld)
  const parts = domain.split('.')

  return (
    <div className="bg-[var(--bg-secondary)] rounded-xl p-4">
      <div className="text-xs font-semibold text-[var(--text-tertiary)] uppercase tracking-wider mb-2">
        Domain Information
      </div>
      <div className="space-y-1.5">
        <div className="flex justify-between items-center text-sm">
          <span className="text-[var(--text-secondary)]">Domain</span>
          <span className="text-[var(--text-primary)] font-mono text-xs">{domain}</span>
        </div>
        <div className="flex justify-between items-center text-sm">
          <span className="text-[var(--text-secondary)]">TLD</span>
          <span className={`font-mono text-xs ${isSuspicious ? 'text-red-500 font-semibold' : 'text-[var(--text-primary)]'}`}>
            {tld}{isSuspicious ? ' ⚠️' : ''}
          </span>
        </div>
        <div className="flex justify-between items-center text-sm">
          <span className="text-[var(--text-secondary)]">Subdomains</span>
          <span className="text-[var(--text-primary)] text-xs">{parts.length - 2 > 0 ? parts.length - 2 : 'None'}</span>
        </div>
        <div className="flex justify-between items-center text-sm">
          <span className="text-[var(--text-secondary)]">Parts</span>
          <span className="text-[var(--text-primary)] text-xs">{parts.length}</span>
        </div>
      </div>
    </div>
  )
}
