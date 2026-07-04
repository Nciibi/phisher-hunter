import { SUSPICIOUS_TLDS, HIGH_RISK_TLDS } from '../constants'
import { BRAND_DOMAINS } from '../constants'

export function parseUrl(url: string): URL {
  let sanitized = url.trim()
  if (!sanitized.startsWith('http://') && !sanitized.startsWith('https://')) {
    sanitized = 'https://' + sanitized
  }
  return new URL(sanitized)
}

export function getDomain(url: string): string {
  try {
    const parsed = parseUrl(url)
    return parsed.hostname.toLowerCase()
  } catch {
    return url.toLowerCase()
  }
}

export function getHostname(url: string): string {
  try {
    const parsed = parseUrl(url)
    return parsed.hostname.toLowerCase()
  } catch {
    return ''
  }
}

export function getTLD(hostname: string): string {
  const parts = hostname.split('.')
  if (parts.length < 2) return ''
  const possibleTlds: string[] = []
  for (let i = parts.length - 1; i > 0; i--) {
    possibleTlds.push('.' + parts.slice(i).join('.'))
  }
  const knownPublicSuffixes = [
    '.co.uk', '.org.uk', '.ac.uk', '.gov.uk', '.net.uk',
    '.com.au', '.net.au', '.org.au', '.edu.au', '.gov.au',
    '.co.jp', '.ne.jp', '.or.jp', '.co.kr', '.or.kr',
    '.com.br', '.org.br', '.net.br', '.gov.br',
    '.com.cn', '.net.cn', '.org.cn', '.gov.cn',
    '.co.in', '.net.in', '.org.in', '.gen.in',
    '.com.mx', '.org.mx', '.net.mx',
    '.co.za', '.org.za', '.net.za', '.web.za',
    '.com.ar', '.net.ar', '.org.ar', '.gov.ar',
    '.com.tr', '.net.tr', '.org.tr', '.gov.tr'
  ]
  for (const suffix of knownPublicSuffixes) {
    if (hostname.endsWith(suffix)) return suffix
  }
  return '.' + parts[parts.length - 1]
}

export function getSubdomains(hostname: string): string[] {
  const parts = hostname.split('.')
  if (parts.length <= 2) return []
  return parts.slice(0, parts.length - 2)
}

export function getDomainWithoutTLD(hostname: string): string {
  const tld = getTLD(hostname)
  return hostname.slice(0, -tld.length)
}

export function getRegistrableDomain(hostname: string): string {
  const tld = getTLD(hostname)
  const withoutTld = hostname.slice(0, -tld.length)
  const parts = withoutTld.split('.')
  return parts[parts.length - 1] + tld
}

export function isSuspiciousTLD(tld: string): boolean {
  return SUSPICIOUS_TLDS.has(tld.toLowerCase()) || HIGH_RISK_TLDS.has(tld.toLowerCase())
}

export function isHighRiskTLD(tld: string): boolean {
  return HIGH_RISK_TLDS.has(tld.toLowerCase())
}

export function countDots(url: string): number {
  return (url.match(/\./g) || []).length
}

export function countHyphens(hostname: string): number {
  return (hostname.match(/-/g) || []).length
}

export function countDigits(hostname: string): number {
  return (hostname.match(/\d/g) || []).length
}

export function countSpecialChars(hostname: string): number {
  return (hostname.match(/[^a-zA-Z0-9.-]/g) || []).length
}

export function getPathDepth(url: string): number {
  try {
    const parsed = parseUrl(url)
    return parsed.pathname.split('/').filter(Boolean).length
  } catch {
    return 0
  }
}

export function hasIpAddress(hostname: string): boolean {
  const ipv4Pattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
  const ipv6Pattern = /^[0-9a-fA-F:]+$/
  return ipv4Pattern.test(hostname) || ipv6Pattern.test(hostname)
}

export function getBrandForDomain(hostname: string): string | null {
  for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
    for (const domain of domains) {
      if (hostname === domain || hostname.endsWith('.' + domain)) {
        return brand
      }
    }
  }
  return null
}

export function isKnownBrandDomain(hostname: string): string | null {
  for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
    for (const domain of domains) {
      const mainDomain = domain.split('.')[0]
      const hostnameParts = hostname.split('.')
      if (hostnameParts.length >= 2) {
        const hostMainDomain = hostnameParts[hostnameParts.length - 2]
        if (hostMainDomain.toLowerCase() === mainDomain.toLowerCase()) {
          const ourTld = '.' + hostnameParts[hostnameParts.length - 1]
          const brandTld = '.' + domain.split('.').slice(1).join('.')
          if (ourTld === brandTld) {
            return brand
          }
        }
      }
    }
  }
  return null
}

export function normalizeUrl(url: string): string {
  try {
    const parsed = parseUrl(url)
    return parsed.origin + parsed.pathname.replace(/\/$/, '') + parsed.search
  } catch {
    return url
  }
}

export function isValidUrl(url: string): boolean {
  try {
    new URL(url)
    return true
  } catch {
    return false
  }
}

export function extractQueryParams(url: string): Record<string, string> {
  try {
    const parsed = parseUrl(url)
    const params: Record<string, string> = {}
    parsed.searchParams.forEach((value, key) => {
      params[key] = value
    })
    return params
  } catch {
    return {}
  }
}
