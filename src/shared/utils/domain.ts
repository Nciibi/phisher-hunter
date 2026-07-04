import { BRAND_DOMAINS, HOMOGLITCH_CHARACTERS } from '../constants'

export interface TyposquatResult {
  isSuspicious: boolean
  matchedBrand: string | null
  matchedDomain: string | null
  similarity: number
  type: TyposquatType | null
}

export type TyposquatType =
  | 'homograph'
  | 'misspelling'
  | 'subdomain_trick'
  | 'tld_substitution'
  | 'extra_domain'
  | 'typo'
  | 'insertion'
  | 'deletion'
  | 'repetition'
  | 'replacement'

export function detectTyposquatting(hostname: string): TyposquatResult {
  const normalizedHostname = hostname.toLowerCase().replace(/^www\./, '')
  const allBrandDomains = Object.values(BRAND_DOMAINS).flat()
  const mainDomain = normalizedHostname.split('.')[0]
  const brandNames = Object.keys(BRAND_DOMAINS)
  const brandDomainNames = allBrandDomains.map(d => d.split('.')[0])

  for (const domain of allBrandDomains) {
    const brand = getBrandForDomainName(domain, BRAND_DOMAINS)
    const domainMain = domain.split('.')[0].toLowerCase()

    if (normalizedHostname === domain) {
      return {
        isSuspicious: false,
        matchedBrand: brand,
        matchedDomain: domain,
        similarity: 1,
        type: null
      }
    }

    const tldSubstitution = checkTLDSubstitution(normalizedHostname, domain)
    if (tldSubstitution) {
      return {
        isSuspicious: true,
        matchedBrand: brand,
        matchedDomain: domain,
        similarity: 0.9,
        type: 'tld_substitution'
      }
    }

    const subdomainTrick = checkSubdomainTrick(normalizedHostname, domain)
    if (subdomainTrick) {
      return {
        isSuspicious: true,
        matchedBrand: brand,
        matchedDomain: domain,
        similarity: 0.85,
        type: 'subdomain_trick'
      }
    }

    const isHomograph = detectHomographAttack(mainDomain, domainMain)
    if (isHomograph && mainDomain !== domainMain) {
      return {
        isSuspicious: true,
        matchedBrand: brand,
        matchedDomain: domain,
        similarity: 0.8,
        type: 'homograph'
      }
    }

    const levDistance = levenshteinDistance(mainDomain, domainMain)
    if (levDistance === 1 && mainDomain !== domainMain) {
      return {
        isSuspicious: true,
        matchedBrand: brand,
        matchedDomain: domain,
        similarity: 0.75,
        type: 'typo'
      }
    }
    if (levDistance === 2 && mainDomain !== domainMain) {
      return {
        isSuspicious: true,
        matchedBrand: brand,
        matchedDomain: domain,
        similarity: 0.6,
        type: 'misspelling'
      }
    }

    if (mainDomain.includes(domainMain) && mainDomain !== domainMain) {
      return {
        isSuspicious: true,
        matchedBrand: brand,
        matchedDomain: domain,
        similarity: 0.7,
        type: 'extra_domain'
      }
    }

    for (const brandName of brandNames) {
      const levBrand = levenshteinDistance(mainDomain, brandName)
      if (levBrand <= 1 && mainDomain !== brandName) {
        return {
          isSuspicious: true,
          matchedBrand: brandName,
          matchedDomain: domain,
          similarity: 0.7,
          type: 'typo'
        }
      }
    }
  }

  return {
    isSuspicious: false,
    matchedBrand: null,
    matchedDomain: null,
    similarity: 0,
    type: null
  }
}

function getBrandForDomainName(
  domain: string,
  brandMap: Record<string, string[]>
): string | null {
  for (const [brand, domains] of Object.entries(brandMap)) {
    if (domains.includes(domain)) return brand
  }
  return null
}

function checkTLDSubstitution(
  hostname: string,
  brandDomain: string
): boolean {
  const hostParts = hostname.split('.')
  const brandParts = brandDomain.split('.')
  if (hostParts.length !== brandParts.length) return false
  const hostMain = hostParts[0]
  const brandMain = brandParts[0]
  const hostTld = hostParts.slice(1).join('.')
  const brandTld = brandParts.slice(1).join('.')
  return hostMain === brandMain && hostTld !== brandTld
}

function checkSubdomainTrick(
  hostname: string,
  brandDomain: string
): boolean {
  const dotCount = (hostname.match(/\./g) || []).length
  if (dotCount < 2) return false
  const brandMainDomain = brandDomain.split('.')[0]
  const parts = hostname.split('.')
  const mainPart = parts[parts.length - 2]
  const secureParts = parts.slice(0, -2)

  if (secureParts.some(p => p.toLowerCase() === brandMainDomain.toLowerCase())) {
    return true
  }

  if (mainPart === brandMainDomain && secureParts.length > 0) {
    return true
  }

  return false
}

export function detectHomographAttack(
  input: string,
  target: string
): boolean {
  if (input === target) return false
  if (input.length !== target.length) return false
  let diffCount = 0
  for (let i = 0; i < input.length; i++) {
    if (input[i] !== target[i]) {
      if (HOMOGLITCH_CHARACTERS.has(input[i]) || HOMOGLITCH_CHARACTERS.has(target[i])) {
        diffCount++
      } else {
        return false
      }
    }
  }
  return diffCount > 0 && diffCount <= 2
}

export function detectHomographInString(input: string): boolean {
  for (const char of input) {
    if (HOMOGLITCH_CHARACTERS.has(char)) return true
  }
  return false
}

export function levenshteinDistance(a: string, b: string): number {
  const an = a.length
  const bn = b.length
  const matrix: number[][] = []
  for (let i = 0; i <= an; i++) {
    matrix[i] = [i]
  }
  for (let j = 0; j <= bn; j++) {
    matrix[0][j] = j
  }
  for (let i = 1; i <= an; i++) {
    for (let j = 1; j <= bn; j++) {
      if (a[i - 1] === b[j - 1]) {
        matrix[i][j] = matrix[i - 1][j - 1]
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        )
      }
    }
  }
  return matrix[an][bn]
}

export function computeStringSimilarity(a: string, b: string): number {
  const distance = levenshteinDistance(a, b)
  const maxLen = Math.max(a.length, b.length)
  if (maxLen === 0) return 1
  return 1 - distance / maxLen
}

export function extractBrandKeywords(text: string): string[] {
  const found: string[] = []
  const brandNames = Object.keys(BRAND_DOMAINS)
  const normalizedText = text.toLowerCase()
  for (const brand of brandNames) {
    if (normalizedText.includes(brand.replace(/_/g, ''))) {
      found.push(brand.replace(/_/g, ' '))
    }
  }
  return found
}
