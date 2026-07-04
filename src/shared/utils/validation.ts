export function sanitizeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
}

export function sanitizeUrl(input: string): string {
  const url = input.trim()
  const allowedProtocols = ['http:', 'https:', 'ftp:', 'mailto:', 'tel:']
  try {
    const parsed = new URL(url)
    if (!allowedProtocols.includes(parsed.protocol)) return ''
    return url
  } catch {
    return ''
  }
}

export function sanitizeForStorage<T>(data: T): T {
  if (typeof data === 'string') {
    return data.slice(0, 10000) as T
  }
  if (typeof data === 'object' && data !== null) {
    const sanitized: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
      if (typeof value === 'string') {
        sanitized[key] = value.slice(0, 10000)
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = sanitizeForStorage(value)
      } else {
        sanitized[key] = value
      }
    }
    return sanitized as T
  }
  return data
}

export function validateEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

export function validateDomain(domain: string): boolean {
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/
  return domainRegex.test(domain)
}

export function isProbablyMaliciousScript(scriptContent: string): boolean {
  const maliciousPatterns = [
    /document\.write\(.+\)/i,
    /eval\(.+\)/i,
    /atob\(.+\)/i,
    /String\.fromCharCode\(.+\)/i,
    /\\x[0-9a-fA-F]{2}/,
    /base64/gi,
    /escape\(/i,
    /unescape\(/i,
    /fromCharCode\(/i,
    /charCodeAt\(/i,
    /\\u[0-9a-fA-F]{4}/,
    /['"]\s*\+\s*['"]/g
  ]
  return maliciousPatterns.some(pattern => pattern.test(scriptContent))
}

export function truncateString(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str
  return str.slice(0, maxLength - 3) + '...'
}

export function isValidJson(str: string): boolean {
  try {
    JSON.parse(str)
    return true
  } catch {
    return false
  }
}

export function deepFreeze<T>(obj: T): T {
  if (typeof obj !== 'object' || obj === null) return obj
  const propNames = Object.getOwnPropertyNames(obj)
  for (const name of propNames) {
    const value = (obj as Record<string, unknown>)[name]
    ;(obj as Record<string, unknown>)[name] = value
  }
  return Object.freeze(obj)
}
