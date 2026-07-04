import type { RiskLevel, EngineResult } from './analysis'

export interface DetectionEngine {
  id: string
  name: string
  description: string
  version: string
  enabled: boolean
  weight: number
  analyze(context: EngineContext): Promise<EngineResult>
}

export interface EngineContext {
  url: string
  domain: string
  hostname: string
  protocol: string
  port: string
  path: string
  query: string
  fragment: string
  tld: string
  subdomains: string[]
  ip?: string
  html?: string
  forms?: FormInfo[]
  links?: string[]
  scripts?: string[]
  iframes?: IframeInfo[]
  headers?: Record<string, string>
  redirectChain?: string[]
  certificates?: CertificateData[]
  documentProps?: DocumentProperties
  tabId?: number
}

export interface FormInfo {
  action: string
  method: string
  fields: FormFieldInfo[]
  hasPassword: boolean
  hasSubmit: boolean
  actionDomain: string
  isExternal: boolean
}

export interface FormFieldInfo {
  type: string
  name: string
  id: string
  placeholder: string
  isPassword: boolean
  isHidden: boolean
}

export interface IframeInfo {
  src: string
  width: string
  height: string
  isHidden: boolean
  domain: string
}

export interface DocumentProperties {
  title: string
  domain: string
  lastModified: number
  referrer: string
  cookiesEnabled: boolean
}

export interface CertificateData {
  issuer: string
  subject: string
  validFrom: number
  validTo: number
  fingerprint: string
  isSelfSigned: boolean
}

export interface EngineWeightConfig {
  id: string
  enabled: boolean
  weight: number
  threshold: number
}

export const DEFAULT_ENGINE_WEIGHTS: EngineWeightConfig[] = [
  { id: 'url-reputation', enabled: true, weight: 15, threshold: 0.5 },
  { id: 'domain-age', enabled: true, weight: 8, threshold: 0.4 },
  { id: 'typosquatting', enabled: true, weight: 12, threshold: 0.5 },
  { id: 'homograph', enabled: true, weight: 10, threshold: 0.4 },
  { id: 'unicode-attack', enabled: true, weight: 10, threshold: 0.4 },
  { id: 'suspicious-tld', enabled: true, weight: 5, threshold: 0.6 },
  { id: 'certificate', enabled: true, weight: 10, threshold: 0.5 },
  { id: 'phishing-feeds', enabled: true, weight: 15, threshold: 0.3 },
  { id: 'javascript-heuristics', enabled: true, weight: 8, threshold: 0.5 },
  { id: 'credential-harvesting', enabled: true, weight: 12, threshold: 0.4 },
  { id: 'hidden-iframe', enabled: true, weight: 5, threshold: 0.5 },
  { id: 'password-field', enabled: true, weight: 5, threshold: 0.6 },
  { id: 'brand-impersonation', enabled: true, weight: 12, threshold: 0.4 },
  { id: 'html-structure', enabled: true, weight: 8, threshold: 0.5 },
  { id: 'form-destination', enabled: true, weight: 10, threshold: 0.4 },
  { id: 'redirection-chain', enabled: true, weight: 8, threshold: 0.5 },
  { id: 'screenshot-similarity', enabled: false, weight: 10, threshold: 0.5 }
]

export type EngineId = typeof DEFAULT_ENGINE_WEIGHTS[number]['id']
