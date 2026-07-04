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
  { id: 'credential-canary', enabled: true, weight: 18, threshold: 0.4 },
  { id: 'visual-fingerprint', enabled: true, weight: 15, threshold: 0.4 },
  { id: 'language-matrix', enabled: true, weight: 13, threshold: 0.4 },
  { id: 'url-entropy', enabled: true, weight: 12, threshold: 0.5 },
  { id: 'temporal-clustering', enabled: true, weight: 12, threshold: 0.5 },
  { id: 'css-deception', enabled: true, weight: 10, threshold: 0.5 },
  { id: 'script-timeseries', enabled: true, weight: 10, threshold: 0.5 },
  { id: 'certificate-anomaly', enabled: true, weight: 9, threshold: 0.5 },
  { id: 'interactive-honeypot', enabled: true, weight: 7, threshold: 0.5 }
]

export type EngineId = typeof DEFAULT_ENGINE_WEIGHTS[number]['id']
