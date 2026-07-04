export const EXTENSION_NAME = 'Seagles Shield'
export const EXTENSION_VERSION = '1.0.0'
export const STORAGE_KEYS = {
  SETTINGS: 'seagles_shield_settings',
  CACHE: 'seagles_shield_cache',
  WHITELIST: 'seagles_shield_whitelist',
  BLACKLIST: 'seagles_shield_blacklist',
  STATS: 'seagles_shield_stats',
  ANALYSES: 'seagles_shield_analyses',
  FEED_DATA: 'seagles_shield_feeds'
} as const

export const CACHE_DEFAULTS = {
  MAX_SIZE: 10000,
  DEFAULT_TTL: 3600000,
  FEED_TTL: 1800000,
  ANALYSIS_TTL: 300000
} as const

export const API_DEFAULTS = {
  TIMEOUT: 5000,
  MAX_RETRIES: 3,
  RETRY_DELAY: 1000,
  MAX_CONCURRENT: 5
} as const

export const SCORE_THRESHOLDS = {
  SAFE_MAX: 0.15,
  LOW_MAX: 0.35,
  MEDIUM_MAX: 0.55,
  HIGH_MAX: 0.75
} as const

export const BRAND_DOMAINS: Record<string, string[]> = {
  google: ['google.com', 'gmail.com', 'youtube.com', 'drive.google.com'],
  microsoft: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'azure.com', 'bing.com'],
  apple: ['apple.com', 'icloud.com'],
  facebook: ['facebook.com', 'fb.com', 'messenger.com', 'instagram.com', 'whatsapp.com'],
  amazon: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.co.jp'],
  paypal: ['paypal.com', 'paypal.me'],
  netflix: ['netflix.com'],
  linkedin: ['linkedin.com'],
  twitter: ['twitter.com', 'x.com'],
  binance: ['binance.com', 'binance.us'],
  coinbase: ['coinbase.com'],
  metamask: ['metamask.io'],
  github: ['github.com'],
  stackoverflow: ['stackoverflow.com'],
  wordpress: ['wordpress.com'],
  shopify: ['shopify.com'],
  dropbox: ['dropbox.com'],
  adobe: ['adobe.com'],
  cloudflare: ['cloudflare.com'],
  discord: ['discord.com', 'discord.gg'],
  steam: ['steampowered.com', 'steamcommunity.com'],
  bankofamerica: ['bankofamerica.com'],
  chase: ['chase.com'],
  wellsFargo: ['wellsfargo.com'],
  citi: ['citi.com'],
  capitalone: ['capitalone.com'],
  hsbc: ['hsbc.com'],
  barclays: ['barclays.com'],
  stripe: ['stripe.com'],
  square: ['squareup.com'],
  etsy: ['etsy.com'],
  ebay: ['ebay.com'],
  bestbuy: ['bestbuy.com'],
  walmart: ['walmart.com'],
  target: ['target.com'],
  cvs: ['cvs.com'],
  walgreens: ['walgreens.com'],
  costco: ['costco.com'],
  homedepot: ['homedepot.com'],
  lowes: ['lowes.com'],
  zoom: ['zoom.us'],
  slack: ['slack.com'],
  atlassian: ['atlassian.net', 'jira.com'],
  okta: ['okta.com'],
  duo: ['duosecurity.com'],
  oracle: ['oracle.com'],
  salesforce: ['salesforce.com'],
  sap: ['sap.com']
}

export const SUSPICIOUS_TLDS = new Set([
  '.xyz', '.top', '.club', '.online', '.site', '.live',
  '.work', '.blog', '.store', '.shop', '.click', '.link',
  '.download', '.review', '.win', '.bid', '.trade', '.webcam',
  '.science', '.party', '.gq', '.ml', '.ga', '.cf', '.tk',
  '.rest', '.faith', '.date', '.men', '.loan', '.repair',
  '.stream', '.racing', '.accountant', '.country', '.mom',
  '.lol', '.pics', '.gdn', '.work', '.host', '.press',
  '.website', '.space', '.tech', '.fun', '.icu', '.cyou'
])

export const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'signin', 'verify', 'account', 'secure',
  'update', 'confirm', 'authenticate', 'password', 'credential',
  'wallet', 'recover', 'reset', 'support', 'helpdesk', 'security',
  'alert', 'suspicious', 'unusual', 'access', 'limited', 'restricted',
  'validation', 'ssn', 'socialsecurity', 'routing', 'accountnumber',
  'banking', 'onlinebanking', 'ebanking', 'netbanking',
  '2fa', 'twofactor', 'mfa', 'multifactor',
  'billing', 'invoice', 'payment', 'charge', 'subscription',
  'refund', 'prize', 'winner', 'lottery', 'free', 'gift',
  'coupon', 'discount', 'offer', 'promotion',
  'crypto', 'bitcoin', 'ethereum', 'blockchain', 'defi',
  'metamask', 'ledger', 'trezor', 'trustwallet',
  'phishing', 'malware', 'virus', 'antivirus',
  'document', 'docusign', 'adobesign', 'esign',
  'sharepoint', 'onedrive', 'googledrive', 'dropbox'
]

export const WELL_KNOWN_TRACKERS = new Set([
  'google-analytics.com', 'googletagmanager.com', 'facebook.net',
  'doubleclick.net', 'adservice.google.com', 'scorecardresearch.com',
  'quantserve.com', 'criteo.com', 'adsrvr.org', 'rubiconproject.com',
  'openx.net', 'pubmatic.com', 'casalemedia.com', 'contextweb.com',
  'adnxs.com', 'adsafeprotected.com', 'moatads.com', 'proht.com'
])

export const KNOWN_PHISHING_FEEDS = [
  'https://openphish.com/feed.txt',
  'https://phishstats.info/phish_score.csv',
  'https://raw.githubusercontent.com/datadancer223/fake-news/master/data/phishing_domains.txt'
]

export const MESSAGE_ACTION_PREFIX = 'SEAGLES_SHIELD_'

export const WARNING_PAGE_URL = chrome.runtime?.getURL?.('/warning.html') ?? 'warning.html'

export const DEBOUNCE_DELAYS = {
  SCAN: 300,
  NAVIGATION: 500,
  INPUT: 200,
  SETTINGS_SAVE: 500
} as const

export const PERFORMANCE_BUDGETS = {
  MAX_ANALYSIS_TIME: 5000,
  MAX_ENGINE_TIME: 2000,
  MAX_CONTENT_SCRIPT_LOAD: 100,
  MAX_POPUP_LOAD: 200,
  MAX_MEMORY_CACHE_ITEMS: 500
} as const

export const HOMOGLITCH_CHARACTERS = new Set([
  '\u0430', '\u0435', '\u043E', '\u0440', '\u0441', '\u0443',
  '\u0456', '\u0454', '\u04BB', '\u04E9', '\u0501',
  '\u0432', '\u043A', '\u043C', '\u04AF',
  '\u00E0', '\u00E1', '\u00E2', '\u00E3', '\u00E4', '\u00E5',
  '\u00E8', '\u00E9', '\u00EA', '\u00EB',
  '\u00EC', '\u00ED', '\u00EE', '\u00EF',
  '\u00F2', '\u00F3', '\u00F4', '\u00F5', '\u00F6',
  '\u00F9', '\u00FA', '\u00FB', '\u00FC',
  '\u0101', '\u0113', '\u012B', '\u014D', '\u016B',
  '\u00FD', '\u00FF'
])

export const HIGH_RISK_TLDS = new Set([
  '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc',
  '.sbs', '.lol', '.sex', '.xxx', '.porn', '.adult',
  '.cam', '.homes', '.life', '.surf', '.bond', '.realtor',
  '.cricket', '.faith', '.date', '.download', '.loan', '.men',
  '.racing', '.review', '.win', '.bid', '.trade', '.webcam',
  '.science', '.party', '.accountant', '.country', '.stream',
  '.gdn', '.mom', '.rest', '.host', '.press', '.cyou', '.icu'
])
