export const EXTENSION_NAME = 'Phisher Hunter'
export const EXTENSION_VERSION = '2.0.0'
export const STORAGE_KEYS = {
  SETTINGS: 'phisher_hunter_settings',
  CACHE: 'phisher_hunter_cache',
  WHITELIST: 'phisher_hunter_whitelist',
  BLACKLIST: 'phisher_hunter_blacklist',
  STATS: 'phisher_hunter_stats',
  ANALYSES: 'phisher_hunter_analyses',
  FEED_DATA: 'phisher_hunter_feeds',
  CANARY_STATE: 'phisher_hunter_canary',
  BRAND_FINGERPRINTS: 'phisher_hunter_fingerprints',
  CAMPAIGN_DATA: 'phisher_hunter_campaigns'
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

export const MESSAGE_ACTION_PREFIX = 'PHISHER_HUNTER_'

export const WARNING_PAGE_URL = chrome.runtime?.getURL?.('/warning.html') ?? 'warning.html'

export const DEBOUNCE_DELAYS = {
  SCAN: 300,
  NAVIGATION: 500,
  INPUT: 200,
  SETTINGS_SAVE: 500,
  MUTATION_OBSERVER: 100,
  CANARY_INJECT: 50
} as const

export const PERFORMANCE_BUDGETS = {
  MAX_ANALYSIS_TIME: 5000,
  MAX_ENGINE_TIME: 2000,
  MAX_CONTENT_SCRIPT_LOAD: 100,
  MAX_POPUP_LOAD: 200,
  MAX_MEMORY_CACHE_ITEMS: 500
} as const

// --- NOVEL TECHNIQUE CONSTANTS ---

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

// --- NOVEL: Credential Canary ---
export const CANARY_FIELD_NAMES = [
  'ph_username_verify',
  'ph_canary_token',
  'ph_security_check',
  'ph_verify_field',
  'ph_honeypot_email'
]

export const CANARY_FIELD_STYLES = {
  position: 'absolute',
  left: '-9999px',
  top: '-9999px',
  width: '1px',
  height: '1px',
  opacity: '0',
  overflow: 'hidden',
  zIndex: '-1'
} as const

// --- NOVEL: URL Entropy thresholds ---
export const URL_ENTROPY_THRESHOLDS = {
  SUBDOMAIN_HIGH: 3.5,
  PATH_HIGH: 4.0,
  QUERY_HIGH: 4.5,
  OVERALL_HIGH: 3.8
} as const

// --- NOVEL: Phishing Language Patterns ---
export const PHISHING_NGRAM_PATTERNS: Record<string, RegExp[]> = {
  urgency: [
    /act\s+(now|immediately|quickly)/i,
    /limited\s+time/i,
    /expires?\s+(soon|today|now)/i,
    /immediate\s+(action|attention|response)/i,
    /urgent/i,
    /time\s+(sensitive|critical|crucial)/i,
    /don'?t\s+(miss|lose|delay)/i,
    /last\s+(chance|warning|notice)/i,
    /final\s+(notice|reminder|warning)/i
  ],
  authority: [
    /security\s+(team|department|center)/i,
    /account\s+(management|team|services)/i,
    /support\s+(team|center|department)/i,
    /help\s+(desk|center)/i,
    /administrat/i,
    /official\s+(notice|notification|communication)/i,
    /legal\s+(department|notice|action)/i
  ],
  threat: [
    /suspended/i,
    /terminated/i,
    /disabled/i,
    /restricted/i,
    /deactivated/i,
    /blocked/i,
    /compromised/i,
    /unauthorized\s+(access|login|activity)/i,
    /security\s+(breach|incident|violation)/i,
    /fraudulent\s+(activity|transaction|login)/i
  ],
  reward: [
    /won\s+/i,
    /winner/i,
    /congratulations/i,
    /prize/i,
    /lottery/i,
    /inheritance/i,
    /grant\s+/i,
    /compensation/i,
    /settlement/i,
    /unclaimed/i
  ],
  credential: [
    /verify\s+(your|the)\s+(account|identity|information)/i,
    /confirm\s+(your|the)\s+(account|details|information)/i,
    /update\s+(your|the)\s+(account|details|information|password)/i,
    /sign\s+in\s+(to|here)\s+(verify|confirm|update)/i,
    /login\s+(to|here)\s+(verify|confirm|update)/i,
    /account\s+(verification|confirmation|validation)/i,
    /provide\s+(your|the)\s+(credentials|password|information)/i
  ]
}

// --- NOVEL: CSS Deception Patterns ---
export const CSS_DECEPTION_PATTERNS = [
  { pattern: /opacity\s*:\s*0/i, weight: 0.15, name: 'zero-opacity' },
  { pattern: /opacity\s*:\s*0\.\d{1,2}\s*;?/i, weight: 0.08, name: 'low-opacity' },
  { pattern: /visibility\s*:\s*hidden/i, weight: 0.15, name: 'visibility-hidden' },
  { pattern: /display\s*:\s*none/i, weight: 0.1, name: 'display-none' },
  { pattern: /text-indent\s*:\s*-\d{4,}/i, weight: 0.12, name: 'text-indent-offscreen' },
  { pattern: /position\s*:\s*(fixed|absolute)\s*;[^}]*z-index\s*:\s*\d{4,}/i, weight: 0.2, name: 'high-z-index-overlay' },
  { pattern: /clip\s*:\s*rect\([^)]*\)/i, weight: 0.1, name: 'clip-hide' },
  { pattern: /overflow\s*:\s*hidden\s*;[^}]*height\s*:\s*0/i, weight: 0.1, name: 'overflow-hide' },
  { pattern: /transform\s*:\s*(scale|translate)\([^)]*\)-?\d{4,}/i, weight: 0.12, name: 'transform-offscreen' },
  { pattern: /pointer-events\s*:\s*none/i, weight: 0.05, name: 'pointer-events-none' },
  { pattern: /filter\s*:\s*blur\(\d+px\)/i, weight: 0.05, name: 'blur-filter' }
]

// --- NOVEL: DOM Fingerprint elements ---
export const FINGERPRINT_TAG_WEIGHTS: Record<string, number> = {
  form: 10,
  input: 5,
  'input[type="password"]': 15,
  button: 3,
  a: 1,
  img: 2,
  iframe: 8,
  script: 4,
  meta: 2,
  div: 0.5,
  span: 0.3
}

// --- NOVEL: Temporal clustering ---
export const CAMPAIGN_TIME_WINDOW_MS = 7 * 24 * 60 * 60 * 1000
export const CAMPAIGN_SIMILARITY_THRESHOLD = 0.7

// --- NOVEL: Script behavior monitoring ---
export const SCRIPT_MONITOR_WINDOW_MS = 5000
export const MAX_MUTATIONS_PER_WINDOW = 100
export const SUSPICIOUS_MUTATION_PATTERNS = [
  { pattern: /form/i, type: 'form-creation' },
  { pattern: /input/i, type: 'input-creation' },
  { pattern: /password/i, type: 'password-reference' },
  { pattern: /submit/i, type: 'submit-handler' },
  { pattern: /fetch|XMLHttpRequest/i, type: 'network-request' },
  { pattern: /addEventListener/i, type: 'event-listener' },
  { pattern: /location/i, type: 'location-access' },
  { pattern: /cookie/i, type: 'cookie-access' }
]
