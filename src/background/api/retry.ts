import { API_DEFAULTS } from '../../shared/constants'

export interface RetryOptions {
  maxRetries?: number
  baseDelay?: number
  maxDelay?: number
  backoffFactor?: number
  retryableStatuses?: number[]
}

const DEFAULT_OPTIONS: Required<RetryOptions> = {
  maxRetries: API_DEFAULTS.MAX_RETRIES,
  baseDelay: API_DEFAULTS.RETRY_DELAY,
  maxDelay: 10000,
  backoffFactor: 2,
  retryableStatuses: [408, 429, 500, 502, 503, 504]
}

export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const opts = { ...DEFAULT_OPTIONS, ...options }
  let lastError: Error | null = null

  for (let attempt = 0; attempt <= opts.maxRetries; attempt++) {
    try {
      return await fn()
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error))

      if (attempt < opts.maxRetries) {
        const delay = Math.min(
          opts.baseDelay * Math.pow(opts.backoffFactor, attempt),
          opts.maxDelay
        )

        if (error instanceof ResponseError && !opts.retryableStatuses.includes(error.status)) {
          throw error
        }

        await new Promise(resolve => setTimeout(resolve, delay))
      }
    }
  }

  throw lastError || new Error('Retry failed')
}

export class ResponseError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly statusText: string
  ) {
    super(message)
    this.name = 'ResponseError'
  }
}

export async function fetchWithRetry(
  url: string,
  init?: RequestInit,
  options: RetryOptions = {}
): Promise<Response> {
  return withRetry(async () => {
    const response = await fetch(url, {
      ...init,
      signal: init?.signal ?? AbortSignal.timeout(API_DEFAULTS.TIMEOUT)
    })

    if (!response.ok) {
      throw new ResponseError(
        `HTTP ${response.status}: ${response.statusText}`,
        response.status,
        response.statusText
      )
    }

    return response
  }, options)
}
