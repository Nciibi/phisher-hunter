import '@testing-library/jest-dom'

// Mock Chrome API
const chromeMock = {
  runtime: {
    sendMessage: vi.fn(),
    onMessage: {
      addListener: vi.fn()
    },
    getURL: vi.fn((path: string) => path),
    id: 'test-extension-id'
  },
  storage: {
    local: {
      get: vi.fn(() => Promise.resolve({})),
      set: vi.fn(() => Promise.resolve()),
      remove: vi.fn(() => Promise.resolve())
    },
    sync: {
      get: vi.fn(() => Promise.resolve({})),
      set: vi.fn(() => Promise.resolve())
    }
  },
  tabs: {
    query: vi.fn(() => Promise.resolve([{ id: 1, url: 'https://example.com', title: 'Test' }])),
    sendMessage: vi.fn(),
    onUpdated: {
      addListener: vi.fn()
    }
  },
  webNavigation: {
    onCommitted: {
      addListener: vi.fn()
    }
  },
  alarms: {
    create: vi.fn(),
    onAlarm: {
      addListener: vi.fn()
    }
  },
  action: {
    setBadgeText: vi.fn(),
    setBadgeBackgroundColor: vi.fn()
  }
}

Object.assign(globalThis, { chrome: chromeMock })
