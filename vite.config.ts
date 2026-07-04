import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { resolve } from 'path'
import { copyFileSync, mkdirSync, existsSync, writeFileSync, readFileSync, renameSync } from 'fs'
import { dirname } from 'path'

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    {
      name: 'chrome-extension',
      closeBundle() {
        const dist = resolve(__dirname, 'dist')
        const iconsDir = resolve(dist, 'icons')
        if (!existsSync(iconsDir)) mkdirSync(iconsDir, { recursive: true })

        const sizes = [16, 32, 48, 128]
        sizes.forEach((size) => {
          const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
            <rect width="${size}" height="${size}" rx="${size * 0.2}" fill="#1a73e8"/>
            <text x="${size / 2}" y="${size * 0.68}" text-anchor="middle" fill="white" font-size="${size * 0.6}" font-family="Arial" font-weight="bold">S</text>
            <path d="M${size * 0.25} ${size * 0.75} L${size * 0.75} ${size * 0.75} L${size * 0.5} ${size * 0.85} Z" fill="#34a853" opacity="0.8"/>
          </svg>`
          writeFileSync(resolve(iconsDir, `icon${size}.svg`), svg)
        })

        const manifest = {
          manifest_version: 3,
          name: 'Phisher Hunter',
          version: '2.0.0',
          description: 'Next-generation phishing protection with novel detection techniques',
          permissions: [
            'storage',
            'alarms',
            'tabs',
            'webNavigation',
            'scripting'
          ],
          host_permissions: ['<all_urls>'],
          background: {
            service_worker: 'background/index.js',
            type: 'module'
          },
          content_scripts: [
            {
              matches: ['<all_urls>'],
              js: ['content/index.js'],
              run_at: 'document_start',
              all_frames: true,
              match_about_blank: true
            }
          ],
          action: {
            default_popup: 'popup.html',
            default_icon: {
              16: 'icons/icon16.svg',
              32: 'icons/icon32.svg',
              48: 'icons/icon48.svg',
              128: 'icons/icon128.svg'
            },
            default_title: 'Seagles Shield'
          },
          web_accessible_resources: [
            {
              resources: ['warning.html', 'icons/*'],
              matches: ['<all_urls>']
            }
          ],
          icons: {
            16: 'icons/icon16.svg',
            32: 'icons/icon32.svg',
            48: 'icons/icon48.svg',
            128: 'icons/icon128.svg'
          },
          content_security_policy: {
            extension_pages: "script-src 'self'; object-src 'self';"
          }
        }
        writeFileSync(resolve(dist, 'manifest.json'), JSON.stringify(manifest, null, 2))
      }
    }
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      '@shared': resolve(__dirname, 'src/shared'),
      '@background': resolve(__dirname, 'src/background'),
      '@content': resolve(__dirname, 'src/content'),
      '@popup': resolve(__dirname, 'src/popup'),
      '@warning': resolve(__dirname, 'src/warning')
    }
  },
  build: {
    outDir: 'dist',
    emptyDir: true,
    sourcemap: false,
    rollupOptions: {
      input: {
        background: resolve(__dirname, 'src/background/index.ts'),
        content: resolve(__dirname, 'src/content/index.ts'),
        popup: resolve(__dirname, 'popup.html'),
        warning: resolve(__dirname, 'warning.html')
      },
      output: {
        entryFileNames: '[name]/index.js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: (assetInfo) => {
          if (assetInfo.name?.endsWith('.css')) return '[name]/style.css'
          if (assetInfo.name?.includes('.html')) return '[name].html'
          return 'assets/[name]-[hash][extname]'
        }
      }
    },
    target: 'es2020',
    minify: 'terser'
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./tests/setup.ts'],
    include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts', 'src/**/*.tsx'],
      exclude: ['src/**/*.d.ts', 'src/**/types/*'],
      thresholds: {
        statements: 95,
        branches: 95,
        functions: 95,
        lines: 95
      }
    }
  }
})
