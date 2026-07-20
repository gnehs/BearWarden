import { resolve } from 'path'
import { defineConfig } from 'electron-vite'
import { lingui } from '@lingui/vite-plugin'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import Icons from 'unplugin-icons/vite'

export default defineConfig({
  main: {},
  preload: {
    build: {
      rollupOptions: {
        input: {
          index: resolve('src/preload/index.ts'),
          'account-webauthn-wrapper': resolve('src/preload/account-webauthn-wrapper.ts'),
          'account-webauthn-registration': resolve('src/preload/account-webauthn-registration.ts')
        }
      },
      isolatedEntries: true,
      externalizeDeps: false
    }
  },
  renderer: {
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true
    },
    resolve: {
      alias: {
        '@renderer': resolve('src/renderer/src')
      }
    },
    build: {
      rollupOptions: {
        input: {
          index: resolve('src/renderer/index.html'),
          'account-webauthn-wrapper': resolve('src/renderer/account-webauthn-wrapper.html')
        }
      },
      isolatedEntries: true
    },
    plugins: [
      tailwindcss(),
      react({
        babel: {
          plugins: ['@lingui/babel-plugin-lingui-macro']
        }
      }),
      lingui(),
      Icons({ compiler: 'jsx', jsx: 'react' })
    ]
  }
})
