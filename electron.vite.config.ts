import { resolve } from 'path'
import { defineConfig } from 'electron-vite'
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
          'account-webauthn-wrapper': resolve('src/preload/account-webauthn-wrapper.ts')
        }
      },
      isolatedEntries: true,
      externalizeDeps: false
    }
  },
  renderer: {
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
    plugins: [tailwindcss(), react(), Icons({ compiler: 'jsx', jsx: 'react' })]
  }
})
