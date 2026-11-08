import { resolve } from 'node:path'
import { lingui } from '@lingui/vite-plugin'
import react from '@vitejs/plugin-react'
import { configDefaults, defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [
    react({
      babel: {
        plugins: ['@lingui/babel-plugin-lingui-macro']
      }
    }),
    lingui()
  ],
  test: {
    exclude: [...configDefaults.exclude, '.claude/**'],
    setupFiles: ['src/renderer/src/test/i18n-setup.ts']
  },
  resolve: {
    alias: {
      '@renderer': resolve('src/renderer/src')
    }
  }
})
