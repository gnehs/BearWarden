import { defineConfig } from '@lingui/cli'

export default defineConfig({
  sourceLocale: 'en',
  locales: ['en', 'zh-CN', 'zh-TW', 'ja'],
  fallbackLocales: {
    default: 'en'
  },
  catalogs: [
    {
      path: '<rootDir>/src/renderer/src/locales/{locale}/messages',
      include: ['<rootDir>/src/renderer/src']
    }
  ]
})
