import '@fontsource/inter/latin-400.css'
import '@fontsource/inter/latin-500.css'
import '@fontsource/inter/latin-600.css'
import '@fontsource/inter/latin-700.css'
import '@fontsource/inter/latin-800.css'
import '@fontsource/inter/latin-900.css'
import './assets/main.css'

import { RouterProvider } from '@tanstack/react-router'
import { I18nProvider } from '@lingui/react'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import AppUpdateNotifier from './components/AppUpdateNotifier'
import AutofillPickerHost from './components/AutofillPickerHost'
import { Toaster } from './components/ui/sonner'
import { TooltipProvider } from './components/ui/tooltip'
import { router } from './router'
import { activateLocale, detectSystemLocale, i18n } from './i18n'

const isAutofillPicker = new URLSearchParams(window.location.search).get('mode') === 'autofill'
if (isAutofillPicker) {
  document.documentElement.style.background = 'transparent'
  document.body.style.background = 'transparent'
}

void activateLocale(detectSystemLocale()).then(() => {
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <I18nProvider i18n={i18n}>
        <TooltipProvider>
          {isAutofillPicker ? (
            <AutofillPickerHost />
          ) : (
            <>
              <RouterProvider router={router} />
              <AppUpdateNotifier />
              <Toaster position="bottom-right" />
            </>
          )}
        </TooltipProvider>
      </I18nProvider>
    </StrictMode>
  )

  window.addEventListener('languagechange', () => {
    void activateLocale(detectSystemLocale())
  })
})
