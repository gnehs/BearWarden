import type { BrowserWindowConstructorOptions } from 'electron'

export function windowChromeOptions(
  platform: NodeJS.Platform
): Pick<
  BrowserWindowConstructorOptions,
  'vibrancy' | 'backgroundMaterial' | 'titleBarStyle' | 'titleBarOverlay' | 'trafficLightPosition'
> {
  if (platform === 'darwin') {
    return {
      vibrancy: 'fullscreen-ui',
      titleBarStyle: 'hiddenInset',
      trafficLightPosition: { x: 14, y: 20 }
    }
  }

  return {
    ...(platform === 'win32' ? { backgroundMaterial: 'mica' as const } : {}),
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#00000000',
      height: 54
    }
  }
}
