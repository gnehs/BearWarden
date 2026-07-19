import { describe, expect, it } from 'vitest'
import { windowChromeOptions } from './window-chrome'

describe('windowChromeOptions', () => {
  it('keeps the inset traffic lights on macOS', () => {
    expect(windowChromeOptions('darwin')).toEqual({
      vibrancy: 'fullscreen-ui',
      titleBarStyle: 'hiddenInset',
      trafficLightPosition: { x: 14, y: 20 }
    })
  })

  it('uses the window controls overlay and Mica on Windows', () => {
    expect(windowChromeOptions('win32')).toEqual({
      backgroundMaterial: 'mica',
      titleBarStyle: 'hidden',
      titleBarOverlay: { color: '#00000000', height: 54 }
    })
  })

  it('uses the window controls overlay without a Windows-only material on Linux', () => {
    expect(windowChromeOptions('linux')).toEqual({
      titleBarStyle: 'hidden',
      titleBarOverlay: { color: '#00000000', height: 54 }
    })
  })
})
