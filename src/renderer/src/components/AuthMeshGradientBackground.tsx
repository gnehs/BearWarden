import { MeshGradient } from '@paper-design/shaders-react'
import { useEffect, useState } from 'react'

const reducedMotionQuery = '(prefers-reduced-motion: reduce)'
const webGlContextAttributes = { alpha: true, premultipliedAlpha: true } as const

function supportsWebGl2(): boolean {
  const canvas = document.createElement('canvas')
  const context = canvas.getContext('webgl2')
  context?.getExtension('WEBGL_lose_context')?.loseContext()
  return context !== null
}

function usePrefersReducedMotion(): boolean {
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(
    () => window.matchMedia(reducedMotionQuery).matches
  )

  useEffect(() => {
    const mediaQuery = window.matchMedia(reducedMotionQuery)
    const updatePreference = (): void => setPrefersReducedMotion(mediaQuery.matches)

    mediaQuery.addEventListener('change', updatePreference)
    return () => mediaQuery.removeEventListener('change', updatePreference)
  }, [])

  return prefersReducedMotion
}

function AuthMeshGradientBackground(): React.JSX.Element {
  const prefersReducedMotion = usePrefersReducedMotion()
  const [hasWebGl2] = useState(supportsWebGl2)

  return (
    <div
      className="pointer-events-none absolute inset-0 overflow-hidden mix-blend-plus-lighter"
      aria-hidden="true"
    >
      {hasWebGl2 && (
        <MeshGradient
          className="absolute inset-0 size-full opacity-25"
          width={1280}
          height={720}
          colors={['#e0eaff', '#241d9a', '#f75092', '#9f50d3']}
          distortion={0.8}
          swirl={0.1}
          grainMixer={0}
          grainOverlay={0}
          speed={prefersReducedMotion ? 0 : 1}
          style={{ width: '100%', height: '100%' }}
          minPixelRatio={1}
          maxPixelCount={1920 * 1080}
          webGlContextAttributes={webGlContextAttributes}
        />
      )}
    </div>
  )
}

export default AuthMeshGradientBackground
