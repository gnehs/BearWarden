import { GodRays } from '@paper-design/shaders-react'
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

function AuthGodRaysBackground(): React.JSX.Element {
  const prefersReducedMotion = usePrefersReducedMotion()
  const [hasWebGl2] = useState(supportsWebGl2)

  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden="true">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_48%_32%,color-mix(in_oklch,var(--foreground)_7%,transparent),transparent_46%),linear-gradient(145deg,color-mix(in_oklch,var(--muted)_58%,transparent),color-mix(in_oklch,var(--background)_74%,transparent)_58%,color-mix(in_oklch,var(--accent)_54%,transparent))]" />
      {hasWebGl2 && (
        <GodRays
          className="absolute inset-0 size-full opacity-75"
          width="100%"
          height="100%"
          colors={['#ffffff5c', '#64748b2e', '#cbd5e142', '#c7844430']}
          colorBack="#00000000"
          colorBloom="#ffffff24"
          bloom={0.28}
          intensity={0.58}
          density={0.2}
          spotty={0.46}
          midSize={0.18}
          midIntensity={0.28}
          speed={prefersReducedMotion ? 0 : 0.45}
          frame={2400}
          scale={1.22}
          offsetX={0.02}
          offsetY={-0.36}
          fit="cover"
          minPixelRatio={1}
          maxPixelCount={1920 * 1080}
          webGlContextAttributes={webGlContextAttributes}
        />
      )}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,transparent_22%,color-mix(in_oklch,var(--background)_24%,transparent)_100%)]" />
    </div>
  )
}

export default AuthGodRaysBackground
