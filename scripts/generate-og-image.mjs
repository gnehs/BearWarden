import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { createElement as h } from 'react'
import { render } from 'takumi-js'

/* eslint-disable @typescript-eslint/explicit-function-return-type -- Native ESM keeps this asset script runnable without a TypeScript executor. */

const WIDTH = 1280
const HEIGHT = 640
const MAX_GITHUB_BYTES = 1_000_000

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url))
const repositoryRoot = path.resolve(scriptDirectory, '..')
const iconPath = path.join(repositoryRoot, 'resources', 'icon.png')
const defaultOutputPath = path.join(repositoryRoot, 'docs', 'assets', 'bearwarden-og.png')

function optionValue(name) {
  const optionIndex = process.argv.indexOf(name)

  if (optionIndex === -1) return undefined
  if (!process.argv[optionIndex + 1]) throw new Error(`${name} requires a path`)

  return process.argv[optionIndex + 1]
}

function div(style, ...children) {
  return h('div', { style }, ...children)
}

function line(width = '70%', tone = '#8295a3', height = 8) {
  return div({
    width,
    height,
    borderRadius: 999,
    background: tone,
    opacity: 0.46
  })
}

function railItem({ active = false, round = false } = {}) {
  return div(
    {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      height: 46,
      padding: '0 14px',
      border: active ? '1px solid rgba(52, 211, 153, 0.18)' : '1px solid transparent',
      borderRadius: 14,
      background: active ? 'rgba(16, 185, 129, 0.18)' : 'transparent'
    },
    div(
      { display: 'flex', alignItems: 'center', gap: 11 },
      div({
        width: 25,
        height: 25,
        borderRadius: round ? 999 : 8,
        background: active ? '#10b981' : '#294455',
        boxShadow: active ? '0 5px 16px rgba(16, 185, 129, 0.25)' : 'none'
      }),
      line(active ? 58 : 48, active ? '#6ee7b7' : '#8295a3', 7)
    ),
    div({
      width: 6,
      height: 6,
      borderRadius: 999,
      background: active ? '#34d399' : '#486171'
    })
  )
}

function vaultRow({ active = false, accent = '#6b8190' } = {}) {
  return div(
    {
      display: 'flex',
      alignItems: 'center',
      height: 66,
      gap: 12,
      padding: '0 15px',
      border: active ? '1px solid rgba(52, 211, 153, 0.16)' : '1px solid transparent',
      borderRadius: 15,
      background: active
        ? 'linear-gradient(90deg, rgba(16, 185, 129, 0.22), rgba(16, 185, 129, 0.11))'
        : 'transparent'
    },
    div({
      width: 34,
      height: 34,
      borderRadius: 10,
      background: accent,
      boxShadow: 'inset 0 0 0 1px rgba(255, 255, 255, 0.12)'
    }),
    div(
      { display: 'flex', flexDirection: 'column', width: 125, gap: 8 },
      line('78%', active ? '#d1fae5' : '#9aabb5', 8),
      line('52%', '#617986', 6)
    ),
    div({ marginLeft: 'auto', color: '#718793', fontSize: 17 }, '•••')
  )
}

function field({ password = false, wide = false } = {}) {
  return div(
    {
      display: 'flex',
      alignItems: 'center',
      height: 41,
      gap: 13,
      borderBottom: '1px solid rgba(130, 149, 163, 0.15)'
    },
    div({ width: 17, height: 17, border: '2px solid #718996', borderRadius: 5 }),
    password
      ? div({ color: '#eef5f7', fontSize: 19, letterSpacing: 5 }, '••••••••')
      : line(wide ? '68%' : '48%', '#a3b3bb', 8),
    div({
      width: 14,
      height: 14,
      marginLeft: 'auto',
      border: '2px solid #718996',
      borderRadius: 3
    })
  )
}

function appMockup() {
  const railItems = [
    { active: true, round: true },
    { round: true },
    {},
    { round: true },
    {},
    { round: true },
    {}
  ]
  const rows = [
    { active: true, accent: '#f4f1e8' },
    { accent: '#1a594c' },
    { accent: '#14518a' },
    { accent: '#654b9d' },
    { accent: '#437d53' },
    { accent: '#a94d12' }
  ]

  return div(
    {
      display: 'flex',
      width: 825,
      height: 512,
      overflow: 'hidden',
      border: '1px solid rgba(193, 215, 225, 0.25)',
      borderRadius: 24,
      background: 'rgba(7, 26, 39, 0.93)',
      boxShadow: '0 30px 80px rgba(0, 0, 0, 0.38), 0 0 0 1px rgba(255, 255, 255, 0.025)',
      backdropFilter: 'blur(18px)'
    },
    div(
      {
        display: 'flex',
        flexDirection: 'column',
        width: 148,
        borderRight: '1px solid rgba(152, 177, 188, 0.16)'
      },
      div(
        {
          display: 'flex',
          alignItems: 'center',
          height: 52,
          paddingLeft: 18,
          gap: 8,
          borderBottom: '1px solid rgba(152, 177, 188, 0.14)'
        },
        ...['#ff5f57', '#febc2e', '#28c840'].map((background) =>
          div({ width: 10, height: 10, borderRadius: 999, background })
        )
      ),
      div(
        { display: 'flex', flexDirection: 'column', padding: '15px 10px', gap: 4 },
        ...railItems.map(railItem)
      ),
      div(
        { marginTop: 'auto', padding: 18 },
        div({ width: 26, height: 26, border: '2px solid #5d7582', borderRadius: 9 })
      )
    ),
    div(
      {
        display: 'flex',
        flexDirection: 'column',
        width: 255,
        padding: '17px 12px',
        borderRight: '1px solid rgba(152, 177, 188, 0.16)'
      },
      div(
        {
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          height: 36,
          padding: '0 10px 10px'
        },
        line(80, '#8da0aa', 9),
        div({
          width: 56,
          height: 28,
          border: '1px solid rgba(152, 177, 188, 0.22)',
          borderRadius: 10
        })
      ),
      ...rows.map(vaultRow)
    ),
    div(
      { display: 'flex', flexDirection: 'column', width: 422, padding: 18, gap: 12 },
      div(
        { display: 'flex', alignItems: 'center', height: 44, gap: 12 },
        div({ width: 38, height: 38, borderRadius: 11, background: '#f4f1e8' }),
        div(
          { display: 'flex', flexDirection: 'column', width: 170, gap: 7 },
          line('70%', '#d7e0e4', 9),
          line('48%', '#708794', 6)
        ),
        div({
          width: 18,
          height: 18,
          marginLeft: 'auto',
          border: '2px solid #9fb0b8',
          borderRadius: 999
        })
      ),
      div(
        {
          padding: '4px 16px 1px',
          border: '1px solid rgba(152, 177, 188, 0.20)',
          borderRadius: 18,
          background: 'rgba(255, 255, 255, 0.025)'
        },
        field(),
        field({ password: true }),
        field({ wide: true })
      ),
      div(
        {
          padding: '8px 16px 4px',
          border: '1px solid rgba(152, 177, 188, 0.20)',
          borderRadius: 18,
          background: 'rgba(255, 255, 255, 0.025)'
        },
        div(
          { display: 'flex', alignItems: 'center', height: 34, gap: 10 },
          div({ width: 17, height: 17, border: '2px solid #8295a3', borderRadius: 999 }),
          line('42%', '#a8b8bf', 8),
          div({
            width: 16,
            height: 16,
            marginLeft: 'auto',
            border: '3px solid #10b981',
            borderTopColor: 'transparent',
            borderRadius: 999
          })
        ),
        div({ padding: '8px 0 12px', color: '#f7fafb', fontSize: 26, letterSpacing: 10 }, '••••••')
      ),
      div(
        {
          display: 'flex',
          flexDirection: 'column',
          height: 126,
          gap: 11,
          padding: 16,
          border: '1px solid rgba(152, 177, 188, 0.20)',
          borderRadius: 18,
          background: 'rgba(255, 255, 255, 0.025)'
        },
        line('32%', '#a8b8bf', 9),
        line('84%', '#758b96', 7),
        line('68%', '#667d89', 7),
        line('76%', '#667d89', 7)
      )
    )
  )
}

function ogImage() {
  return div(
    {
      position: 'relative',
      display: 'flex',
      width: '100%',
      height: '100%',
      overflow: 'hidden',
      color: '#ffffff',
      background: '#00243E',
      fontFamily: 'Geist, sans-serif'
    },
    div({
      position: 'absolute',
      width: 520,
      height: 520,
      left: -250,
      top: -250,
      borderRadius: 999,
      background: 'radial-gradient(circle, rgba(247, 165, 67, 0.34), rgba(247, 165, 67, 0) 69%)'
    }),
    div({
      position: 'absolute',
      width: 620,
      height: 620,
      right: -300,
      bottom: -330,
      borderRadius: 999,
      background: 'radial-gradient(circle, rgba(247, 165, 67, 0.30), rgba(247, 165, 67, 0) 70%)'
    }),
    div({
      position: 'absolute',
      inset: 0,
      background: 'linear-gradient(120deg, rgba(255, 255, 255, 0.025), transparent 45%)'
    }),
    h(
      'section',
      {
        style: {
          position: 'relative',
          zIndex: 1,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          width: 470,
          paddingLeft: 68,
          paddingRight: 24
        }
      },
      h('img', { src: 'bearwarden-icon', width: 180, height: 180 }),
      h(
        'h1',
        {
          style: {
            margin: '28px 0 0',
            fontSize: 62,
            fontWeight: 700,
            lineHeight: 1,
            letterSpacing: -3.2
          }
        },
        h('span', { style: { color: '#F8FAFC' } }, 'Bear'),
        h('span', { style: { color: '#F7A543' } }, 'Warden')
      ),
      h(
        'p',
        {
          style: {
            width: 370,
            margin: '20px 0 0',
            color: '#B9C8D1',
            fontSize: 22,
            lineHeight: 1.45
          }
        },
        'A secure, local-first',
        h('br'),
        'password manager'
      )
    ),
    h(
      'section',
      {
        style: {
          position: 'relative',
          zIndex: 1,
          display: 'flex',
          alignItems: 'center',
          width: 810
        }
      },
      appMockup()
    )
  )
}

const requestedOutputPath = optionValue('--output')
const outputPath = requestedOutputPath
  ? path.resolve(repositoryRoot, requestedOutputPath)
  : defaultOutputPath
const icon = await readFile(iconPath)
const image = await render(ogImage(), {
  width: WIDTH,
  height: HEIGHT,
  format: 'png',
  dithering: 'ordered-bayer',
  images: [{ src: 'bearwarden-icon', data: icon }]
})

if (image.byteLength >= MAX_GITHUB_BYTES) {
  throw new Error(
    `Generated image is ${image.byteLength} bytes; GitHub requires a file smaller than ${MAX_GITHUB_BYTES} bytes`
  )
}

await mkdir(path.dirname(outputPath), { recursive: true })
await writeFile(outputPath, image)

console.log(
  `Generated ${path.relative(repositoryRoot, outputPath)} (${WIDTH}×${HEIGHT}, ${image.byteLength} bytes)`
)
