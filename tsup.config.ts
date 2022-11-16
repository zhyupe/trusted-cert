import { defineConfig } from 'tsup'
import { name, version } from './package.json'

const banner = `${'/*!\n' + ' * '}${name}.js v${version}\n` +
` * (c) 2020-2021 sprying\n` +
` * (c) 2022 zhyupe\n` +
' * Released under the MIT License.\n' +
' */'

const isProd = process.env.NODE_ENV === 'production'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  splitting: false,
  clean: true,
  dts: true,
  minify: isProd,
  banner: {
    js: banner
  }
})
