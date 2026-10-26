import { defineConfig } from 'vite'
import { resolve } from 'node:path'

export default defineConfig({
  base: '/',
  build: {
    outDir: resolve(import.meta.dirname, '../cmd/panel/ui-dist'),
    emptyOutDir: true,
    assetsDir: 'assets',
    sourcemap: false
  }
})
