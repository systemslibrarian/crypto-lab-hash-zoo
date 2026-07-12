/// <reference types="vitest/config" />
import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-hash-zoo/',
  test: {
    // Unit tests live next to the source under src/. The Playwright a11y suite
    // in e2e/ is driven by `npm run test:a11y`, not vitest, so exclude it here.
    include: ['src/**/*.{test,spec}.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
