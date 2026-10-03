import { defineConfig } from 'vitest/config';

export default defineConfig({
  // Relative base so the site works from any GitHub Pages sub-path.
  base: './',
  build: { outDir: 'dist', emptyOutDir: true },
  test: { include: ['src/**/*.test.ts'] },
});
