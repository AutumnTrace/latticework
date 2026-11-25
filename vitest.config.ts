import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/*/test/**/*.test.ts', 'apps/*/test/**/*.test.ts'],
    globalSetup: ['scripts/vitest-vectors.ts'],
    testTimeout: 60_000,
  },
});
