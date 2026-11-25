import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const lib = (path: string) => fileURLToPath(new URL(`./packages/latticework/src/${path}`, import.meta.url));

export default defineConfig({
  resolve: {
    alias: [
      { find: /^@autumntrace\/latticework\/internals$/, replacement: lib('internals.ts') },
      { find: /^@autumntrace\/latticework$/, replacement: lib('index.ts') },
    ],
  },
  test: {
    include: ['packages/*/test/**/*.test.ts', 'apps/*/test/**/*.test.ts'],
    globalSetup: ['scripts/vitest-vectors.ts'],
    testTimeout: 60_000,
  },
});
