import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

const lib = (path: string) => fileURLToPath(new URL(`../../packages/latticework/src/${path}`, import.meta.url));

// Served from https://autumntrace.github.io/latticework/ in production.
export default defineConfig({
  base: '/latticework/',
  resolve: {
    // Use the library's TypeScript sources directly: no build step in between.
    alias: [
      { find: /^@autumntrace\/latticework\/internals$/, replacement: lib('internals.ts') },
      { find: /^@autumntrace\/latticework$/, replacement: lib('index.ts') },
    ],
  },
  build: { target: 'es2022' },
});
