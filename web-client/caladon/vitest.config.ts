import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // The live integration test reaches the real gateway (cold-start can be minutes — see
    // gw-v1-live/RESULT.md), so give it a generous per-test timeout.
    testTimeout: 360_000,
    hookTimeout: 60_000,
    include: ['test/**/*.test.ts'],
  },
});
