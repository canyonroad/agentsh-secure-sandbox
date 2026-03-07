import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/e2e/**/*.e2e.test.ts'],
    testTimeout: 300_000, // 5 min per test
    hookTimeout: 120_000, // 2 min for beforeAll (sandbox creation + provisioning)
    fileParallelism: false, // run platforms sequentially to avoid resource contention
  },
});
