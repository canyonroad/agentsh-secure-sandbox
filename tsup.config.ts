import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/adapters/index.ts',
    'src/adapters/vercel.ts',
    'src/adapters/e2b.ts',
    'src/adapters/daytona.ts',
    'src/adapters/cloudflare.ts',
    'src/adapters/blaxel.ts',
    'src/adapters/sprites.ts',
    'src/adapters/modal.ts',
    'src/adapters/runloop.ts',
    'src/adapters/exe.ts',
    'src/policies/index.ts',
    'src/testing/index.ts',
  ],
  format: ['esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  outDir: 'dist',
});
