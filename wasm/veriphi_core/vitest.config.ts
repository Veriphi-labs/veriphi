import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',         // no DOM needed
    setupFiles: ['./vitest.setup.ts'],
    include: ['tests/**/*.test.ts'],
    testTimeout: 30000,
  },
});