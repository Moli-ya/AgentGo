import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    fileParallelism: false,
    include: ['scripts/**/*.test.ts'],
    reporters: ['default']
  }
})
