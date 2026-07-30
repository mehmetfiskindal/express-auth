module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  // bcrypt hashing (cost 12) + a live HTTP round-trip can exceed Jest's
  // default 5000ms on slower/older CI runners (observed on Node 18.x).
  testTimeout: 15000,
  roots: ['<rootDir>/src'],
  testMatch: ['**/*.spec.ts', '**/*.test.ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/index.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
};
