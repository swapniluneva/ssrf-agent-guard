/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    roots: ['<rootDir>/test'],
    testMatch: ['**/*.test.ts'],
    moduleFileExtensions: ['ts', 'js', 'json'],
    transform: {
        '^.+\\.ts$': ['ts-jest', {
            tsconfig: {
                target: 'ES2020',
                module: 'commonjs',
                esModuleInterop: true,
                strict: true,
                moduleResolution: 'node',
                skipLibCheck: true,
            },
        }],
    },
    collectCoverageFrom: [
        'index.ts',
        'lib/**/*.ts',
        '!**/*.d.ts',
    ],
    coverageDirectory: 'coverage',
    coverageReporters: ['text', 'lcov', 'html'],
    clearMocks: true,
    resetMocks: true,
    restoreMocks: true,
};
