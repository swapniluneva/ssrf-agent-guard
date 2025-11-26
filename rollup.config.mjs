import typescript from 'rollup-plugin-typescript2';

export default {
    input: 'index.ts',
    output: [
        { file: 'dist/index.esm.js', format: 'es' },
        { file: 'dist/index.cjs.js', format: 'cjs', exports: 'named' },
    ],
    plugins: [typescript({ useTsconfigDeclarationDir: true })],
};
