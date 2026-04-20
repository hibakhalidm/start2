import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';

export default defineConfig({
    plugins: [
        react(),
        wasm(),
        topLevelAwait()
    ],
    resolve: {
        alias: {
            '@': '/src',
        },
    },
    // Web Workers require code-splitting, which is incompatible with IIFE/UMD output.
    // Force an ES module build output so worker bundles are supported.
    build: {
        rollupOptions: {
            output: {
                format: 'es'
            }
        }
    },
    worker: {
        format: 'es'
    },
    server: {
        port: 5173,
        strictPort: true,
    }
});
