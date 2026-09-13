import { defineConfig } from 'vite';
import { resolve } from 'path';
import fs from 'fs';

// Helper plugin to copy manifest.json and icons to dist
function copyExtensionAssets() {
  return {
    name: 'copy-extension-assets',
    closeBundle() {
      const distDir = resolve(__dirname, 'dist');
      if (!fs.existsSync(distDir)) {
        fs.mkdirSync(distDir, { recursive: true });
      }
      // Copy manifest.json
      fs.copyFileSync(resolve(__dirname, 'manifest.json'), resolve(distDir, 'manifest.json'));

      // Copy icons
      const srcIcons = resolve(__dirname, 'icons');
      const distIcons = resolve(distDir, 'icons');
      if (!fs.existsSync(distIcons)) {
        fs.mkdirSync(distIcons, { recursive: true });
      }
      if (fs.existsSync(srcIcons)) {
        fs.readdirSync(srcIcons).forEach((file) => {
          fs.copyFileSync(resolve(srcIcons, file), resolve(distIcons, file));
        });
      }

      // Copy built service-worker.js & content-script.js to root for dual-mode extension loading
      const swDist = resolve(distDir, 'service-worker.js');
      const csDist = resolve(distDir, 'content-script.js');
      if (fs.existsSync(swDist)) {
        fs.copyFileSync(swDist, resolve(__dirname, 'service-worker.js'));
      }
      if (fs.existsSync(csDist)) {
        fs.copyFileSync(csDist, resolve(__dirname, 'content-script.js'));
      }
    },
  };
}

export default defineConfig({
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/popup.html'),
        options: resolve(__dirname, 'src/options/options.html'),
        interstitial: resolve(__dirname, 'src/interstitial/interstitial.html'),
        'service-worker': resolve(__dirname, 'src/background/service-worker.ts'),
        'content-script': resolve(__dirname, 'src/content/content-script.ts'),
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'service-worker') {
            return 'service-worker.js';
          }
          if (chunkInfo.name === 'content-script') {
            return 'content-script.js';
          }
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
      },
    },
  },
  plugins: [copyExtensionAssets()],
});
