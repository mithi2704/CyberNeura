import { build } from 'vite';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function bundleExtension() {
  console.log('[CyberNeura Build] Starting robust extension bundling (Standalone IIFE mode)...');

  const distDir = path.resolve(__dirname, 'dist');
  if (fs.existsSync(distDir)) {
    fs.rmSync(distDir, { recursive: true, force: true });
  }
  fs.mkdirSync(distDir, { recursive: true });

  // 1. Bundle individual TypeScript entries as standalone IIFE bundles
  const scripts = [
    {
      name: 'CyberNeuraServiceWorker',
      entry: path.resolve(__dirname, 'src/background/service-worker.ts'),
      outDir: distDir,
      fileName: 'service-worker.js',
    },
    {
      name: 'CyberNeuraContentScript',
      entry: path.resolve(__dirname, 'src/content/content-script.ts'),
      outDir: distDir,
      fileName: 'content-script.js',
    },
    {
      name: 'CyberNeuraPopup',
      entry: path.resolve(__dirname, 'src/popup/popup.ts'),
      outDir: path.resolve(distDir, 'src/popup'),
      fileName: 'popup.js',
    },
    {
      name: 'CyberNeuraOptions',
      entry: path.resolve(__dirname, 'src/options/options.ts'),
      outDir: path.resolve(distDir, 'src/options'),
      fileName: 'options.js',
    },
    {
      name: 'CyberNeuraInterstitial',
      entry: path.resolve(__dirname, 'src/interstitial/interstitial.ts'),
      outDir: path.resolve(distDir, 'src/interstitial'),
      fileName: 'interstitial.js',
    },
  ];

  for (const script of scripts) {
    console.log(`[CyberNeura Build] Compiling ${script.fileName}...`);
    await build({
      configFile: false,
      build: {
        lib: {
          entry: script.entry,
          name: script.name,
          formats: ['iife'],
          fileName: () => script.fileName,
        },
        outDir: script.outDir,
        emptyOutDir: false,
        rollupOptions: {
          output: {
            inlineDynamicImports: true,
          },
        },
      },
    });
  }

  // 2. Copy static HTML and CSS files to dist
  const htmlCssFiles = [
    { src: 'src/popup/popup.html', dest: 'src/popup/popup.html' },
    { src: 'src/popup/popup.css', dest: 'src/popup/popup.css' },
    { src: 'src/options/options.html', dest: 'src/options/options.html' },
    { src: 'src/options/options.css', dest: 'src/options/options.css' },
    { src: 'src/interstitial/interstitial.html', dest: 'src/interstitial/interstitial.html' },
    { src: 'src/interstitial/interstitial.css', dest: 'src/interstitial/interstitial.css' },
  ];

  for (const item of htmlCssFiles) {
    const srcPath = path.resolve(__dirname, item.src);
    const destPath = path.resolve(distDir, item.dest);
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    fs.copyFileSync(srcPath, destPath);
  }

  // Also copy interstitial.html to root of dist as web_accessible_resource fallback
  fs.copyFileSync(
    path.resolve(__dirname, 'src/interstitial/interstitial.html'),
    path.resolve(distDir, 'interstitial.html')
  );

  // 3. Copy icons
  const srcIcons = path.resolve(__dirname, 'icons');
  const distIcons = path.resolve(distDir, 'icons');
  if (fs.existsSync(srcIcons)) {
    fs.mkdirSync(distIcons, { recursive: true });
    for (const file of fs.readdirSync(srcIcons)) {
      fs.copyFileSync(path.resolve(srcIcons, file), path.resolve(distIcons, file));
    }
  }

  // 4. Copy manifest.json
  fs.copyFileSync(
    path.resolve(__dirname, 'manifest.json'),
    path.resolve(distDir, 'manifest.json')
  );

  // 5. Dual-mode support: Mirror built JS files to extension root and src/
  // so the extension works whether loaded from 'extension/' or 'extension/dist/'
  fs.copyFileSync(path.resolve(distDir, 'service-worker.js'), path.resolve(__dirname, 'service-worker.js'));
  fs.copyFileSync(path.resolve(distDir, 'content-script.js'), path.resolve(__dirname, 'content-script.js'));
  fs.copyFileSync(path.resolve(distDir, 'src/popup/popup.js'), path.resolve(__dirname, 'src/popup/popup.js'));
  fs.copyFileSync(path.resolve(distDir, 'src/options/options.js'), path.resolve(__dirname, 'src/options/options.js'));
  fs.copyFileSync(path.resolve(distDir, 'src/interstitial/interstitial.js'), path.resolve(__dirname, 'src/interstitial/interstitial.js'));

  console.log('✓ [CyberNeura Build] Extension build completed successfully with zero ES module chunk dependencies!');
}

bundleExtension().catch((err) => {
  console.error('[CyberNeura Build] Build failed:', err);
  process.exit(1);
});

