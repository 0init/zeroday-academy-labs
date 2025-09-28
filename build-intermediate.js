#!/usr/bin/env node

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

console.log('🎯 Building Intermediate Labs Version...\n');

try {
  // Create a temporary index.html for intermediate version
  const intermediateIndexHtml = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Zeroday Academy - Intermediate Labs</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="./client/src/main-intermediate.tsx"></script>
  </body>
</html>
`;

  // Write intermediate index.html
  fs.writeFileSync('index-intermediate.html', intermediateIndexHtml);

  // Build frontend with intermediate entry point
  console.log('📦 Building frontend (intermediate labs)...');
  execSync('npx vite build --config vite.intermediate.config.ts', { stdio: 'inherit' });

  // Create intermediate backend directory
  if (!fs.existsSync('dist/intermediate')) {
    fs.mkdirSync('dist/intermediate', { recursive: true });
  }

  // Build backend
  console.log('⚡ Building backend (intermediate routes)...');
  execSync('npx esbuild server/index-intermediate.ts --platform=node --packages=external --bundle --format=esm --outfile=dist/intermediate/index.js', { stdio: 'inherit' });

  // Clean up temporary file
  fs.unlinkSync('index-intermediate.html');

  console.log('\n✅ Intermediate Labs build completed!');
  console.log('📁 Output: dist/intermediate/index.js');
  console.log('🌐 Frontend: dist/intermediate/public/');
  console.log('\n🚀 To start: NODE_ENV=production PORT=5000 node dist/intermediate/index.js');

} catch (error) {
  console.error('❌ Build failed:', error);
  process.exit(1);
}