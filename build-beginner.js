#!/usr/bin/env node

import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

console.log('🚀 Building Beginner Labs Version...\n');

try {
  // Create a temporary index.html for beginner version
  const beginnerIndexHtml = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Zeroday Academy - Beginner Labs</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="./client/src/main-beginner.tsx"></script>
  </body>
</html>
`;

  // Write beginner index.html
  fs.writeFileSync('index-beginner.html', beginnerIndexHtml);

  // Build frontend with beginner entry point
  console.log('📦 Building frontend (beginner labs)...');
  execSync('npx vite build --config vite.beginner.config.ts', { stdio: 'inherit' });

  // Create beginner backend directory
  if (!fs.existsSync('dist/beginner')) {
    fs.mkdirSync('dist/beginner', { recursive: true });
  }

  // Build backend
  console.log('⚡ Building backend (beginner routes)...');
  execSync('npx esbuild server/index-beginner.ts --platform=node --packages=external --bundle --format=esm --outfile=dist/beginner/index.js', { stdio: 'inherit' });

  // Clean up temporary file
  fs.unlinkSync('index-beginner.html');

  console.log('\n✅ Beginner Labs build completed!');
  console.log('📁 Output: dist/beginner/index.js');
  console.log('🌐 Frontend: dist/beginner/public/');
  console.log('\n🚀 To start: NODE_ENV=production PORT=5000 node dist/beginner/index.js');

} catch (error) {
  console.error('❌ Build failed:', error);
  process.exit(1);
}