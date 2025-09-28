#!/bin/bash

echo "🚀 Starting Zeroday Academy - Beginner Labs..."

# Check if build exists
if [ ! -f "dist/beginner/index.js" ]; then
  echo "❌ Beginner build not found. Building now..."
  node build-beginner.js
fi

echo "🏃 Starting Beginner Labs server..."
NODE_ENV=production PORT=5000 node dist/beginner/index.js